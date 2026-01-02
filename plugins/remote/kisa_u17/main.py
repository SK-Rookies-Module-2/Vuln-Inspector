"""Remote plugin for KISA U-17 startup script permission checks."""

from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import os
import shlex
import stat
from typing import Dict, List, Optional, Sequence

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_SCRIPT_PATHS = ("/etc/rc.d", "/etc/rc*.d", "/etc/init.d")
DEFAULT_LIST_COMMAND = "ls -l {path}"


@dataclass
class CommandResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    command: Optional[str] = None


def _normalize_list(value, name: str) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        if not all(isinstance(item, str) for item in value):
            raise PluginConfigError(f"{name} must be an array of strings")
        return value
    raise PluginConfigError(f"{name} must be an array of strings")


def _parse_ls_line(raw: str) -> Optional[Dict[str, str]]:
    parts = raw.split()
    if len(parts) < 3:
        return None
    perm = parts[0]
    if not perm or perm[0] not in "-dlcbps":
        return None
    owner = parts[2]
    if "->" in parts:
        arrow_index = parts.index("->")
        if arrow_index > 0:
            path = parts[arrow_index - 1]
        else:
            path = parts[-1]
    else:
        path = parts[-1]
    return {"perm": perm, "owner": owner, "path": path, "raw": raw}


def _others_writable(perm: str) -> bool:
    if len(perm) < 10:
        return False
    return perm[8] == "w"


class StartupScriptPermissionCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        script_paths = _normalize_list(
            self.context.config.get("script_paths"),
            "script_paths",
        ) or list(DEFAULT_SCRIPT_PATHS)
        required_owner = str(self.context.config.get("required_owner") or "root").strip()
        check_others = bool(self.context.config.get("check_others_writable", True))
        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )
        list_command = str(self.context.config.get("list_command") or DEFAULT_LIST_COMMAND).strip()
        if not list_command:
            raise PluginConfigError("list_command must be a non-empty string")

        results = []
        errors = []
        for path in script_paths:
            command = list_command.replace("{path}", shlex.quote(path))
            result = self._run_command(command)
            results.append((path, command, result))
            if result.lines is None:
                errors.append(result)

        lines = []
        for _, _, result in results:
            if result.lines:
                lines.extend([line for line in result.lines if line.strip()])

        if not lines:
            if errors:
                self._add_unavailable(
                    os_type,
                    {"commands": [cmd for _, cmd, _ in results]},
                    errors[0],
                )
            return self.results

        findings = []
        for raw in lines:
            parsed = _parse_ls_line(raw)
            if not parsed:
                continue
            if required_owner and parsed["owner"] != required_owner:
                findings.append(
                    {
                        "path": parsed["path"],
                        "owner": parsed["owner"],
                        "perm": parsed["perm"],
                        "issue": "owner_mismatch",
                        "line": parsed["raw"],
                    }
                )
                continue
            if check_others and _others_writable(parsed["perm"]):
                findings.append(
                    {
                        "path": parsed["path"],
                        "owner": parsed["owner"],
                        "perm": parsed["perm"],
                        "issue": "others_writable",
                        "line": parsed["raw"],
                    }
                )

        if not findings:
            return self.results

        limited = findings[:max_results]
        evidence = {
            "os_type": os_type,
            "config_path": {"commands": [cmd for _, cmd, _ in results]},
            "mode": self._merge_modes(
                {str(idx): res.mode for idx, (_, _, res) in enumerate(results)}
            ),
            "detected_value": limited,
            "count": len(findings),
        }
        host = next((res.host for _, _, res in results if res.host), None)
        if host:
            evidence["host"] = host
        if errors:
            evidence["partial_errors"] = [res.error for res in errors if res.error]

        self.add_finding(
            vuln_id="KISA-U-17",
            title=f"{self._format_os(os_type)} 시작 스크립트 권한 미흡",
            severity="High",
            evidence=evidence,
            tags=["KISA:U-17"],
            description="시작 스크립트 소유자 또는 권한 설정이 안전하지 않습니다.",
            solution="소유자를 root로 변경하고 others 쓰기 권한을 제거하세요.",
        )
        return self.results

    def _run_command(self, command: str) -> CommandResult:
        connection = self.context.target.get("connection_info", {}) or {}
        credentials = self.context.target.get("credentials", {}) or {}
        host = connection.get("host") or connection.get("ip")
        user = credentials.get("username")
        key_path = credentials.get("key_path")
        password = credentials.get("password")
        proxy_jump = connection.get("proxy_jump")
        proxy_command = connection.get("proxy_command")
        identities_only = bool(connection.get("identities_only", False))
        allow_local = bool(self.context.config.get("allow_local_fallback", False))

        port_raw = connection.get("port", 22)
        try:
            port = int(port_raw)
        except (TypeError, ValueError):
            raise PluginConfigError("Invalid SSH port in connection_info")

        if host and user and (key_path or password):
            try:
                client = SshClient(
                    host=host,
                    user=user,
                    key_path=key_path,
                    password=password,
                    port=port,
                    proxy_jump=proxy_jump,
                    proxy_command=proxy_command,
                    identities_only=identities_only,
                    sudo=bool(self.context.config.get("use_sudo", False)),
                    sudo_user=self.context.config.get("sudo_user"),
                )
                result = client.run(command)
            except AdapterError as exc:
                return CommandResult(None, "remote", str(exc), host, command)
            if result.exit_code != 0:
                error = result.stderr.strip() or f"SSH exit code {result.exit_code}"
                return CommandResult(None, "remote", error, host, command)
            return CommandResult(result.stdout.splitlines(), "remote", None, host, command)

        if allow_local:
            lines = []
            for raw_path in self._expand_paths(command):
                if not os.path.exists(raw_path):
                    continue
                stat_info = os.stat(raw_path)
                perm = stat.filemode(stat_info.st_mode)
                owner = self._uid_to_name(stat_info.st_uid)
                lines.append(f"{perm} 1 {owner} {raw_path}")
            return CommandResult(lines, "local", None, None, command)

        return CommandResult(None, "remote", "Missing SSH credentials", host, command)

    def _expand_paths(self, command: str) -> List[str]:
        parts = command.split()
        if len(parts) < 2:
            return []
        raw_path = parts[-1].strip("'\"")
        targets = self._glob_paths(raw_path)
        paths: List[str] = []
        for target in targets:
            if os.path.isdir(target):
                try:
                    entries = os.listdir(target)
                except OSError:
                    continue
                for entry in entries:
                    paths.append(os.path.join(target, entry))
            else:
                paths.append(target)
        return paths

    def _glob_paths(self, pattern: str) -> List[str]:
        if "*" not in pattern and "?" not in pattern:
            return [pattern]
        base = os.path.dirname(pattern) or "/"
        try:
            entries = os.listdir(base)
        except OSError:
            return []
        return [os.path.join(base, entry) for entry in entries if fnmatch.fnmatch(entry, os.path.basename(pattern))]

    def _uid_to_name(self, uid: int) -> str:
        try:
            import pwd

            return pwd.getpwuid(uid).pw_name
        except Exception:
            return str(uid)

    def _add_unavailable(self, os_type: str, command, result: CommandResult) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": command if isinstance(command, dict) else {"command": command},
            "mode": result.mode,
        }
        if result.host:
            evidence["host"] = result.host
        if result.error:
            evidence["error"] = result.error
        self.add_finding(
            vuln_id="KISA-U-17",
            title=f"{self._format_os(os_type)} 시작 스크립트 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-17"],
            description="시작 스크립트 권한 정보를 확인할 수 없습니다.",
            solution="대상 접근 권한과 파일 경로를 확인하세요.",
        )

    def _to_positive_int(self, value: object, name: str) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            raise PluginConfigError(f"{name} must be an integer")
        if parsed <= 0:
            raise PluginConfigError(f"{name} must be > 0")
        return parsed

    def _merge_modes(self, modes: Dict[str, str]):
        if not modes:
            return None
        unique = set(modes.values())
        if len(unique) == 1:
            return next(iter(unique))
        return modes

    def _format_os(self, os_type: str) -> str:
        display = {
            "linux": "Linux",
            "solaris": "Solaris",
            "aix": "AIX",
            "hpux": "HP-UX",
        }
        return display.get(os_type, os_type.upper())
