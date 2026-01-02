"""Remote plugin for KISA U-33 hidden file discovery."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shlex
import subprocess
from typing import Dict, List, Optional, Sequence

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_FIND_COMMAND = "find {path} -xdev {prune} -type f -name '.*' -ls"
DEFAULT_SEARCH_PATHS = (
    "/",
    "/home",
    "/root",
    "/tmp",
    "/var",
    "/var/tmp",
    "/dev",
)
DEFAULT_EXCLUDE_PATHS = ("/proc", "/sys", "/run")
DEFAULT_ALLOWED_BASENAMES = (
    ".profile",
    ".bashrc",
    ".bash_profile",
    ".bash_logout",
    ".cshrc",
    ".kshrc",
    ".login",
    ".logout",
    ".zshrc",
    ".zprofile",
    ".zlogin",
    ".zlogout",
    ".vimrc",
    ".viminfo",
    ".nanorc",
    ".tmux.conf",
    ".screenrc",
    ".inputrc",
    ".gitconfig",
    ".pwd.lock",
)
DEFAULT_SUSPICIOUS_PATHS = ("/tmp", "/var/tmp", "/dev")


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


def _parse_find_path(line: str) -> Optional[str]:
    parts = line.split()
    if len(parts) < 11:
        return None
    return parts[-1]


class HiddenFileCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        find_command = str(self.context.config.get("find_command") or DEFAULT_FIND_COMMAND).strip()
        if not find_command:
            raise PluginConfigError("find_command must be a non-empty string")

        search_paths = _normalize_list(
            self.context.config.get("search_paths"),
            "search_paths",
        ) or list(DEFAULT_SEARCH_PATHS)
        search_paths = [path.strip() for path in search_paths if path.strip()]
        if not search_paths:
            raise PluginConfigError("search_paths must include at least one path")

        exclude_paths = _normalize_list(
            self.context.config.get("exclude_paths"),
            "exclude_paths",
        ) or list(DEFAULT_EXCLUDE_PATHS)
        allowed_basenames = set(
            name.strip()
            for name in _normalize_list(self.context.config.get("allowed_basenames"), "allowed_basenames")
            if name.strip()
        )
        if not allowed_basenames:
            allowed_basenames = set(DEFAULT_ALLOWED_BASENAMES)

        whitelist_paths = set(
            path.strip()
            for path in _normalize_list(self.context.config.get("whitelist_paths"), "whitelist_paths")
            if path.strip()
        )
        suspicious_paths = _normalize_list(
            self.context.config.get("suspicious_paths"),
            "suspicious_paths",
        ) or list(DEFAULT_SUSPICIOUS_PATHS)
        suspicious_paths = [path.strip() for path in suspicious_paths if path.strip()]

        max_results = self._to_positive_int(self.context.config.get("max_results", 200), "max_results")

        command_results = []
        errors = []
        for path in search_paths:
            command = self._build_command(find_command, path, exclude_paths)
            result = self._run_command(command)
            command_results.append((command, result))
            if result.lines is None:
                errors.append(result)

        lines: List[str] = []
        for _, result in command_results:
            if result.lines:
                lines.extend([line for line in result.lines if line.strip()])

        if not lines:
            if errors:
                self._add_unavailable(
                    os_type,
                    {"commands": [cmd for cmd, _ in command_results]},
                    errors[0],
                )
            return self.results

        findings = []
        seen_paths = set()
        for raw in lines:
            path = _parse_find_path(raw)
            if not path:
                continue
            if path in seen_paths:
                continue
            seen_paths.add(path)
            if path in whitelist_paths:
                continue
            if Path(path).name in allowed_basenames:
                continue
            findings.append(
                {
                    "path": path,
                    "line": raw,
                    "suspicious": self._is_suspicious_path(path, suspicious_paths),
                }
            )

        if not findings:
            return self.results

        suspicious_items = [item for item in findings if item.get("suspicious")]
        ordered = suspicious_items + [item for item in findings if not item.get("suspicious")]
        limited = ordered[:max_results]

        evidence = {
            "os_type": os_type,
            "config_path": {"commands": [cmd for cmd, _ in command_results]},
            "mode": self._merge_modes(
                {str(idx): res.mode for idx, (_, res) in enumerate(command_results)}
            ),
            "detected_value": limited,
            "count": len(findings),
            "suspicious_count": len(suspicious_items),
        }
        host = next((res.host for _, res in command_results if res.host), None)
        if host:
            evidence["host"] = host
        if errors:
            evidence["partial_errors"] = [res.error for res in errors if res.error]

        self.add_finding(
            vuln_id="KISA-U-33",
            title=f"{self._format_os(os_type)} 숨겨진 파일 발견",
            severity="Low",
            evidence=evidence,
            tags=["KISA:U-33"],
            description="의심스러운 숨김 파일이 발견되었습니다.",
            solution="불필요한 숨김 파일을 제거하거나 정당성을 확인하세요.",
        )
        return self.results

    def _build_command(self, template: str, path: str, exclude_paths: Sequence[str]) -> str:
        prune_expr = self._build_prune_expr(exclude_paths)
        command = template
        if "{path}" in command:
            command = command.replace("{path}", shlex.quote(path))
        if "{prune}" in command:
            command = command.replace("{prune}", prune_expr)
        elif prune_expr:
            command = self._inject_prune(command, prune_expr)
        return command

    def _inject_prune(self, command: str, prune_expr: str) -> str:
        try:
            tokens = shlex.split(command)
        except ValueError:
            return f"{command} {prune_expr}"
        if "-xdev" in tokens:
            idx = tokens.index("-xdev")
            tokens.insert(idx + 1, prune_expr)
            return " ".join(tokens)
        if tokens and tokens[0] == "find" and len(tokens) >= 2:
            tokens.insert(2, prune_expr)
            return " ".join(tokens)
        return f"{command} {prune_expr}"

    def _build_prune_expr(self, paths: Sequence[str]) -> str:
        items = []
        for path in paths:
            path = str(path).strip()
            if not path:
                continue
            items.append(f"-path {shlex.quote(path)}")
        if not items:
            return ""
        joined = " -o ".join(items)
        return f"\\( {joined} \\) -prune -o"

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
            try:
                parsed = shlex.split(command)
                result = subprocess.run(
                    parsed,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                return CommandResult(None, "local", str(exc), None, command)
            if result.returncode != 0:
                error = result.stderr.strip() or f"Command exit code {result.returncode}"
                return CommandResult(None, "local", error, None, command)
            return CommandResult(result.stdout.splitlines(), "local", None, None, command)

        return CommandResult(None, "remote", "Missing SSH credentials", host, command)

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
            vuln_id="KISA-U-33",
            title=f"{self._format_os(os_type)} 숨겨진 파일 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-33"],
            description="find 명령 실행에 실패하여 점검을 완료할 수 없습니다.",
            solution="대상 접근 권한과 명령 실행 권한을 확인하세요.",
        )

    def _is_suspicious_path(self, path: str, suspicious_paths: Sequence[str]) -> bool:
        for base in suspicious_paths:
            base = str(base).strip()
            if not base:
                continue
            base = base.rstrip("/")
            if path == base:
                return True
            if path.startswith(f"{base}/"):
                return True
        return False

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
