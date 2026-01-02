"""Remote plugin for KISA U-20 inetd/xinetd permission checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import pwd
import shlex
import stat
from typing import Dict, List, Optional, Sequence, Tuple

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_PATHS = {
    "linux": {
        "inetd": "/etc/inetd.conf",
        "xinetd": "/etc/xinetd.conf",
        "xinetd_dir": "/etc/xinetd.d",
    },
    "solaris": {"inetd": "/etc/inetd.conf"},
    "aix": {"inetd": "/etc/inetd.conf"},
    "hpux": {"inetd": "/etc/inetd.conf"},
}


@dataclass
class PermissionResult:
    perm: Optional[int]
    owner: Optional[str]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None
    raw: Optional[str] = None
    method: Optional[str] = None


def _parse_stat_output(raw: str) -> Optional[Tuple[int, str]]:
    parts = raw.strip().split()
    if len(parts) < 2:
        return None
    mode_raw, owner = parts[0], parts[1]
    try:
        mode_value = int(mode_raw, 8)
    except ValueError:
        return None
    return mode_value, owner


def _permstr_to_mode(perm: str) -> Optional[int]:
    if len(perm) < 10:
        return None
    perms = perm[1:10]
    mode = 0
    mapping = [
        (0, "r", 0o400),
        (1, "w", 0o200),
        (2, "x", 0o100),
        (3, "r", 0o040),
        (4, "w", 0o020),
        (5, "x", 0o010),
        (6, "r", 0o004),
        (7, "w", 0o002),
        (8, "x", 0o001),
    ]
    for idx, expected, bit in mapping:
        if perms[idx] == expected:
            mode |= bit

    user_exec = perms[2]
    group_exec = perms[5]
    other_exec = perms[8]
    if user_exec in ("s", "S"):
        mode |= stat.S_ISUID
        if user_exec == "s":
            mode |= 0o100
    if group_exec in ("s", "S"):
        mode |= stat.S_ISGID
        if group_exec == "s":
            mode |= 0o010
    if other_exec in ("t", "T"):
        mode |= stat.S_ISVTX
        if other_exec == "t":
            mode |= 0o001

    return mode


def _parse_ls_output(raw: str) -> Optional[Tuple[int, str]]:
    parts = raw.strip().split()
    if len(parts) < 3:
        return None
    permstr = parts[0]
    owner = parts[2]
    mode_value = _permstr_to_mode(permstr)
    if mode_value is None:
        return None
    return mode_value, owner


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


def _is_missing_file_error(error: Optional[str]) -> bool:
    if not error:
        return False
    lowered = error.lower()
    return "no such file" in lowered or "not found" in lowered or "cannot access" in lowered


class InetdConfigPermissionCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        required_owner = str(self.context.config.get("required_owner") or "root").strip()
        max_mode = self._to_positive_int(self.context.config.get("max_mode", 600), "max_mode")
        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        findings = []
        errors: List[PermissionResult] = []
        checked = []

        if os_type == "linux":
            inetd_path = Path(
                self.context.config.get("inetd_conf_path")
                or DEFAULT_PATHS["linux"]["inetd"]
            )
            xinetd_path = Path(
                self.context.config.get("xinetd_conf_path")
                or DEFAULT_PATHS["linux"]["xinetd"]
            )
            xinetd_dir = Path(
                self.context.config.get("xinetd_dir")
                or DEFAULT_PATHS["linux"]["xinetd_dir"]
            )

            for path, label in (
                (inetd_path, "inetd.conf"),
                (xinetd_path, "xinetd.conf"),
            ):
                result = self._read_permission(path)
                if result.perm is None or result.owner is None:
                    if not _is_missing_file_error(result.error):
                        errors.append(result)
                    continue
                checked.append(str(path))
                issues = self._evaluate_issues(result, required_owner, max_mode)
                if issues:
                    findings.append(self._build_entry(path, result, issues, label))

            dir_results = self._read_dir_permissions(xinetd_dir)
            if dir_results:
                for entry in dir_results:
                    checked.append(entry["path"])
                    issues = self._evaluate_issues(entry["result"], required_owner, max_mode)
                    if issues:
                        findings.append(self._build_entry(Path(entry["path"]), entry["result"], issues, "xinetd.d"))

        else:
            inetd_path = Path(
                self.context.config.get("inetd_conf_path")
                or DEFAULT_PATHS[os_type]["inetd"]
            )
            result = self._read_permission(inetd_path)
            if result.perm is None or result.owner is None:
                if not _is_missing_file_error(result.error):
                    errors.append(result)
            else:
                checked.append(str(inetd_path))
                issues = self._evaluate_issues(result, required_owner, max_mode)
                if issues:
                    findings.append(self._build_entry(inetd_path, result, issues, "inetd.conf"))

        if not findings:
            if not checked:
                error = errors[0] if errors else PermissionResult(
                    None,
                    None,
                    "remote",
                    "No target files found",
                )
                self._add_unavailable(
                    os_type,
                    {"checked_paths": checked or ["no_target_files"]},
                    error,
                )
            return self.results

        limited = findings[:max_results]
        evidence = {
            "os_type": os_type,
            "config_path": {"checked_paths": checked},
            "mode": self._merge_modes({str(idx): item["result"].mode for idx, item in enumerate(limited)}),
            "detected_value": [item["evidence"] for item in limited],
            "count": len(findings),
        }
        host = next((item["result"].host for item in limited if item["result"].host), None)
        if host:
            evidence["host"] = host
        if errors:
            evidence["partial_errors"] = [err.error for err in errors if err.error]

        self.add_finding(
            vuln_id="KISA-U-20",
            title=f"{self._format_os(os_type)} inetd 권한 설정 미흡",
            severity="High",
            evidence=evidence,
            tags=["KISA:U-20"],
            description="inetd/xinetd 설정 파일의 소유자 또는 권한 설정이 기준을 만족하지 않습니다.",
            solution="소유자를 root로 설정하고 권한을 600 이하로 제한하세요.",
        )
        return self.results

    def _read_dir_permissions(self, path: Path) -> List[Dict[str, object]]:
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
                command = f"ls -ld {shlex.quote(str(path))}/*"
                result = client.run(command)
            except AdapterError as exc:
                return []
            if result.exit_code != 0:
                if _is_missing_file_error(result.stderr):
                    return []
                return []
            entries = []
            for raw in result.stdout.splitlines():
                parsed = _parse_ls_line(raw)
                if not parsed:
                    continue
                perm_value = _permstr_to_mode(parsed["perm"])
                if perm_value is None:
                    continue
                entries.append(
                    {
                        "path": parsed["path"],
                        "result": PermissionResult(
                            perm_value,
                            parsed["owner"],
                            "remote",
                            None,
                            host,
                            Path(parsed["path"]),
                            parsed["raw"],
                            "ls",
                        ),
                    }
                )
            return entries

        if allow_local:
            if not path.exists() or not path.is_dir():
                return []
            entries = []
            try:
                names = os.listdir(path)
            except OSError:
                return []
            for name in names:
                file_path = path / name
                if not file_path.is_file():
                    continue
                st = os.stat(file_path)
                perm_value = stat.S_IMODE(st.st_mode)
                owner = self._uid_to_name(st.st_uid)
                entries.append(
                    {
                        "path": str(file_path),
                        "result": PermissionResult(
                            perm_value,
                            owner,
                            "local",
                            None,
                            None,
                            file_path,
                            None,
                            "stat",
                        ),
                    }
                )
            return entries

        return []

    def _read_permission(self, path: Path) -> PermissionResult:
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
                quoted = shlex.quote(str(path))
                commands = [
                    ("stat -c '%a %U' " + quoted, "stat"),
                    ("stat -f '%Lp %Su' " + quoted, "stat"),
                    ("ls -ld " + quoted, "ls"),
                ]
                for command, method in commands:
                    result = client.run(command)
                    if result.exit_code != 0:
                        continue
                    raw = result.stdout.strip()
                    parsed = _parse_stat_output(raw) if method == "stat" else _parse_ls_output(raw)
                    if parsed:
                        mode_value, owner = parsed
                        return PermissionResult(
                            mode_value,
                            owner,
                            "remote",
                            None,
                            host,
                            path,
                            raw,
                            method,
                        )
                error = (result.stderr or result.stdout or "").strip() or "Permission query failed"
                return PermissionResult(None, None, "remote", error, host, path)
            except AdapterError as exc:
                return PermissionResult(None, None, "remote", str(exc), host, path)

        if allow_local:
            if not path.exists():
                return PermissionResult(None, None, "local", "File not found", None, path)
            st = os.stat(path)
            mode_value = stat.S_IMODE(st.st_mode)
            owner = self._uid_to_name(st.st_uid)
            return PermissionResult(mode_value, owner, "local", None, None, path, None, "stat")

        return PermissionResult(None, None, "remote", "Missing SSH credentials", host, path)

    def _evaluate_issues(
        self,
        result: PermissionResult,
        required_owner: str,
        max_mode: int,
    ) -> List[str]:
        issues = []
        if result.owner != required_owner:
            issues.append("owner_mismatch")
        expected_mode = self._parse_mode_value(max_mode)
        if expected_mode is not None and result.perm is not None and result.perm > expected_mode:
            issues.append("permission_too_open")
        return issues

    def _build_entry(
        self,
        path: Path,
        result: PermissionResult,
        issues: List[str],
        source: str,
    ) -> Dict[str, object]:
        evidence = {
            "path": str(path),
            "owner": result.owner,
            "mode": self._format_octal(result.perm),
            "raw": result.raw,
            "method": result.method,
            "issues": issues,
            "source": source,
        }
        return {"evidence": evidence, "result": result}

    def _add_unavailable(self, os_type: str, path, result: PermissionResult) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path(path),
            "mode": result.mode,
        }
        if result.host:
            evidence["host"] = result.host
        if result.error:
            evidence["error"] = result.error
        self.add_finding(
            vuln_id="KISA-U-20",
            title=f"{self._format_os(os_type)} inetd 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-20"],
            description="inetd/xinetd 설정 파일 권한 정보를 확인할 수 없습니다.",
            solution="대상 접근 권한과 파일 경로를 확인하세요.",
        )

    def _merge_modes(self, modes: Dict[str, str]):
        if not modes:
            return None
        unique = set(modes.values())
        if len(unique) == 1:
            return next(iter(unique))
        return modes

    def _stringify_config_path(self, value):
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, list):
            return [self._stringify_config_path(item) for item in value]
        if isinstance(value, dict):
            return {key: self._stringify_config_path(val) for key, val in value.items()}
        return value

    def _uid_to_name(self, uid: int) -> str:
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            return str(uid)

    def _to_positive_int(self, value: object, name: str) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            raise PluginConfigError(f"{name} must be an integer")
        if parsed <= 0:
            raise PluginConfigError(f"{name} must be > 0")
        return parsed

    def _parse_mode_value(self, value: int) -> Optional[int]:
        if value < 0:
            return None
        if value > 0o777:
            value = int(str(value), 8)
        if value <= 0o777:
            return value
        return None

    def _format_octal(self, value: Optional[int]) -> Optional[str]:
        if value is None:
            return None
        return format(value, "04o")

    def _format_os(self, os_type: str) -> str:
        display = {
            "linux": "Linux",
            "solaris": "Solaris",
            "aix": "AIX",
            "hpux": "HP-UX",
        }
        return display.get(os_type, os_type.upper())
