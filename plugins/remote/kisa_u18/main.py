"""Remote plugin for KISA U-18 shadow file permission checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import pwd
import shlex
import stat
from typing import Dict, List, Optional, Tuple

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_PATHS = {
    "linux": {"shadow": "/etc/shadow"},
    "solaris": {"shadow": "/etc/shadow"},
    "aix": {"security_passwd": "/etc/security/passwd"},
    "hpux": {"tcb_dir": "/tcb/files/auth", "shadow": "/etc/shadow"},
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


class ShadowFilePermissionCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        required_owner = str(self.context.config.get("required_owner") or "root").strip()
        max_mode = self._to_positive_int(self.context.config.get("max_mode", 400), "max_mode")

        if os_type in {"linux", "solaris"}:
            path = Path(self.context.config.get("shadow_path") or DEFAULT_PATHS[os_type]["shadow"])
            self._check_path(os_type, path, required_owner, max_mode)
        elif os_type == "aix":
            path = Path(
                self.context.config.get("aix_security_passwd_path")
                or DEFAULT_PATHS["aix"]["security_passwd"]
            )
            self._check_path(os_type, path, required_owner, max_mode)
        elif os_type == "hpux":
            tcb_dir = Path(
                self.context.config.get("hpux_tcb_dir")
                or DEFAULT_PATHS["hpux"]["tcb_dir"]
            )
            shadow_path = Path(
                self.context.config.get("hpux_shadow_path")
                or DEFAULT_PATHS["hpux"]["shadow"]
            )
            tcb_result = self._check_path_exists(tcb_dir)
            if tcb_result is True:
                self._check_path(os_type, tcb_dir, required_owner, max_mode, is_dir=True)
            elif tcb_result is False:
                self._check_path(os_type, shadow_path, required_owner, max_mode)
            else:
                self._add_unavailable(
                    os_type,
                    {"tcb_dir": tcb_dir, "shadow": shadow_path},
                    self._permission_error("Missing SSH credentials", tcb_dir),
                )
        return self.results

    def _check_path(
        self,
        os_type: str,
        path: Path,
        required_owner: str,
        max_mode: int,
        is_dir: bool = False,
    ) -> None:
        result = self._read_permission(path)
        if result.perm is None or result.owner is None:
            self._add_unavailable(os_type, path, result)
            return

        expected_mode = self._parse_mode_value(max_mode)
        issues = []
        if result.owner != required_owner:
            issues.append("owner_mismatch")
        if expected_mode is not None and result.perm > expected_mode:
            issues.append("permission_too_open")

        if issues:
            evidence = self._base_evidence(os_type, path, result)
            evidence["detected_value"] = {
                "owner": result.owner,
                "mode": self._format_octal(result.perm),
                "raw": result.raw,
                "method": result.method,
                "required_owner": required_owner,
                "max_mode": self._format_octal(expected_mode),
                "issues": issues,
                "type": "dir" if is_dir else "file",
            }
            self.add_finding(
                vuln_id="KISA-U-18",
                title=f"{self._format_os(os_type)} shadow 권한 설정 미흡",
                severity="High",
                evidence=evidence,
                tags=["KISA:U-18"],
                description="소유자 또는 권한 설정이 기준을 만족하지 않습니다.",
                solution="소유자를 root로 설정하고 권한을 400 이하로 제한하세요.",
            )

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

    def _check_path_exists(self, path: Path) -> Optional[bool]:
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
                command = f"test -d {shlex.quote(str(path))}"
                result = client.run(command)
            except AdapterError:
                return None
            if result.exit_code == 0:
                return True
            if result.exit_code == 1 and not result.stderr.strip():
                return False
            return None

        if allow_local:
            return path.is_dir()

        return None

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
            vuln_id="KISA-U-18",
            title=f"{self._format_os(os_type)} shadow 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-18"],
            description="shadow 권한 정보를 확인할 수 없습니다.",
            solution="대상 접근 권한과 파일 경로를 확인하세요.",
        )

    def _permission_error(self, message: str, path: Path) -> PermissionResult:
        return PermissionResult(None, None, "remote", message, None, path)

    def _base_evidence(self, os_type: str, path: Path, result: PermissionResult) -> Dict:
        evidence = {
            "os_type": os_type,
            "config_path": str(path),
            "mode": result.mode,
        }
        if result.host:
            evidence["host"] = result.host
        return evidence

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

    def _stringify_config_path(self, value):
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, list):
            return [self._stringify_config_path(item) for item in value]
        if isinstance(value, dict):
            return {key: self._stringify_config_path(val) for key, val in value.items()}
        return value

    def _format_os(self, os_type: str) -> str:
        display = {
            "linux": "Linux",
            "solaris": "Solaris",
            "aix": "AIX",
            "hpux": "HP-UX",
        }
        return display.get(os_type, os_type.upper())
