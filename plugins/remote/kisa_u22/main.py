"""Remote plugin for KISA U-22 services file permission checks."""

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
DEFAULT_SERVICES_PATH = "/etc/services"


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


class ServicesFilePermissionCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        services_path = Path(self.context.config.get("services_path") or DEFAULT_SERVICES_PATH)
        allowed_owners = self._normalize_list(self.context.config.get("allowed_owners"), "allowed_owners")
        max_mode = self._to_positive_int(self.context.config.get("max_mode", 644), "max_mode")
        allow_group_write = bool(self.context.config.get("allow_group_write", False))
        allow_other_write = bool(self.context.config.get("allow_other_write", False))

        result = self._read_permission(services_path)
        if result.perm is None or result.owner is None:
            self._add_unavailable(os_type, services_path, result)
            return self.results

        issues = self._evaluate_issues(
            result,
            allowed_owners,
            max_mode,
            allow_group_write,
            allow_other_write,
        )
        if issues:
            evidence = self._base_evidence(os_type, services_path, result)
            evidence["detected_value"] = {
                "owner": result.owner,
                "mode": self._format_octal(result.perm),
                "raw": result.raw,
                "method": result.method,
                "allowed_owners": allowed_owners,
                "max_mode": self._format_octal(self._parse_mode_value(max_mode)),
                "allow_group_write": allow_group_write,
                "allow_other_write": allow_other_write,
                "issues": issues,
            }
            self.add_finding(
                vuln_id="KISA-U-22",
                title=f"{self._format_os(os_type)} /etc/services 권한 설정 미흡",
                severity="High",
                evidence=evidence,
                tags=["KISA:U-22"],
                description="소유자 또는 권한 설정이 기준을 만족하지 않습니다.",
                solution="소유자를 root/bin/sys로 설정하고 권한을 644 이하로 제한하세요.",
            )

        return self.results

    def _evaluate_issues(
        self,
        result: PermissionResult,
        allowed_owners: List[str],
        max_mode: int,
        allow_group_write: bool,
        allow_other_write: bool,
    ) -> List[str]:
        issues = []
        if allowed_owners and result.owner not in allowed_owners:
            issues.append("owner_mismatch")
        expected_mode = self._parse_mode_value(max_mode)
        if expected_mode is not None and result.perm is not None and result.perm > expected_mode:
            issues.append("permission_too_open")
        if not allow_group_write and result.perm is not None and (result.perm & 0o020):
            issues.append("group_writable")
        if not allow_other_write and result.perm is not None and (result.perm & 0o002):
            issues.append("other_writable")
        return issues

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

    def _add_unavailable(self, os_type: str, path: Path, result: PermissionResult) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": str(path),
            "mode": result.mode,
        }
        if result.host:
            evidence["host"] = result.host
        if result.error:
            evidence["error"] = result.error
        self.add_finding(
            vuln_id="KISA-U-22",
            title=f"{self._format_os(os_type)} /etc/services 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-22"],
            description="/etc/services 권한 정보를 확인할 수 없습니다.",
            solution="대상 접근 권한과 파일 경로를 확인하세요.",
        )

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

    def _normalize_list(self, value, name: str) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            if not all(isinstance(item, str) for item in value):
                raise PluginConfigError(f"{name} must be an array of strings")
            return value
        raise PluginConfigError(f"{name} must be an array of strings")

    def _format_os(self, os_type: str) -> str:
        display = {
            "linux": "Linux",
            "solaris": "Solaris",
            "aix": "AIX",
            "hpux": "HP-UX",
        }
        return display.get(os_type, os_type.upper())
