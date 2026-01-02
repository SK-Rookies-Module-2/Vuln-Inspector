"""Remote plugin for KISA U-06 su access restriction checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import grp
import os
import shlex
import stat
from typing import Dict, List, Optional, Tuple

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_SU_PATH = "/usr/bin/su"
DEFAULT_PAM_SU_PATH = "/etc/pam.d/su"


@dataclass
class ReadResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None


@dataclass
class PermissionResult:
    perm: Optional[int]
    group: Optional[str]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None
    raw: Optional[str] = None
    method: Optional[str] = None


def _strip_inline_comment(raw_line: str) -> str:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return ""
    if "#" in line:
        line = line.split("#", 1)[0].rstrip()
    return line


def _find_pam_wheel_line(lines: List[str]) -> Optional[str]:
    for raw_line in lines:
        line = _strip_inline_comment(raw_line)
        if not line:
            continue
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0].lower() != "auth":
            continue
        module_token = next(
            (token for token in tokens if "pam_wheel.so" in token),
            None,
        )
        if not module_token:
            continue
        if any(token.lower() == "use_uid" for token in tokens):
            return raw_line.strip()
    return None


def _parse_stat_output(raw: str) -> Optional[Tuple[int, str]]:
    parts = raw.strip().split()
    if len(parts) < 2:
        return None
    mode_raw, group = parts[0], parts[1]
    try:
        mode_value = int(mode_raw, 8)
    except ValueError:
        return None
    return mode_value, group


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
    if len(parts) < 4:
        return None
    permstr = parts[0]
    group = parts[3]
    mode_value = _permstr_to_mode(permstr)
    if mode_value is None:
        return None
    return mode_value, group


class SuAccessRestrictionCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        su_path = Path(self.context.config.get("su_path") or DEFAULT_SU_PATH)
        pam_path = Path(self.context.config.get("pam_su_path") or DEFAULT_PAM_SU_PATH)
        privileged_group = str(self.context.config.get("privileged_group") or "wheel")

        if os_type == "linux":
            pam_result = self._read_config_lines(pam_path)
            if pam_result.lines is not None:
                pam_line = _find_pam_wheel_line(pam_result.lines)
                if pam_line:
                    return self.results

            permission_result = self._read_permission(su_path)
            if permission_result.perm is None or permission_result.group is None:
                self._add_unavailable(
                    os_type,
                    {"pam_su": pam_path, "su": su_path},
                    [pam_result, permission_result],
                )
                return self.results

            if not self._is_permission_ok(permission_result, privileged_group):
                evidence = self._base_evidence(
                    os_type,
                    su_path,
                    permission_result,
                )
                evidence["detected_value"] = self._permission_value(permission_result)
                evidence["source"] = "permission"
                evidence["required_group"] = privileged_group
                if pam_result.lines is not None:
                    evidence["pam_configured"] = False
                self._add_vulnerability(os_type, evidence)
            return self.results

        permission_result = self._read_permission(su_path)
        if permission_result.perm is None or permission_result.group is None:
            self._add_unavailable(os_type, su_path, [permission_result])
            return self.results

        if not self._is_permission_ok(permission_result, privileged_group):
            evidence = self._base_evidence(os_type, su_path, permission_result)
            evidence["detected_value"] = self._permission_value(permission_result)
            evidence["source"] = "permission"
            evidence["required_group"] = privileged_group
            self._add_vulnerability(os_type, evidence)

        return self.results

    def _is_permission_ok(self, result: PermissionResult, group: str) -> bool:
        return result.perm == 0o4750 and result.group == group

    def _permission_value(self, result: PermissionResult) -> Dict[str, Optional[str]]:
        return {
            "mode": self._format_octal(result.perm),
            "group": result.group,
            "raw": result.raw,
            "method": result.method,
        }

    def _add_unavailable(self, os_type: str, path, results) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path(path),
            "mode": self._merge_modes({str(idx): res.mode for idx, res in enumerate(results)}),
        }
        host = next((res.host for res in results if res.host), None)
        if host:
            evidence["host"] = host
        errors = [res.error for res in results if res.error]
        if errors:
            evidence["error"] = errors[0] if len(errors) == 1 else errors
        self.add_finding(
            vuln_id="KISA-U-06",
            title=f"{self._format_os(os_type)} su 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-06"],
            description="필수 설정 파일 또는 권한 정보를 읽지 못해 점검을 완료할 수 없습니다.",
            solution="대상 접근 권한과 설정 파일 경로를 확인하세요.",
        )

    def _add_vulnerability(self, os_type: str, evidence: Dict) -> None:
        self.add_finding(
            vuln_id="KISA-U-06",
            title=f"{self._format_os(os_type)} su 기능 제한 미흡",
            severity="High",
            evidence=evidence,
            tags=["KISA:U-06"],
            description="su 명령어가 특정 그룹으로 제한되어 있지 않습니다.",
            solution="su 권한을 4750으로 설정하고 privileged_group에만 실행 권한을 부여하세요.",
        )

    def _base_evidence(self, os_type: str, path: Path, result) -> Dict:
        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path(path),
            "mode": result.mode,
        }
        if result.host:
            evidence["host"] = result.host
        return evidence

    def _stringify_config_path(self, value):
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, list):
            return [self._stringify_config_path(item) for item in value]
        if isinstance(value, dict):
            return {key: self._stringify_config_path(val) for key, val in value.items()}
        return value

    def _merge_modes(self, modes: Dict[str, str]):
        if not modes:
            return None
        unique = set(modes.values())
        if len(unique) == 1:
            return next(iter(unique))
        return modes

    def _read_config_lines(self, config_path: Path) -> ReadResult:
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
                command = f"cat {shlex.quote(str(config_path))}"
                result = client.run(command)
            except AdapterError as exc:
                return ReadResult(None, "remote", str(exc), host, config_path)
            if result.exit_code != 0:
                error = result.stderr.strip() or f"SSH exit code {result.exit_code}"
                return ReadResult(None, "remote", error, host, config_path)
            return ReadResult(
                result.stdout.splitlines(),
                "remote",
                None,
                host,
                config_path,
            )

        if allow_local:
            if config_path.exists():
                return ReadResult(
                    config_path.read_text().splitlines(),
                    "local",
                    None,
                    None,
                    config_path,
                )
            return ReadResult(None, "local", "File not found", None, config_path)

        return ReadResult(None, "remote", "Missing SSH credentials", host, config_path)

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
                    ("stat -c '%a %G' " + quoted, "stat"),
                    ("stat -f '%Lp %Sg' " + quoted, "stat"),
                    ("ls -ld " + quoted, "ls"),
                ]
                for command, method in commands:
                    result = client.run(command)
                    if result.exit_code != 0:
                        continue
                    raw = result.stdout.strip()
                    parsed = _parse_stat_output(raw) if method == "stat" else _parse_ls_output(raw)
                    if parsed:
                        mode_value, group = parsed
                        return PermissionResult(
                            mode_value,
                            group,
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
            group = grp.getgrgid(st.st_gid).gr_name
            return PermissionResult(mode_value, group, "local", None, None, path, None, "stat")

        return PermissionResult(None, None, "remote", "Missing SSH credentials", host, path)

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
