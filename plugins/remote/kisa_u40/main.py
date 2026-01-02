"""Remote plugin for KISA U-40 NFS access control checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import pwd
import re
import shlex
import stat
from typing import Dict, List, Optional, Tuple

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding
from plugins.remote.utils.text import strip_comments

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_EXPORTS_PATH = "/etc/exports"


@dataclass
class ReadResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None
    missing: bool = False


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
    missing: bool = False


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


def _is_missing_error(error: Optional[str]) -> bool:
    if not error:
        return False
    lowered = error.lower()
    return (
        "no such file" in lowered
        or "not found" in lowered
        or "cannot stat" in lowered
        or "cannot access" in lowered
    )


class NfsAccessControlCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        exports_path = Path(self.context.config.get("exports_path") or DEFAULT_EXPORTS_PATH)
        required_owner = str(self.context.config.get("required_owner") or "root").strip()
        max_mode = self._to_positive_int(self.context.config.get("max_mode", 644), "max_mode")
        allow_group_write = bool(self.context.config.get("allow_group_write", False))
        allow_other_write = bool(self.context.config.get("allow_other_write", False))
        max_results = self._to_positive_int(self.context.config.get("max_results", 200), "max_results")

        read_result = self._read_lines(exports_path)
        perm_result = self._read_permission(exports_path)

        if read_result.missing or perm_result.missing:
            return self.results

        permission_issues = []
        permission_error = None
        if perm_result.perm is None or perm_result.owner is None:
            permission_error = perm_result.error or "Permission check failed"
        else:
            expected_mode = self._parse_mode_value(max_mode)
            if perm_result.owner != required_owner:
                permission_issues.append("owner_mismatch")
            if expected_mode is not None and perm_result.perm > expected_mode:
                permission_issues.append("permission_too_open")
            if not allow_group_write and (perm_result.perm & 0o020):
                permission_issues.append("group_writable")
            if not allow_other_write and (perm_result.perm & 0o002):
                permission_issues.append("other_writable")

        content_issues = []
        content_error = None
        if read_result.lines is None:
            content_error = read_result.error or "Failed to read exports"
        else:
            content_issues = self._parse_exports_issues(read_result.lines)

        issues_total = len(content_issues) + len(permission_issues)
        if issues_total:
            limited = content_issues[:max_results]
            detected = {
                "entries": limited,
                "permission": self._build_permission_evidence(
                    perm_result,
                    required_owner,
                    max_mode,
                    allow_group_write,
                    allow_other_write,
                    permission_issues,
                    permission_error,
                ),
            }
            evidence = {
                "os_type": os_type,
                "config_path": str(exports_path),
                "mode": self._merge_modes(
                    {
                        "content": read_result.mode,
                        "permission": perm_result.mode,
                    }
                ),
                "detected_value": detected,
                "count": issues_total,
            }
            host = perm_result.host or read_result.host
            if host:
                evidence["host"] = host
            errors = [err for err in (content_error, permission_error) if err]
            if errors:
                evidence["partial_errors"] = errors

            self.add_finding(
                vuln_id="KISA-U-40",
                title=f"{self._format_os(os_type)} NFS 접근 통제 미흡",
                severity="High",
                evidence=evidence,
                tags=["KISA:U-40"],
                description="NFS exports에 전체 허용 또는 insecure 옵션이 존재하거나 권한이 취약합니다.",
                solution="허용된 호스트만 지정하고 /etc/exports 권한을 644 이하로 설정하세요.",
            )
            return self.results

        if content_error or permission_error:
            self._add_unavailable(
                os_type,
                str(exports_path),
                read_result,
                perm_result,
                [err for err in (content_error, permission_error) if err],
            )

        return self.results

    def _parse_exports_issues(self, lines: List[str]) -> List[Dict[str, str]]:
        issues: List[Dict[str, str]] = []
        seen = set()
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue
            tokens = line.split()
            if len(tokens) < 2:
                continue
            export_path = tokens[0]
            host_tokens = tokens[1:]

            for host_token in host_tokens:
                host_part = host_token.split("(", 1)[0].strip()
                if "*" in host_part:
                    key = ("wildcard_host", export_path, host_part, line)
                    if key in seen:
                        continue
                    seen.add(key)
                    issues.append(
                        {
                            "issue": "wildcard_host",
                            "path": export_path,
                            "host": host_part,
                            "line": line,
                        }
                    )

            if re.search(r"\binsecure\b", line, re.IGNORECASE):
                key = ("insecure_option", export_path, line)
                if key in seen:
                    continue
                seen.add(key)
                issues.append(
                    {
                        "issue": "insecure_option",
                        "path": export_path,
                        "line": line,
                    }
                )
        return issues

    def _build_permission_evidence(
        self,
        result: PermissionResult,
        required_owner: str,
        max_mode: int,
        allow_group_write: bool,
        allow_other_write: bool,
        issues: List[str],
        error: Optional[str],
    ) -> Dict[str, object]:
        evidence: Dict[str, object] = {
            "required_owner": required_owner,
            "max_mode": self._format_octal(self._parse_mode_value(max_mode)),
            "allow_group_write": allow_group_write,
            "allow_other_write": allow_other_write,
        }
        if result.perm is not None and result.owner is not None:
            evidence.update(
                {
                    "owner": result.owner,
                    "mode": self._format_octal(result.perm),
                    "raw": result.raw,
                    "method": result.method,
                    "issues": issues,
                }
            )
        if error:
            evidence["error"] = error
        return evidence

    def _read_lines(self, path: Path) -> ReadResult:
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
                result = client.run(f"cat {quoted}")
            except AdapterError as exc:
                return ReadResult(None, "remote", str(exc), host, path, False)
            if result.exit_code != 0:
                err = (result.stderr or result.stdout or "").strip()
                if _is_missing_error(err):
                    return ReadResult(None, "remote", err or "File not found", host, path, True)
                return ReadResult(None, "remote", err or f"SSH exit code {result.exit_code}", host, path)
            raw_lines = result.stdout.splitlines()
            return ReadResult(strip_comments(raw_lines), "remote", None, host, path)

        if allow_local:
            if not path.exists():
                return ReadResult(None, "local", "File not found", None, path, True)
            try:
                raw_lines = path.read_text().splitlines()
            except OSError as exc:
                return ReadResult(None, "local", str(exc), None, path)
            return ReadResult(strip_comments(raw_lines), "local", None, None, path)

        return ReadResult(None, "remote", "Missing SSH credentials", host, path)

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
                last_error = None
                for command, method in commands:
                    result = client.run(command)
                    if result.exit_code != 0:
                        error = (result.stderr or result.stdout or "").strip()
                        if _is_missing_error(error):
                            return PermissionResult(
                                None,
                                None,
                                "remote",
                                error or "File not found",
                                host,
                                path,
                                None,
                                method,
                                True,
                            )
                        last_error = error or f"SSH exit code {result.exit_code}"
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
                    last_error = "Permission output parse failed"
                return PermissionResult(None, None, "remote", last_error, host, path)
            except AdapterError as exc:
                return PermissionResult(None, None, "remote", str(exc), host, path)

        if allow_local:
            if not path.exists():
                return PermissionResult(None, None, "local", "File not found", None, path, None, None, True)
            st = os.stat(path)
            mode_value = stat.S_IMODE(st.st_mode)
            owner = self._uid_to_name(st.st_uid)
            return PermissionResult(mode_value, owner, "local", None, None, path, None, "stat")

        return PermissionResult(None, None, "remote", "Missing SSH credentials", host, path)

    def _add_unavailable(
        self,
        os_type: str,
        config_path: str,
        read_result: ReadResult,
        perm_result: PermissionResult,
        errors: List[str],
    ) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": config_path,
            "mode": self._merge_modes(
                {
                    "content": read_result.mode,
                    "permission": perm_result.mode,
                }
            ),
        }
        host = perm_result.host or read_result.host
        if host:
            evidence["host"] = host
        if errors:
            evidence["error"] = errors[0]
            evidence["errors"] = errors

        self.add_finding(
            vuln_id="KISA-U-40",
            title=f"{self._format_os(os_type)} NFS 접근 통제 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-40"],
            description="/etc/exports 점검을 완료할 수 없습니다.",
            solution="대상 접근 권한과 파일 경로/명령 실행 권한을 확인하세요.",
        )

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
