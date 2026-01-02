"""Remote plugin for KISA U-31 home directory permission checks."""

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
DEFAULT_PASSWD_PATH = "/etc/passwd"


@dataclass
class ReadResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None


@dataclass
class PasswdEntry:
    name: str
    home: Path
    line: str


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


def _parse_passwd(lines: Sequence[str], ignore_users: Sequence[str]) -> List[PasswdEntry]:
    ignore_set = {name.strip() for name in ignore_users if name and name.strip()}
    entries = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name = parts[0].strip()
        home = parts[5].strip()
        if not name or name in ignore_set:
            continue
        if not home:
            continue
        home_path = Path(home)
        if not home_path.is_absolute():
            continue
        entries.append(PasswdEntry(name=name, home=home_path, line=raw_line.strip()))
    return entries


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


class HomeDirectoryPermissionCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        passwd_path = Path(self.context.config.get("passwd_path") or DEFAULT_PASSWD_PATH)
        ignore_users = _normalize_list(
            self.context.config.get("ignore_users"),
            "ignore_users",
        )
        allow_group_write = bool(self.context.config.get("allow_group_write", False))
        allow_other_write = bool(self.context.config.get("allow_other_write", False))
        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        client, host = self._get_ssh_client()
        passwd_result = self._read_config_lines(passwd_path, client, host)
        if passwd_result.lines is None:
            self._add_unavailable(os_type, passwd_path, passwd_result)
            return self.results

        entries = _parse_passwd(passwd_result.lines, ignore_users)
        if not entries:
            return self.results

        issues = []
        errors = []
        checked_count = 0
        missing_count = 0

        for entry in entries:
            result = self._read_permission(entry.home, client, host)
            if result.missing:
                missing_count += 1
                continue
            if result.perm is None or result.owner is None:
                if result.error:
                    errors.append({"user": entry.name, "path": str(entry.home), "error": result.error})
                continue

            checked_count += 1
            issue_flags = []
            if result.owner != entry.name:
                issue_flags.append("owner_mismatch")
            if not allow_group_write and (result.perm & 0o020):
                issue_flags.append("group_writable")
            if not allow_other_write and (result.perm & 0o002):
                issue_flags.append("other_writable")
            if issue_flags:
                issues.append(
                    {
                        "user": entry.name,
                        "path": str(entry.home),
                        "owner": result.owner,
                        "mode": self._format_octal(result.perm),
                        "raw": result.raw,
                        "method": result.method,
                        "issues": issue_flags,
                    }
                )

        if not issues:
            if checked_count == 0 and errors:
                self._add_unavailable(os_type, passwd_path, passwd_result, errors)
            return self.results

        limited = issues[:max_results]
        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path({"passwd": passwd_path}),
            "mode": passwd_result.mode,
            "detected_value": limited,
            "count": len(issues),
            "checked_dirs": checked_count,
            "missing_dirs": missing_count,
            "policy": {
                "allow_group_write": allow_group_write,
                "allow_other_write": allow_other_write,
            },
        }
        if host:
            evidence["host"] = host
        if errors:
            evidence["partial_errors"] = errors[:max_results]

        self.add_finding(
            vuln_id="KISA-U-31",
            title=f"{self._format_os(os_type)} 홈 디렉터리 권한 설정 미흡",
            severity="Medium",
            evidence=evidence,
            tags=["KISA:U-31"],
            description="홈 디렉터리 소유자 또는 권한 설정이 기준을 만족하지 않습니다.",
            solution="홈 디렉터리를 해당 계정이 소유하도록 하고 타 사용자 쓰기 권한을 제거하세요.",
        )
        return self.results

    def _get_ssh_client(self) -> Tuple[Optional[SshClient], Optional[str]]:
        connection = self.context.target.get("connection_info", {}) or {}
        credentials = self.context.target.get("credentials", {}) or {}
        host = connection.get("host") or connection.get("ip")
        user = credentials.get("username")
        key_path = credentials.get("key_path")
        password = credentials.get("password")
        proxy_jump = connection.get("proxy_jump")
        proxy_command = connection.get("proxy_command")
        identities_only = bool(connection.get("identities_only", False))

        port_raw = connection.get("port", 22)
        try:
            port = int(port_raw)
        except (TypeError, ValueError):
            raise PluginConfigError("Invalid SSH port in connection_info")

        if host and user and (key_path or password):
            return (
                SshClient(
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
                ),
                host,
            )
        return None, host

    def _read_config_lines(
        self,
        config_path: Path,
        client: Optional[SshClient],
        host: Optional[str],
    ) -> ReadResult:
        allow_local = bool(self.context.config.get("allow_local_fallback", False))
        if client:
            try:
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

    def _read_permission(
        self,
        path: Path,
        client: Optional[SshClient],
        host: Optional[str],
    ) -> PermissionResult:
        allow_local = bool(self.context.config.get("allow_local_fallback", False))
        if client:
            try:
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
        passwd_path: Path,
        result: ReadResult,
        errors: Optional[List[Dict[str, str]]] = None,
    ) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path({"passwd": passwd_path}),
            "mode": result.mode,
        }
        if result.host:
            evidence["host"] = result.host
        if result.error:
            evidence["error"] = result.error
        if errors:
            evidence["partial_errors"] = errors
        self.add_finding(
            vuln_id="KISA-U-31",
            title=f"{self._format_os(os_type)} 홈 디렉터리 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-31"],
            description="홈 디렉터리 권한 정보를 확인할 수 없습니다.",
            solution="대상 접근 권한과 홈 디렉터리 경로를 확인하세요.",
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

