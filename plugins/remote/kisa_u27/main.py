"""Remote plugin for KISA U-27 rhosts/hosts.equiv checks."""

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


def _strip_comment(raw_line: str) -> str:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return ""
    if "#" in line:
        line = line.split("#", 1)[0].rstrip()
    return line


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


class RhostsHostsEquivCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        passwd_path = Path(self.context.config.get("passwd_path") or DEFAULT_PASSWD_PATH)
        hosts_equiv_path = Path(
            self.context.config.get("hosts_equiv_path") or "/etc/hosts.equiv"
        )
        rhosts_name = str(self.context.config.get("rhosts_name") or ".rhosts").strip()
        if not rhosts_name:
            raise PluginConfigError("rhosts_name must be a non-empty string")

        ignore_users = _normalize_list(
            self.context.config.get("ignore_users"),
            "ignore_users",
        )
        allowed_hosts_equiv_owners = _normalize_list(
            self.context.config.get("allowed_hosts_equiv_owners"),
            "allowed_hosts_equiv_owners",
        ) or ["root"]
        allow_root_owner = bool(self.context.config.get("allow_root_owner", True))
        allow_user_owner = bool(self.context.config.get("allow_user_owner", True))
        extra_allowed_owners = _normalize_list(
            self.context.config.get("extra_allowed_owners"),
            "extra_allowed_owners",
        )
        max_mode = self._to_positive_int(self.context.config.get("max_mode", 600), "max_mode")
        allow_group_write = bool(self.context.config.get("allow_group_write", False))
        allow_other_write = bool(self.context.config.get("allow_other_write", False))
        max_results = self._to_positive_int(self.context.config.get("max_results", 200), "max_results")

        client, host = self._get_ssh_client()

        issues = []
        errors = []
        checked_count = 0
        missing_count = 0

        hosts_result = self._read_permission(hosts_equiv_path, client, host)
        if hosts_result.missing:
            missing_count += 1
        elif hosts_result.perm is None or hosts_result.owner is None:
            if hosts_result.error:
                errors.append({"path": str(hosts_equiv_path), "error": hosts_result.error})
        else:
            content_result = self._read_config_lines(hosts_equiv_path, client, host)
            if content_result.lines is None:
                if content_result.error:
                    errors.append({"path": str(hosts_equiv_path), "error": content_result.error})
            else:
                checked_count += 1
                file_issues, plus_lines = self._evaluate_file(
                    content_result.lines,
                    hosts_result.owner,
                    hosts_result.perm,
                    allowed_hosts_equiv_owners,
                    allow_group_write,
                    allow_other_write,
                    max_mode,
                )
                if file_issues:
                    issues.append(
                        {
                            "file_type": "hosts.equiv",
                            "path": str(hosts_equiv_path),
                            "owner": hosts_result.owner,
                            "mode": self._format_octal(hosts_result.perm),
                            "issues": file_issues,
                            "plus_lines": plus_lines,
                            "raw": hosts_result.raw,
                            "method": hosts_result.method,
                        }
                    )

        passwd_result = self._read_config_lines(passwd_path, client, host)
        if passwd_result.lines is None:
            if passwd_result.error:
                errors.append({"path": str(passwd_path), "error": passwd_result.error})
        else:
            entries = _parse_passwd(passwd_result.lines, ignore_users)
            for entry in entries:
                rhosts_path = Path(rhosts_name) if rhosts_name.startswith("/") else entry.home / rhosts_name
                rhosts_result = self._read_permission(rhosts_path, client, host)
                if rhosts_result.missing:
                    missing_count += 1
                    continue
                if rhosts_result.perm is None or rhosts_result.owner is None:
                    if rhosts_result.error:
                        errors.append({"path": str(rhosts_path), "error": rhosts_result.error})
                    continue

                content_result = self._read_config_lines(rhosts_path, client, host)
                if content_result.lines is None:
                    if content_result.error:
                        errors.append({"path": str(rhosts_path), "error": content_result.error})
                    continue

                checked_count += 1
                allowed_owners = self._build_allowed_owners(
                    entry.name,
                    allow_root_owner,
                    allow_user_owner,
                    extra_allowed_owners,
                )
                file_issues, plus_lines = self._evaluate_file(
                    content_result.lines,
                    rhosts_result.owner,
                    rhosts_result.perm,
                    allowed_owners,
                    allow_group_write,
                    allow_other_write,
                    max_mode,
                )
                if file_issues:
                    issues.append(
                        {
                            "file_type": "rhosts",
                            "user": entry.name,
                            "path": str(rhosts_path),
                            "owner": rhosts_result.owner,
                            "mode": self._format_octal(rhosts_result.perm),
                            "issues": file_issues,
                            "plus_lines": plus_lines,
                            "raw": rhosts_result.raw,
                            "method": rhosts_result.method,
                        }
                    )

        if not issues:
            if checked_count == 0 and errors:
                self._add_unavailable(
                    os_type,
                    {"hosts_equiv": hosts_equiv_path, "passwd": passwd_path},
                    errors,
                    host,
                )
            return self.results

        limited = issues[:max_results]
        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path(
                {
                    "hosts_equiv": hosts_equiv_path,
                    "passwd": passwd_path,
                    "rhosts_name": rhosts_name,
                }
            ),
            "mode": self._merge_modes(
                {"hosts_equiv": hosts_result.mode, "passwd": passwd_result.mode}
            ),
            "detected_value": limited,
            "count": len(issues),
            "checked_files": checked_count,
            "missing_files": missing_count,
            "policy": {
                "allowed_hosts_equiv_owners": allowed_hosts_equiv_owners,
                "allow_root_owner": allow_root_owner,
                "allow_user_owner": allow_user_owner,
                "extra_allowed_owners": extra_allowed_owners,
                "max_mode": self._format_octal(self._parse_mode_value(max_mode)),
                "allow_group_write": allow_group_write,
                "allow_other_write": allow_other_write,
            },
        }
        if host:
            evidence["host"] = host
        if errors:
            evidence["partial_errors"] = errors[:max_results]

        self.add_finding(
            vuln_id="KISA-U-27",
            title=f"{self._format_os(os_type)} rhosts/hosts.equiv 사용 설정",
            severity="High",
            evidence=evidence,
            tags=["KISA:U-27"],
            description="rhosts 또는 hosts.equiv 파일에서 위험한 설정이 발견되었습니다.",
            solution="해당 파일을 제거하거나 '+' 사용을 금지하고 권한을 600으로 제한하세요.",
        )
        return self.results

    def _evaluate_file(
        self,
        lines: Sequence[str],
        owner: str,
        perm: int,
        allowed_owners: Sequence[str],
        allow_group_write: bool,
        allow_other_write: bool,
        max_mode: int,
    ) -> Tuple[List[str], List[str]]:
        issues = []
        plus_lines = []
        for raw in lines:
            line = _strip_comment(raw)
            if not line:
                continue
            tokens = line.split()
            if tokens and tokens[0] == "+":
                plus_lines.append(line)
        if plus_lines:
            issues.append("plus_entry")

        allowed = {item.strip() for item in allowed_owners if item and item.strip()}
        if allowed and owner not in allowed:
            issues.append("owner_mismatch")

        expected_mode = self._parse_mode_value(max_mode)
        if expected_mode is not None and perm > expected_mode:
            issues.append("permission_too_open")
        if not allow_group_write and (perm & 0o020):
            issues.append("group_writable")
        if not allow_other_write and (perm & 0o002):
            issues.append("other_writable")
        return issues, plus_lines

    def _build_allowed_owners(
        self,
        username: str,
        allow_root_owner: bool,
        allow_user_owner: bool,
        extra_allowed_owners: Sequence[str],
    ) -> List[str]:
        allowed = {item.strip() for item in extra_allowed_owners if item and item.strip()}
        if allow_root_owner:
            allowed.add("root")
        if allow_user_owner:
            allowed.add(username)
        return sorted(allowed)

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
                if _is_missing_error(error):
                    return ReadResult(None, "remote", error, host, config_path)
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

    def _add_unavailable(self, os_type: str, config_path, errors, host: Optional[str]) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path(config_path),
        }
        if host:
            evidence["host"] = host
        if errors:
            evidence["error"] = errors[0] if len(errors) == 1 else errors
        self.add_finding(
            vuln_id="KISA-U-27",
            title=f"{self._format_os(os_type)} rhosts/hosts.equiv 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-27"],
            description="필수 파일을 읽지 못해 점검을 완료할 수 없습니다.",
            solution="대상 접근 권한과 파일 경로를 확인하세요.",
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

    def _merge_modes(self, modes: Dict[str, Optional[str]]):
        clean = {key: value for key, value in modes.items() if value}
        if not clean:
            return None
        unique = set(clean.values())
        if len(unique) == 1:
            return next(iter(unique))
        return clean

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
