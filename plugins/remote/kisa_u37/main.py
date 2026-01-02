"""Remote plugin for KISA U-37 cron/at permission checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import pwd
import shlex
import stat
import subprocess
from typing import Dict, List, Optional, Sequence, Tuple

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_COMMAND_PATHS = ("/usr/bin/crontab", "/usr/bin/at")
DEFAULT_CONFIG_PATHS = ("/etc/cron.d", "/etc/cron.daily", "/etc/cron.allow", "/etc/at.allow")
DEFAULT_FIND_COMMAND = "find {path} -type f -ls"


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


def _parse_find_entry(line: str) -> Optional[Tuple[str, str, str]]:
    parts = line.split()
    if len(parts) < 11:
        return None
    perm = parts[2]
    owner = parts[4]
    path = parts[-1]
    return perm, owner, path


class CronAtPermissionCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        command_paths = _normalize_list(
            self.context.config.get("command_paths"),
            "command_paths",
        ) or list(DEFAULT_COMMAND_PATHS)
        allow_group_execute = bool(self.context.config.get("allow_group_execute", False))
        allow_other_execute = bool(self.context.config.get("allow_other_execute", False))

        config_search_paths = _normalize_list(
            self.context.config.get("config_search_paths"),
            "config_search_paths",
        ) or list(DEFAULT_CONFIG_PATHS)
        find_command = str(self.context.config.get("find_command") or DEFAULT_FIND_COMMAND).strip()
        if not find_command:
            raise PluginConfigError("find_command must be a non-empty string")

        allowed_owners = _normalize_list(
            self.context.config.get("allowed_owners"),
            "allowed_owners",
        ) or ["root"]
        max_mode = self._to_positive_int(self.context.config.get("max_mode", 640), "max_mode")
        allow_group_write = bool(self.context.config.get("allow_group_write", False))
        allow_other_write = bool(self.context.config.get("allow_other_write", False))
        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        client, host = self._get_ssh_client()

        issues = []
        errors = []
        missing_paths = []
        checked_files = 0
        modes: Dict[str, str] = {}

        for path_value in command_paths:
            path = Path(path_value)
            result = self._read_permission(path, client, host)
            if result.mode:
                modes[str(path)] = result.mode
            if result.missing:
                missing_paths.append(str(path))
                continue
            if result.perm is None or result.owner is None:
                if result.error:
                    errors.append({"path": str(path), "error": result.error})
                continue
            checked_files += 1
            command_issues = []
            if not allow_group_execute and (result.perm & 0o010):
                command_issues.append("group_executable")
            if not allow_other_execute and (result.perm & 0o001):
                command_issues.append("other_executable")
            if command_issues:
                issues.append(
                    {
                        "category": "command",
                        "path": str(path),
                        "owner": result.owner,
                        "mode": self._format_octal(result.perm),
                        "raw": result.raw,
                        "method": result.method,
                        "issues": command_issues,
                    }
                )

        for path_value in config_search_paths:
            command = self._build_command(find_command, path_value)
            result = self._run_command(command, client, host)
            if result.mode:
                modes[command] = result.mode
            if result.lines is None:
                if _is_missing_error(result.error):
                    missing_paths.append(path_value)
                    continue
                if result.error:
                    errors.append({"command": command, "error": result.error})
                continue
            for raw in result.lines:
                if not raw.strip():
                    continue
                parsed = _parse_find_entry(raw)
                if not parsed:
                    continue
                permstr, owner, path = parsed
                mode_value = _permstr_to_mode(permstr)
                if mode_value is None:
                    continue
                checked_files += 1
                file_issues = []
                allowed = {item.strip() for item in allowed_owners if item and item.strip()}
                if allowed and owner not in allowed:
                    file_issues.append("owner_mismatch")
                expected_mode = self._parse_mode_value(max_mode)
                if expected_mode is not None and mode_value > expected_mode:
                    file_issues.append("permission_too_open")
                if not allow_group_write and (mode_value & 0o020):
                    file_issues.append("group_writable")
                if not allow_other_write and (mode_value & 0o002):
                    file_issues.append("other_writable")
                if file_issues:
                    issues.append(
                        {
                            "category": "config",
                            "path": path,
                            "owner": owner,
                            "mode": self._format_octal(mode_value),
                            "raw": raw,
                            "issues": file_issues,
                        }
                    )

        if not issues:
            if checked_files == 0 and errors:
                self._add_unavailable(
                    os_type,
                    {
                        "command_paths": command_paths,
                        "config_search_paths": config_search_paths,
                        "find_command": find_command,
                    },
                    errors,
                    host,
                )
            return self.results

        limited = issues[:max_results]
        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path(
                {
                    "command_paths": command_paths,
                    "config_search_paths": config_search_paths,
                    "find_command": find_command,
                }
            ),
            "mode": self._merge_modes(modes),
            "detected_value": limited,
            "count": len(issues),
            "checked_files": checked_files,
            "missing_paths": missing_paths,
            "policy": {
                "allow_group_execute": allow_group_execute,
                "allow_other_execute": allow_other_execute,
                "allowed_owners": allowed_owners,
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
            vuln_id="KISA-U-37",
            title=f"{self._format_os(os_type)} crontab/at 권한 설정 미흡",
            severity="High",
            evidence=evidence,
            tags=["KISA:U-37"],
            description="crontab/at 명령 또는 관련 설정 파일 권한이 기준을 만족하지 않습니다.",
            solution="일반 사용자 실행 권한을 제거하고 관련 설정 파일 소유자를 root, 권한을 640 이하로 설정하세요.",
        )
        return self.results

    def _build_command(self, template: str, path: str) -> str:
        command = template
        if "{path}" in command:
            command = command.replace("{path}", shlex.quote(path))
        return command

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

    def _run_command(
        self,
        command: str,
        client: Optional[SshClient],
        host: Optional[str],
    ) -> CommandResult:
        allow_local = bool(self.context.config.get("allow_local_fallback", False))
        if client:
            try:
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
            vuln_id="KISA-U-37",
            title=f"{self._format_os(os_type)} crontab/at 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-37"],
            description="crontab/at 관련 파일을 확인할 수 없습니다.",
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

    def _merge_modes(self, modes: Dict[str, str]):
        if not modes:
            return None
        unique = set(modes.values())
        if len(unique) == 1:
            return next(iter(unique))
        return modes

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
