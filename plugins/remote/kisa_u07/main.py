"""Remote plugin for KISA U-07 unused account checks."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import shlex
import subprocess
from typing import Dict, List, Optional, Sequence

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_PASSWD_PATH = "/etc/passwd"
DEFAULT_SHADOW_PATH = "/etc/shadow"

LASTLOG_HEADER_PREFIX = "username"
LASTLOG_NEVER = "never logged in"

DATETIME_FORMATS = (
    "%a %b %d %H:%M:%S %z %Y",
    "%a %b %d %H:%M:%S %Y",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
)


@dataclass
class ReadResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None


@dataclass
class CommandResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None


@dataclass
class PasswdEntry:
    name: str
    uid: int
    shell: str
    line: str


@dataclass
class LastlogEntry:
    status: str
    last_login: Optional[datetime]
    raw: str


def _normalize_list(value, name: str) -> Optional[List[str]]:
    if value is None:
        return None
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        if not all(isinstance(item, str) for item in value):
            raise PluginConfigError(f"{name} must be an array of strings")
        return value
    raise PluginConfigError(f"{name} must be an array of strings")


def _parse_passwd(lines: List[str]) -> Dict[str, PasswdEntry]:
    entries: Dict[str, PasswdEntry] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name = parts[0].strip()
        uid_raw = parts[2].strip()
        shell = parts[6].strip()
        if not name:
            continue
        try:
            uid = int(uid_raw)
        except (TypeError, ValueError):
            continue
        entries[name] = PasswdEntry(name=name, uid=uid, shell=shell, line=raw_line.strip())
    return entries


def _parse_shadow_lock(lines: List[str]) -> Dict[str, bool]:
    locked: Dict[str, bool] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2:
            continue
        name = parts[0].strip()
        passwd_field = parts[1].strip()
        if not name:
            continue
        locked[name] = passwd_field.startswith("!") or passwd_field.startswith("*")
    return locked


def _is_login_shell(
    shell: str,
    login_shells: Optional[Sequence[str]],
    non_login_shells: Sequence[str],
) -> bool:
    if not shell:
        return False
    if login_shells is not None:
        return shell in login_shells
    return shell not in non_login_shells


def _to_utc_naive(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _parse_datetime(candidate: str) -> Optional[datetime]:
    for fmt in DATETIME_FORMATS:
        try:
            parsed = datetime.strptime(candidate, fmt)
        except ValueError:
            continue
        return _to_utc_naive(parsed)
    return None


def _parse_lastlog_lines(lines: List[str]) -> Dict[str, LastlogEntry]:
    entries: Dict[str, LastlogEntry] = {}
    for raw_line in lines:
        line = raw_line.rstrip()
        if not line.strip():
            continue
        if line.strip().lower().startswith(LASTLOG_HEADER_PREFIX):
            continue
        parts = line.split()
        if not parts:
            continue
        username = parts[0]
        rest = line[len(username):].strip()
        if not rest:
            continue
        if LASTLOG_NEVER in rest.lower():
            entries[username] = LastlogEntry(status="never", last_login=None, raw=line)
            continue

        parsed = None
        for count in (6, 5, 4):
            if len(parts) >= count + 1:
                candidate = " ".join(parts[-count:])
                parsed = _parse_datetime(candidate)
                if parsed:
                    break
        if parsed:
            entries[username] = LastlogEntry(status="parsed", last_login=parsed, raw=line)
        else:
            entries[username] = LastlogEntry(status="unknown", last_login=None, raw=line)
    return entries


class UnusedAccountCleanupCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        passwd_path = Path(self.context.config.get("passwd_path") or DEFAULT_PASSWD_PATH)
        shadow_path = Path(self.context.config.get("shadow_path") or DEFAULT_SHADOW_PATH)

        system_accounts = _normalize_list(
            self.context.config.get("system_accounts"),
            "system_accounts",
        ) or []
        non_login_shells = _normalize_list(
            self.context.config.get("non_login_shells"),
            "non_login_shells",
        ) or []
        login_shells = _normalize_list(
            self.context.config.get("login_shells"),
            "login_shells",
        )

        inactive_days = self._to_int(self.context.config.get("inactive_days"), "inactive_days")
        check_system_accounts = bool(self.context.config.get("check_system_accounts", True))
        check_inactive_accounts = bool(self.context.config.get("check_inactive_accounts", True))
        lastlog_command = str(self.context.config.get("lastlog_command") or "lastlog").strip()

        passwd_result = self._read_config_lines(passwd_path)
        shadow_result = self._read_config_lines(shadow_path)
        if passwd_result.lines is None or shadow_result.lines is None:
            self._add_unavailable(
                os_type,
                {"passwd": passwd_path, "shadow": shadow_path},
                [passwd_result, shadow_result],
            )
            return self.results

        passwd_entries = _parse_passwd(passwd_result.lines)
        shadow_locks = _parse_shadow_lock(shadow_result.lines)

        login_capable = []
        for entry in passwd_entries.values():
            if shadow_locks.get(entry.name, False):
                continue
            if not _is_login_shell(entry.shell, login_shells, non_login_shells):
                continue
            login_capable.append(entry)

        mode_map = {
            "passwd": passwd_result.mode,
            "shadow": shadow_result.mode,
        }

        if check_system_accounts:
            self._check_system_accounts(
                os_type,
                system_accounts,
                login_capable,
                passwd_path,
                shadow_path,
                mode_map,
                passwd_result,
                shadow_result,
            )

        if check_inactive_accounts:
            if not lastlog_command:
                raise PluginConfigError("lastlog_command must be a non-empty string")
            lastlog_result = self._run_lastlog(lastlog_command)
            if lastlog_result.lines is None:
                self._add_lastlog_unavailable(os_type, lastlog_command, lastlog_result)
                return self.results
            self._check_inactive_accounts(
                os_type,
                login_capable,
                lastlog_result,
                inactive_days,
                {"passwd": passwd_path, "shadow": shadow_path, "lastlog": lastlog_command},
                {**mode_map, "lastlog": lastlog_result.mode},
            )

        return self.results

    def _check_system_accounts(
        self,
        os_type: str,
        system_accounts: Sequence[str],
        login_capable: Sequence[PasswdEntry],
        passwd_path: Path,
        shadow_path: Path,
        modes: Dict[str, str],
        passwd_result: ReadResult,
        shadow_result: ReadResult,
    ) -> None:
        system_set = {name.strip() for name in system_accounts if name.strip()}
        if not system_set:
            return
        findings = []
        for entry in login_capable:
            if entry.name in system_set:
                findings.append(
                    {
                        "account": entry.name,
                        "shell": entry.shell,
                        "line": entry.line,
                    }
                )
        if not findings:
            return

        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path(
                {"passwd": passwd_path, "shadow": shadow_path}
            ),
            "mode": self._merge_modes(modes),
            "detected_value": findings,
            "source": "system",
            "line": findings[0].get("line"),
        }
        host = passwd_result.host or shadow_result.host
        if host:
            evidence["host"] = host
        self._add_vulnerability(os_type, evidence)

    def _check_inactive_accounts(
        self,
        os_type: str,
        login_capable: Sequence[PasswdEntry],
        lastlog_result: CommandResult,
        inactive_days: int,
        config_path,
        modes: Dict[str, str],
    ) -> None:
        lastlog_entries = _parse_lastlog_lines(lastlog_result.lines or [])
        now = datetime.utcnow()
        findings = []
        for entry in login_capable:
            lastlog = lastlog_entries.get(entry.name)
            if lastlog is None:
                continue
            if lastlog.status == "never":
                findings.append(
                    {
                        "account": entry.name,
                        "shell": entry.shell,
                        "last_login": "never",
                        "raw": lastlog.raw,
                        "line": entry.line,
                    }
                )
                continue
            if lastlog.status == "parsed" and lastlog.last_login:
                days = (now - lastlog.last_login).days
                if days >= inactive_days:
                    findings.append(
                        {
                            "account": entry.name,
                            "shell": entry.shell,
                            "last_login": lastlog.last_login.isoformat() + "Z",
                            "inactive_days": days,
                            "raw": lastlog.raw,
                            "line": entry.line,
                        }
                    )

        if not findings:
            return

        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path(config_path),
            "mode": self._merge_modes(modes),
            "detected_value": findings,
            "source": "inactive",
            "inactive_days": inactive_days,
            "line": findings[0].get("line"),
        }
        if lastlog_result.host:
            evidence["host"] = lastlog_result.host
        self._add_vulnerability(os_type, evidence)

    def _add_vulnerability(self, os_type: str, evidence: Dict) -> None:
        self.add_finding(
            vuln_id="KISA-U-07",
            title=f"{self._format_os(os_type)} 불필요 계정 존재",
            severity="Low",
            evidence=evidence,
            tags=["KISA:U-07"],
            description="로그인이 가능한 불필요/미사용 계정이 존재합니다.",
            solution="불필요한 계정을 삭제하거나 쉘을 nologin으로 변경하세요.",
        )

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
            vuln_id="KISA-U-07",
            title=f"{self._format_os(os_type)} 계정 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-07"],
            description="필수 파일을 읽지 못해 점검을 완료할 수 없습니다.",
            solution="대상 접근 권한과 설정 파일 경로를 확인하세요.",
        )

    def _add_lastlog_unavailable(
        self,
        os_type: str,
        command: str,
        result: CommandResult,
    ) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": {"lastlog": command},
            "mode": result.mode,
        }
        if result.host:
            evidence["host"] = result.host
        if result.error:
            evidence["error"] = result.error
        self.add_finding(
            vuln_id="KISA-U-07",
            title=f"{self._format_os(os_type)} 미사용 계정 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-07"],
            description="lastlog 실행 실패로 미사용 계정을 확인할 수 없습니다.",
            solution="lastlog 명령이 실행 가능한지와 권한을 확인하세요.",
        )

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

    def _run_lastlog(self, command: str) -> CommandResult:
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
                return CommandResult(None, "remote", str(exc), host)
            if result.exit_code != 0:
                error = result.stderr.strip() or f"SSH exit code {result.exit_code}"
                return CommandResult(None, "remote", error, host)
            return CommandResult(result.stdout.splitlines(), "remote", None, host)

        if allow_local:
            try:
                parsed = shlex.split(command)
                result = subprocess.run(
                    parsed,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                return CommandResult(None, "local", str(exc), None)
            if result.returncode != 0:
                error = result.stderr.strip() or f"Command exit code {result.returncode}"
                return CommandResult(None, "local", error, None)
            return CommandResult(result.stdout.splitlines(), "local", None, None)

        return CommandResult(None, "remote", "Missing SSH credentials", host)

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

    def _format_os(self, os_type: str) -> str:
        display = {
            "linux": "Linux",
            "solaris": "Solaris",
            "aix": "AIX",
            "hpux": "HP-UX",
        }
        return display.get(os_type, os_type.upper())

    def _to_int(self, value: object, name: str) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            raise PluginConfigError(f"{name} must be an integer")
        if parsed < 0:
            raise PluginConfigError(f"{name} must be >= 0")
        return parsed
