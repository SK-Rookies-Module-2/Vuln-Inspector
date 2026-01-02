"""Remote plugin for KISA U-32 home directory existence checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shlex
from typing import Dict, List, Optional, Sequence, Tuple

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_PASSWD_PATH = "/etc/passwd"
DEFAULT_IGNORE_HOME_PATHS = ("/dev/null", "/nonexistent", "/var/empty")


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
    home: Optional[Path]
    raw_home: str
    line: str


@dataclass
class DirCheckResult:
    exists: Optional[bool]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None
    user: Optional[str] = None


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


def _parse_passwd(lines: Sequence[str], ignore_users: Sequence[str]) -> List[PasswdEntry]:
    ignore_set = {name.strip() for name in ignore_users if name and name.strip()}
    entries: List[PasswdEntry] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name = parts[0].strip()
        home_raw = parts[5].strip()
        if not name or name in ignore_set:
            continue
        home_path = Path(home_raw) if home_raw else None
        if home_path and not home_path.is_absolute():
            home_path = None
        entries.append(
            PasswdEntry(
                name=name,
                home=home_path,
                raw_home=home_raw,
                line=raw_line.strip(),
            )
        )
    return entries


def _normalize_prefixes(prefixes: Sequence[str]) -> List[str]:
    normalized = []
    for prefix in prefixes:
        trimmed = prefix.strip()
        if not trimmed:
            continue
        normalized.append(trimmed.rstrip("/"))
    return normalized


def _is_ignored_home(raw_home: str, ignore_set: set[str], prefixes: Sequence[str]) -> bool:
    if not raw_home:
        return False
    if raw_home in ignore_set:
        return True
    for prefix in prefixes:
        if not prefix:
            continue
        if raw_home == prefix or raw_home.startswith(prefix + "/"):
            return True
    return False


class HomeDirectoryExistenceCheck(BasePlugin):
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
        ) or []
        ignore_home_paths = _normalize_list(
            self.context.config.get("ignore_home_paths"),
            "ignore_home_paths",
        )
        if ignore_home_paths is None:
            ignore_home_paths = list(DEFAULT_IGNORE_HOME_PATHS)
        ignore_home_prefixes = _normalize_list(
            self.context.config.get("ignore_home_prefixes"),
            "ignore_home_prefixes",
        ) or []
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
        ignore_set = {path.strip() for path in ignore_home_paths if path and path.strip()}
        prefixes = _normalize_prefixes(ignore_home_prefixes)

        missing_entries = []
        errors = []
        checked_count = 0
        skipped_count = 0

        for entry in entries:
            if _is_ignored_home(entry.raw_home, ignore_set, prefixes):
                skipped_count += 1
                continue
            if not entry.raw_home:
                missing_entries.append(
                    {
                        "account": entry.name,
                        "home": entry.raw_home,
                        "status": "home_not_set",
                        "line": entry.line,
                    }
                )
                continue
            if entry.home is None:
                missing_entries.append(
                    {
                        "account": entry.name,
                        "home": entry.raw_home,
                        "status": "home_not_absolute",
                        "line": entry.line,
                    }
                )
                continue

            result = self._check_directory(entry.home, client, host, entry.name)
            if result.exists is True:
                checked_count += 1
                continue
            if result.exists is False:
                checked_count += 1
                missing_entries.append(
                    {
                        "account": entry.name,
                        "home": str(entry.home),
                        "status": "home_missing",
                        "line": entry.line,
                    }
                )
                continue
            errors.append(
                {
                    "account": entry.name,
                    "home": str(entry.home),
                    "error": result.error or "Home check failed",
                }
            )

        if not missing_entries:
            if errors and checked_count == 0:
                self._add_unavailable(os_type, passwd_path, passwd_result, errors)
            return self.results

        limited = missing_entries[:max_results]
        evidence = {
            "os_type": os_type,
            "config_path": str(passwd_path),
            "mode": passwd_result.mode,
            "detected_value": limited,
            "count": len(missing_entries),
            "checked_count": checked_count,
            "skipped_count": skipped_count,
        }
        if host:
            evidence["host"] = host
        if errors:
            evidence["partial_errors"] = errors[:max_results]

        self.add_finding(
            vuln_id="KISA-U-32",
            title=f"{self._format_os(os_type)} 홈 디렉터리 누락",
            severity="Medium",
            evidence=evidence,
            tags=["KISA:U-32"],
            description="/etc/passwd에 등록된 홈 디렉터리가 존재하지 않는 계정이 있습니다.",
            solution="계정별 홈 디렉터리를 생성하거나 불필요한 계정을 정리하세요.",
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

    def _check_directory(
        self,
        path: Path,
        client: Optional[SshClient],
        host: Optional[str],
        user: str,
    ) -> DirCheckResult:
        allow_local = bool(self.context.config.get("allow_local_fallback", False))
        if client:
            try:
                command = f"test -d {shlex.quote(str(path))}"
                result = client.run(command)
            except AdapterError as exc:
                return DirCheckResult(None, "remote", str(exc), host, path, user)
            if result.exit_code == 0:
                return DirCheckResult(True, "remote", None, host, path, user)
            if result.exit_code == 1:
                return DirCheckResult(False, "remote", None, host, path, user)
            error = (result.stderr or result.stdout or "").strip()
            return DirCheckResult(None, "remote", error or "Home check failed", host, path, user)

        if allow_local:
            try:
                exists = path.is_dir()
            except OSError as exc:
                return DirCheckResult(None, "local", str(exc), None, path, user)
            return DirCheckResult(exists, "local", None, None, path, user)

        return DirCheckResult(None, "remote", "Missing SSH credentials", host, path, user)

    def _add_unavailable(
        self,
        os_type: str,
        path: Path,
        result: ReadResult,
        errors: Optional[List[Dict[str, str]]] = None,
    ) -> None:
        evidence = self._base_evidence(os_type, path, result)
        if result.error:
            evidence["error"] = result.error
        if errors:
            evidence["partial_errors"] = errors
        self.add_finding(
            vuln_id="KISA-U-32",
            title=f"{self._format_os(os_type)} 홈 디렉터리 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-32"],
            description="홈 디렉터리 존재 여부를 확인할 수 없습니다.",
            solution="대상 접근 권한과 /etc/passwd 경로를 확인하세요.",
        )

    def _base_evidence(self, os_type: str, path: Path, result: ReadResult) -> Dict:
        evidence = {
            "os_type": os_type,
            "config_path": str(path),
            "mode": result.mode,
        }
        if result.host:
            evidence["host"] = result.host
        return evidence

    def _to_positive_int(self, value: object, name: str) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            raise PluginConfigError(f"{name} must be an integer")
        if parsed <= 0:
            raise PluginConfigError(f"{name} must be > 0")
        return parsed

    def _format_os(self, os_type: str) -> str:
        display = {
            "linux": "Linux",
            "solaris": "Solaris",
            "aix": "AIX",
            "hpux": "HP-UX",
        }
        return display.get(os_type, os_type.upper())
