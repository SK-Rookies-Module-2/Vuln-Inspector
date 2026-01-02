"""Remote plugin for KISA U-47 SMTP relay restriction checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import shlex
from typing import Dict, List, Optional, Sequence, Tuple

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_ACCESS_PATH = "/etc/mail/access"
DEFAULT_ACCESS_DB_PATH = "/etc/mail/access.db"
DEFAULT_SENDMAIL_CF_PATH = "/etc/mail/sendmail.cf"

PROMISCUOUS_RELAY_RE = re.compile(r"\bpromiscuous_relay\b", re.IGNORECASE)
RELAYING_DENIED_RE = re.compile(r"relaying denied", re.IGNORECASE)


@dataclass
class ReadResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None
    missing: bool = False


@dataclass
class PathCheckResult:
    exists: Optional[bool]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None


def _strip_comment(raw_line: str) -> str:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return ""
    if "#" in line:
        line = line.split("#", 1)[0].rstrip()
    return line.strip()


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


class SmtpRelayRestrictionCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        access_path = Path(self.context.config.get("access_path") or DEFAULT_ACCESS_PATH)
        access_db_path = Path(
            self.context.config.get("access_db_path") or DEFAULT_ACCESS_DB_PATH
        )
        sendmail_cf_path = Path(
            self.context.config.get("sendmail_cf_path") or DEFAULT_SENDMAIL_CF_PATH
        )

        check_access = bool(self.context.config.get("check_access", True))
        check_access_db = bool(self.context.config.get("check_access_db", True))
        check_sendmail_cf = bool(self.context.config.get("check_sendmail_cf", True))

        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        client, host = self._get_ssh_client()

        issues: List[Dict[str, object]] = []
        errors: List[object] = []
        missing_files: List[str] = []
        modes: Dict[str, str] = {}
        checked = 0
        config_present = False

        if check_access:
            result = self._read_config_lines(access_path, client, host)
            modes["access"] = result.mode
            if result.host:
                host = host or result.host
            if result.lines is None:
                if result.missing:
                    missing_files.append(str(access_path))
                    checked += 1
                else:
                    errors.append(result)
            else:
                checked += 1
                config_present = True
                prom_line = self._find_promiscuous_relay(result.lines)
                if prom_line:
                    issues.append(
                        {
                            "source": "access",
                            "path": str(access_path),
                            "issue": "promiscuous_relay",
                            "line": prom_line,
                        }
                    )

        if check_access_db:
            result = self._check_path_exists(access_db_path, client, host)
            modes["access_db"] = result.mode
            if result.host:
                host = host or result.host
            if result.exists is None:
                errors.append(result)
            else:
                checked += 1
                if result.exists:
                    config_present = True
                else:
                    missing_files.append(str(access_db_path))
                    if config_present:
                        issues.append(
                            {
                                "source": "access_db",
                                "path": str(access_db_path),
                                "issue": "access_db_missing",
                            }
                        )

        if check_sendmail_cf:
            result = self._read_config_lines(sendmail_cf_path, client, host)
            modes["sendmail_cf"] = result.mode
            if result.host:
                host = host or result.host
            if result.lines is None:
                if result.missing:
                    missing_files.append(str(sendmail_cf_path))
                    checked += 1
                else:
                    errors.append(result)
            else:
                checked += 1
                config_present = True
                relaying_line = self._find_relaying_denied(result.lines)
                if not relaying_line:
                    issues.append(
                        {
                            "source": "sendmail_cf",
                            "path": str(sendmail_cf_path),
                            "issue": "relaying_denied_missing",
                        }
                    )

        if issues:
            evidence = {
                "os_type": os_type,
                "config_path": {
                    "access_path": str(access_path),
                    "access_db_path": str(access_db_path),
                    "sendmail_cf_path": str(sendmail_cf_path),
                },
                "mode": self._merge_modes(modes),
                "detected_value": issues[:max_results],
                "count": len(issues),
            }
            if host:
                evidence["host"] = host
            if missing_files:
                evidence["missing_files"] = missing_files
            error_list = [err.error for err in errors if getattr(err, "error", None)]
            if error_list:
                evidence["partial_errors"] = error_list[:max_results]

            self.add_finding(
                vuln_id="KISA-U-47",
                title=f"{self._format_os(os_type)} 스팸 메일 릴레이 제한 미흡",
                severity="High",
                evidence=evidence,
                tags=["KISA:U-47"],
                description="SMTP 릴레이 제한이 충분히 설정되지 않았습니다.",
                solution="Sendmail 릴레이 제한을 적용하고 access.db를 갱신하세요.",
            )
            return self.results

        if checked == 0 and errors:
            self._add_unavailable(os_type, access_path, sendmail_cf_path, errors)

        return self.results

    def _find_promiscuous_relay(self, lines: Sequence[str]) -> Optional[str]:
        for raw_line in lines:
            line = _strip_comment(raw_line)
            if not line:
                continue
            if PROMISCUOUS_RELAY_RE.search(line):
                return raw_line.strip()
        return None

    def _find_relaying_denied(self, lines: Sequence[str]) -> Optional[str]:
        for raw_line in lines:
            line = _strip_comment(raw_line)
            if not line:
                continue
            if RELAYING_DENIED_RE.search(line):
                return raw_line.strip()
        return None

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
                error = (result.stderr or result.stdout or "").strip()
                if _is_missing_error(error):
                    return ReadResult(None, "remote", error or "File not found", host, config_path, True)
                return ReadResult(None, "remote", error or f"SSH exit code {result.exit_code}", host, config_path)
            return ReadResult(result.stdout.splitlines(), "remote", None, host, config_path)

        if allow_local:
            if not config_path.exists():
                return ReadResult(None, "local", "File not found", None, config_path, True)
            try:
                lines = config_path.read_text().splitlines()
            except OSError as exc:
                return ReadResult(None, "local", str(exc), None, config_path)
            return ReadResult(lines, "local", None, None, config_path)

        return ReadResult(None, "remote", "Missing SSH credentials", host, config_path)

    def _check_path_exists(
        self,
        path: Path,
        client: Optional[SshClient],
        host: Optional[str],
    ) -> PathCheckResult:
        allow_local = bool(self.context.config.get("allow_local_fallback", False))
        if client:
            try:
                command = f"test -f {shlex.quote(str(path))}"
                result = client.run(command)
            except AdapterError as exc:
                return PathCheckResult(None, "remote", str(exc), host, path)
            if result.exit_code == 0:
                return PathCheckResult(True, "remote", None, host, path)
            if result.exit_code == 1 and not result.stderr.strip():
                return PathCheckResult(False, "remote", None, host, path)
            error = (result.stderr or result.stdout or "").strip()
            return PathCheckResult(None, "remote", error or f"SSH exit code {result.exit_code}", host, path)

        if allow_local:
            return PathCheckResult(path.is_file(), "local", None, None, path)

        return PathCheckResult(None, "remote", "Missing SSH credentials", host, path)

    def _add_unavailable(
        self,
        os_type: str,
        access_path: Path,
        sendmail_cf_path: Path,
        errors: List[object],
    ) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": {
                "access_path": str(access_path),
                "sendmail_cf_path": str(sendmail_cf_path),
            },
            "mode": self._merge_modes(
                {
                    str(idx): err.mode
                    for idx, err in enumerate(errors)
                    if getattr(err, "mode", None)
                }
            ),
        }
        host = next((err.host for err in errors if getattr(err, "host", None)), None)
        if host:
            evidence["host"] = host
        error_list = [err.error for err in errors if getattr(err, "error", None)]
        if error_list:
            evidence["error"] = error_list[0]
            evidence["errors"] = error_list

        self.add_finding(
            vuln_id="KISA-U-47",
            title=f"{self._format_os(os_type)} SMTP 릴레이 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-47"],
            description="SMTP 릴레이 설정을 확인할 수 없습니다.",
            solution="대상 접근 권한과 설정 파일 경로를 확인하세요.",
        )

    def _to_positive_int(self, value: object, name: str) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            raise PluginConfigError(f"{name} must be an integer")
        if parsed <= 0:
            raise PluginConfigError(f"{name} must be > 0")
        return parsed

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
