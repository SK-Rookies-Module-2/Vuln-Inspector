"""Remote plugin for KISA U-46 sendmail restrictqrun checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import shlex
import subprocess
from typing import Dict, List, Optional, Sequence, Tuple

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_SENDMAIL_CF = "/etc/mail/sendmail.cf"
DEFAULT_PROCESS_COMMAND = "ps -ef"

PRIVACY_PATTERN = re.compile(r"^O\\s+PrivacyOptions\\s*=\\s*(.+)$", re.IGNORECASE)
SENDMAIL_PATTERN = re.compile(r"\\bsendmail\\b", re.IGNORECASE)


@dataclass
class ReadResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None
    missing: bool = False


@dataclass
class CommandResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    command: Optional[str] = None


def _strip_comment(raw_line: str) -> str:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return ""
    if "#" in line:
        line = line.split("#", 1)[0].rstrip()
    return line.strip()


def _parse_privacy_options(lines: Sequence[str]) -> Optional[str]:
    for raw_line in lines:
        line = _strip_comment(raw_line)
        if not line:
            continue
        match = PRIVACY_PATTERN.match(line)
        if match:
            return match.group(1).strip()
    return None


def _has_restrictqrun(value: str) -> bool:
    lowered = value.lower()
    return "restrictqrun" in lowered.replace(" ", "")


def _has_sendmail_process(lines: Sequence[str]) -> bool:
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if "grep" in lowered and "sendmail" in lowered:
            continue
        if SENDMAIL_PATTERN.search(line):
            return True
    return False


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


class SendmailRestrictQrunCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        sendmail_cf_path = Path(self.context.config.get("sendmail_cf_path") or DEFAULT_SENDMAIL_CF)
        require_smtp_enabled = bool(self.context.config.get("require_smtp_enabled", False))
        check_service = bool(self.context.config.get("check_service", False))
        process_command = str(self.context.config.get("smtp_process_command") or DEFAULT_PROCESS_COMMAND).strip()
        if check_service and not process_command:
            raise PluginConfigError("smtp_process_command must be a non-empty string")

        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        client, host = self._get_ssh_client()

        checked_sources = []
        errors: List[Dict[str, str]] = []
        modes: Dict[str, Optional[str]] = {}

        if check_service:
            result = self._run_command(process_command, client, host)
            modes["process"] = result.mode
            checked_sources.append("process")
            if result.lines is None:
                errors.append(
                    {
                        "source": "process",
                        "command": process_command,
                        "error": result.error or "Command failed",
                    }
                )
            else:
                smtp_running = _has_sendmail_process(result.lines)
                if require_smtp_enabled and not smtp_running:
                    return self.results

        config_result = self._read_config_lines(sendmail_cf_path, client, host)
        modes["sendmail_cf"] = config_result.mode
        if config_result.lines is None:
            self._add_unavailable(
                os_type,
                sendmail_cf_path,
                process_command if check_service else None,
                errors,
                self._merge_modes(modes),
                host,
                config_result,
            )
            return self.results

        checked_sources.append("sendmail_cf")
        privacy_value = _parse_privacy_options(config_result.lines)
        if privacy_value is None or not _has_restrictqrun(privacy_value):
            detected = privacy_value or "missing"
            evidence = {
                "os_type": os_type,
                "config_path": {
                    "sendmail_cf_path": str(sendmail_cf_path),
                    "process_command": process_command if check_service else None,
                },
                "mode": self._merge_modes(modes),
                "detected_value": {
                    "privacy_options": detected,
                    "issue": "restrictqrun_missing",
                },
                "count": 1,
                "checked_sources": checked_sources,
            }
            if host:
                evidence["host"] = host
            if errors:
                evidence["partial_errors"] = errors[:max_results]

            self.add_finding(
                vuln_id="KISA-U-46",
                title=f"{self._format_os(os_type)} Sendmail restrictqrun 미설정",
                severity="High",
                evidence=evidence,
                tags=["KISA:U-46"],
                description="Sendmail PrivacyOptions에 restrictqrun 옵션이 설정되어 있지 않습니다.",
                solution="sendmail.cf에서 PrivacyOptions에 restrictqrun을 추가하세요.",
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
                error = (result.stderr or result.stdout or "").strip()
                if _is_missing_error(error):
                    return ReadResult(
                        None,
                        "remote",
                        error or "File not found",
                        host,
                        config_path,
                        True,
                    )
                return ReadResult(None, "remote", error or f"SSH exit code {result.exit_code}", host, config_path)
            return ReadResult(
                result.stdout.splitlines(),
                "remote",
                None,
                host,
                config_path,
            )

        if allow_local:
            if not config_path.exists():
                return ReadResult(None, "local", "File not found", None, config_path, True)
            return ReadResult(
                config_path.read_text().splitlines(),
                "local",
                None,
                None,
                config_path,
            )

        return ReadResult(None, "remote", "Missing SSH credentials", host, config_path)

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
                    timeout=30,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                return CommandResult(None, "local", str(exc), None, command)
            if result.returncode != 0:
                error = result.stderr.strip() or f"Command exit code {result.returncode}"
                return CommandResult(None, "local", error, None, command)
            return CommandResult(result.stdout.splitlines(), "local", None, None, command)

        return CommandResult(None, "remote", "Missing SSH credentials", host, command)

    def _add_unavailable(
        self,
        os_type: str,
        sendmail_cf_path: Path,
        process_command: Optional[str],
        errors: List[Dict[str, str]],
        mode: Optional[object],
        host: Optional[str],
        config_result: ReadResult,
    ) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": {
                "sendmail_cf_path": str(sendmail_cf_path),
                "process_command": process_command,
            },
            "mode": mode,
            "partial_errors": errors,
        }
        if config_result.error:
            evidence["error"] = config_result.error
        if host:
            evidence["host"] = host
        self.add_finding(
            vuln_id="KISA-U-46",
            title=f"{self._format_os(os_type)} Sendmail 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-46"],
            description="Sendmail 설정을 확인할 수 없습니다.",
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

    def _merge_modes(self, modes: Dict[str, Optional[str]]):
        clean = {key: value for key, value in modes.items() if value}
        if not clean:
            return None
        unique = set(clean.values())
        if len(unique) == 1:
            return next(iter(unique))
        return clean

    def _format_os(self, os_type: str) -> str:
        display = {
            "linux": "Linux",
            "solaris": "Solaris",
            "aix": "AIX",
            "hpux": "HP-UX",
        }
        return display.get(os_type, os_type.upper())
