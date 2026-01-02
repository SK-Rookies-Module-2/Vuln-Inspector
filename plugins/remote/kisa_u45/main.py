"""Remote plugin for KISA U-45 mail service version checks."""

from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
import subprocess
from typing import Dict, List, Optional, Sequence, Tuple

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_SENDMAIL_COMMAND = "sh -lc 'sendmail -d0.1 < /dev/null | grep Version'"
DEFAULT_POSTFIX_COMMAND = "postconf mail_version"

SENDMAIL_VERSION_RE = re.compile(r"\bVersion\s+([0-9][0-9A-Za-z.\-]+)\b", re.IGNORECASE)
POSTFIX_VERSION_RE = re.compile(r"\bmail_version\s*=\s*([0-9][0-9A-Za-z.\-]+)\b", re.IGNORECASE)
GENERIC_VERSION_RE = re.compile(r"([0-9]+(?:\.[0-9]+){0,3})")


@dataclass
class CommandResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    command: Optional[str] = None


def _is_command_missing(error: Optional[str]) -> bool:
    if not error:
        return False
    lowered = error.lower()
    return "not found" in lowered or "command not found" in lowered


class MailServiceVersionCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        sendmail_command = str(
            self.context.config.get("sendmail_command") or DEFAULT_SENDMAIL_COMMAND
        ).strip()
        postfix_command = str(
            self.context.config.get("postfix_command") or DEFAULT_POSTFIX_COMMAND
        ).strip()
        if not sendmail_command and not postfix_command:
            raise PluginConfigError("At least one command must be configured")

        min_sendmail_version = self.context.config.get("min_sendmail_version")
        min_postfix_version = self.context.config.get("min_postfix_version")
        report_unknown = bool(self.context.config.get("report_unknown", True))
        max_results = self._to_positive_int(
            self.context.config.get("max_results", 50),
            "max_results",
        )

        client, host = self._get_ssh_client()

        results = []
        errors = []

        if sendmail_command:
            sendmail_result = self._run_command(sendmail_command, client, host)
            results.append(
                self._evaluate_service(
                    "sendmail",
                    sendmail_command,
                    sendmail_result,
                    min_sendmail_version,
                )
            )
            if sendmail_result.lines is None and sendmail_result.error and not _is_command_missing(
                sendmail_result.error
            ):
                errors.append({"command": sendmail_command, "error": sendmail_result.error})

        if postfix_command:
            postfix_result = self._run_command(postfix_command, client, host)
            results.append(
                self._evaluate_service(
                    "postfix",
                    postfix_command,
                    postfix_result,
                    min_postfix_version,
                )
            )
            if postfix_result.lines is None and postfix_result.error and not _is_command_missing(
                postfix_result.error
            ):
                errors.append({"command": postfix_command, "error": postfix_result.error})

        available = [item for item in results if item["status"] != "missing"]
        if not available:
            return self.results

        outdated = [item for item in available if item["status"] == "outdated"]
        unknown = [item for item in available if item["status"] == "unknown"]

        if not outdated and not unknown and not errors:
            return self.results

        evidence = {
            "os_type": os_type,
            "config_path": {
                "sendmail_command": sendmail_command,
                "postfix_command": postfix_command,
            },
            "detected_value": {
                "services": available[:max_results],
                "min_versions": {
                    "sendmail": min_sendmail_version,
                    "postfix": min_postfix_version,
                },
            },
        }
        if host:
            evidence["host"] = host
        if errors:
            evidence["partial_errors"] = errors[:max_results]

        if outdated:
            self.add_finding(
                vuln_id="KISA-U-45",
                title=f"{self._format_os(os_type)} 메일 서비스 구버전 사용",
                severity="High",
                evidence=evidence,
                tags=["KISA:U-45"],
                description="메일 서비스 버전이 기준보다 낮습니다.",
                solution="Sendmail/Postfix를 최신 패치 버전으로 업데이트하세요.",
            )
            return self.results

        if unknown and report_unknown:
            self.add_finding(
                vuln_id="KISA-U-45",
                title=f"{self._format_os(os_type)} 메일 서비스 버전 확인 필요",
                severity="Info",
                evidence=evidence,
                tags=["KISA:U-45"],
                description="메일 서비스 버전은 확인되었으나 기준 버전 정보가 없습니다.",
                solution="벤더 권고 최신 버전과 비교해 구버전 여부를 확인하세요.",
            )

        return self.results

    def _evaluate_service(
        self,
        service: str,
        command: str,
        result: CommandResult,
        min_version: Optional[str],
    ) -> Dict[str, object]:
        info: Dict[str, object] = {
            "service": service,
            "command": command,
            "status": "missing",
            "version": None,
            "min_version": min_version,
            "lines": None,
        }
        if result.lines is None:
            if result.error and not _is_command_missing(result.error):
                info["status"] = "unknown"
                info["error"] = result.error
            return info

        version = self._extract_version(service, result.lines)
        info["lines"] = result.lines[:5]
        if version is None:
            info["status"] = "unknown"
            return info

        info["version"] = version
        if not min_version:
            info["status"] = "unknown"
            return info

        current = self._normalize_version(version)
        minimum = self._normalize_version(min_version)
        if current is None or minimum is None:
            info["status"] = "unknown"
            return info

        if self._is_version_lower(current, minimum):
            info["status"] = "outdated"
            return info

        info["status"] = "ok"
        return info

    def _extract_version(self, service: str, lines: Sequence[str]) -> Optional[str]:
        patterns = []
        if service == "sendmail":
            patterns.append(SENDMAIL_VERSION_RE)
        if service == "postfix":
            patterns.append(POSTFIX_VERSION_RE)
        patterns.append(GENERIC_VERSION_RE)

        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue
            for pattern in patterns:
                match = pattern.search(line)
                if match:
                    return match.group(1)
        return None

    def _normalize_version(self, value: str) -> Optional[Tuple[int, ...]]:
        if not value:
            return None
        parts = re.findall(r"\d+", value)
        if not parts:
            return None
        return tuple(int(part) for part in parts)

    def _is_version_lower(self, current: Tuple[int, ...], minimum: Tuple[int, ...]) -> bool:
        length = max(len(current), len(minimum))
        current_pad = list(current) + [0] * (length - len(current))
        minimum_pad = list(minimum) + [0] * (length - len(minimum))
        return current_pad < minimum_pad

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
