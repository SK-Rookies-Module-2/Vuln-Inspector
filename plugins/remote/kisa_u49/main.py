"""Remote plugin for KISA U-49 DNS version checks."""

from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
import subprocess
from typing import List, Optional, Tuple

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_NAMED_COMMAND = "named -v"

NAMED_VERSION_RE = re.compile(r"\b(?:named|BIND)\s+([0-9][0-9A-Za-z.\-]+)\b", re.IGNORECASE)
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


class DnsServiceVersionCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        named_command = str(self.context.config.get("named_command") or DEFAULT_NAMED_COMMAND).strip()
        if not named_command:
            raise PluginConfigError("named_command must be a non-empty string")

        min_named_version = self.context.config.get("min_named_version")
        report_unknown = bool(self.context.config.get("report_unknown", True))
        max_results = self._to_positive_int(
            self.context.config.get("max_results", 50),
            "max_results",
        )

        client, host = self._get_ssh_client()
        result = self._run_command(named_command, client, host)
        if result.lines is None:
            if _is_command_missing(result.error):
                return self.results
            self._add_unavailable(os_type, named_command, result)
            return self.results

        version = self._extract_version(result.lines)
        status = "unknown"
        if version and min_named_version:
            current = self._normalize_version(version)
            minimum = self._normalize_version(min_named_version)
            if current is None or minimum is None:
                status = "unknown"
            elif self._is_version_lower(current, minimum):
                status = "outdated"
            else:
                status = "ok"
        elif version:
            status = "unknown"

        evidence = {
            "os_type": os_type,
            "config_path": {"named_command": named_command},
            "detected_value": {
                "version": version,
                "min_version": min_named_version,
                "lines": result.lines[:5],
            },
        }
        if host:
            evidence["host"] = host

        if status == "ok":
            return self.results

        if status == "outdated":
            self.add_finding(
                vuln_id="KISA-U-49",
                title=f"{self._format_os(os_type)} DNS 서비스 구버전 사용",
                severity="High",
                evidence=evidence,
                tags=["KISA:U-49"],
                description="BIND(named) 버전이 기준보다 낮습니다.",
                solution="BIND(named)를 최신 보안 패치 버전으로 업데이트하세요.",
            )
            return self.results

        if report_unknown:
            self.add_finding(
                vuln_id="KISA-U-49",
                title=f"{self._format_os(os_type)} DNS 서비스 버전 확인 필요",
                severity="Info",
                evidence=evidence,
                tags=["KISA:U-49"],
                description="DNS 서비스 버전은 확인되었으나 기준 버전 정보가 없습니다.",
                solution="벤더 권고 최신 버전과 비교해 구버전 여부를 확인하세요.",
            )
        return self.results

    def _extract_version(self, lines: List[str]) -> Optional[str]:
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue
            match = NAMED_VERSION_RE.search(line)
            if match:
                return match.group(1)
            generic = GENERIC_VERSION_RE.search(line)
            if generic:
                return generic.group(1)
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

    def _add_unavailable(self, os_type: str, command: str, result: CommandResult) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": {"named_command": command},
            "mode": result.mode,
        }
        if result.host:
            evidence["host"] = result.host
        if result.error:
            evidence["error"] = result.error
        self.add_finding(
            vuln_id="KISA-U-49",
            title=f"{self._format_os(os_type)} DNS 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-49"],
            description="named 버전을 확인할 수 없습니다.",
            solution="대상 접근 권한과 명령 실행 권한을 확인하세요.",
        )

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
