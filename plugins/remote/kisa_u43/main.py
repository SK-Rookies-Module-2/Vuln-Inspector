"""Remote plugin for KISA U-43 NIS/NIS+ checks."""

from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
import subprocess
from typing import Dict, List, Optional, Tuple

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_PROCESS_COMMAND = "ps -ef"
DEFAULT_PROCESS_PATTERN = "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"
DEFAULT_NIS_PLUS_PATTERN = "rpc.nisd|nisplus"


@dataclass
class CommandResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    command: Optional[str] = None


def _find_processes(lines: List[str], pattern: re.Pattern[str]) -> List[str]:
    matches = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if "grep" in lowered and pattern.search(line):
            continue
        if pattern.search(line):
            matches.append(raw_line.strip())
    return matches


class NisServiceCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        process_command = str(
            self.context.config.get("process_command") or DEFAULT_PROCESS_COMMAND
        ).strip()
        if not process_command:
            raise PluginConfigError("process_command must be a non-empty string")

        process_pattern = str(
            self.context.config.get("process_pattern") or DEFAULT_PROCESS_PATTERN
        ).strip()
        if not process_pattern:
            raise PluginConfigError("process_pattern must be a non-empty string")

        check_nis_plus = bool(self.context.config.get("check_nis_plus", False))
        nis_plus_pattern = str(
            self.context.config.get("nis_plus_pattern") or DEFAULT_NIS_PLUS_PATTERN
        ).strip()
        if check_nis_plus and not nis_plus_pattern:
            raise PluginConfigError("nis_plus_pattern must be a non-empty string")

        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        try:
            nis_regex = re.compile(process_pattern, re.IGNORECASE)
        except re.error as exc:
            raise PluginConfigError(f"process_pattern regex error: {exc}") from exc

        nis_plus_regex = None
        if check_nis_plus:
            try:
                nis_plus_regex = re.compile(nis_plus_pattern, re.IGNORECASE)
            except re.error as exc:
                raise PluginConfigError(f"nis_plus_pattern regex error: {exc}") from exc

        client, host = self._get_ssh_client()
        result = self._run_command(process_command, client, host)
        if result.lines is None:
            self._add_unavailable(os_type, process_command, result)
            return self.results

        nis_matches = _find_processes(result.lines, nis_regex)
        if not nis_matches:
            return self.results

        evidence = {
            "os_type": os_type,
            "config_path": {
                "process_command": process_command,
                "process_pattern": process_pattern,
                "nis_plus_pattern": nis_plus_pattern if check_nis_plus else None,
            },
            "mode": result.mode,
            "detected_value": nis_matches[:max_results],
            "count": len(nis_matches),
        }
        if host:
            evidence["host"] = host
        if nis_plus_regex:
            nis_plus_matches = _find_processes(result.lines, nis_plus_regex)
            if nis_plus_matches:
                evidence["nis_plus_detected"] = nis_plus_matches[:max_results]

        self.add_finding(
            vuln_id="KISA-U-43",
            title=f"{self._format_os(os_type)} NIS service enabled",
            severity="High",
            evidence=evidence,
            tags=["KISA:U-43"],
            description="NIS related daemons are running.",
            solution="Disable unnecessary NIS services or migrate to a safer alternative.",
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
            "config_path": {"process_command": command},
            "mode": result.mode,
        }
        if result.host:
            evidence["host"] = result.host
        if result.error:
            evidence["error"] = result.error

        self.add_finding(
            vuln_id="KISA-U-43",
            title=f"{self._format_os(os_type)} NIS service check unavailable",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-43"],
            description="Unable to verify NIS service processes.",
            solution="Check target access and command execution permissions.",
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
