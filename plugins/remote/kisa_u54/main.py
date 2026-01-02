"""Remote plugin for KISA U-54 plain FTP service checks."""

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
DEFAULT_PROCESS_COMMAND = "ps -ef"
DEFAULT_NETSTAT_COMMAND = "netstat -an"
DEFAULT_FTP_PORT = 21


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


def _find_processes(lines: Sequence[str], names: Sequence[str]) -> List[Dict[str, str]]:
    patterns = [re.compile(rf"\\b{re.escape(name)}\\b", re.IGNORECASE) for name in names]
    matches = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if "grep" in lowered and any(name in lowered for name in names):
            continue
        for name, pattern in zip(names, patterns):
            if pattern.search(line):
                matches.append({"name": name, "line": raw_line.strip()})
                break
    return matches


def _find_listening_port(lines: Sequence[str], port: int) -> Optional[str]:
    token = f":{port}"
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        upper = line.upper()
        if "LISTEN" not in upper:
            continue
        if token in line:
            return raw_line.strip()
    return None


class PlainFtpDisableCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        check_process = bool(self.context.config.get("check_process", True))
        check_port = bool(self.context.config.get("check_port", True))
        if not check_process and not check_port:
            raise PluginConfigError("At least one of check_process or check_port must be true")

        process_command = str(self.context.config.get("process_command") or DEFAULT_PROCESS_COMMAND).strip()
        netstat_command = str(self.context.config.get("netstat_command") or DEFAULT_NETSTAT_COMMAND).strip()
        ftp_port = self._to_positive_int(
            self.context.config.get("ftp_port", DEFAULT_FTP_PORT),
            "ftp_port",
        )
        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        if check_process and not process_command:
            raise PluginConfigError("process_command must be a non-empty string")
        if check_port and not netstat_command:
            raise PluginConfigError("netstat_command must be a non-empty string")

        ftp_process_names = _normalize_list(
            self.context.config.get("ftp_process_names"),
            "ftp_process_names",
        ) or ["ftpd"]

        client, host = self._get_ssh_client()

        issues = []
        errors: List[Dict[str, str]] = []
        checked_sources = []
        modes: Dict[str, Optional[str]] = {}

        if check_process:
            result = self._run_command(process_command, client, host)
            modes["process"] = result.mode
            if result.lines is None:
                errors.append(
                    {
                        "source": "process",
                        "command": process_command,
                        "error": result.error or "Command failed",
                    }
                )
            else:
                checked_sources.append("process")
                for hit in _find_processes(result.lines, ftp_process_names):
                    issues.append(
                        {
                            "source": "process",
                            "name": hit["name"],
                            "line": hit["line"],
                            "issue": "process_running",
                        }
                    )

        if check_port:
            result = self._run_command(netstat_command, client, host)
            modes["port"] = result.mode
            if result.lines is None:
                errors.append(
                    {
                        "source": "port",
                        "command": netstat_command,
                        "error": result.error or "Command failed",
                    }
                )
            else:
                checked_sources.append("port")
                line = _find_listening_port(result.lines, ftp_port)
                if line:
                    issues.append(
                        {
                            "source": "port",
                            "port": ftp_port,
                            "line": line,
                            "issue": "port_listening",
                        }
                    )

        if not issues:
            if not checked_sources and errors:
                self._add_unavailable(
                    os_type,
                    process_command,
                    netstat_command,
                    errors,
                    self._merge_modes(modes),
                    host,
                )
            return self.results

        limited = issues[:max_results]
        evidence = {
            "os_type": os_type,
            "config_path": {
                "process_command": process_command,
                "netstat_command": netstat_command,
                "ftp_process_names": ftp_process_names,
                "ftp_port": ftp_port,
            },
            "mode": self._merge_modes(modes),
            "detected_value": limited,
            "count": len(issues),
            "checked_sources": checked_sources,
        }
        if host:
            evidence["host"] = host
        if errors:
            evidence["partial_errors"] = errors[:max_results]

        self.add_finding(
            vuln_id="KISA-U-54",
            title=f"{self._format_os(os_type)} FTP 서비스 활성화",
            severity="Medium",
            evidence=evidence,
            tags=["KISA:U-54"],
            description="암호화되지 않은 FTP 서비스가 활성화되어 있습니다.",
            solution="FTP 서비스를 중지하거나 SFTP 등 암호화 전송 방식으로 전환하세요.",
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

    def _add_unavailable(
        self,
        os_type: str,
        process_command: str,
        netstat_command: str,
        errors: List[Dict[str, str]],
        mode: Optional[object],
        host: Optional[str],
    ) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": {
                "process_command": process_command,
                "netstat_command": netstat_command,
            },
            "mode": mode,
            "partial_errors": errors,
        }
        if host:
            evidence["host"] = host
        self.add_finding(
            vuln_id="KISA-U-54",
            title=f"{self._format_os(os_type)} FTP 서비스 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-54"],
            description="FTP 서비스 상태를 확인할 수 없습니다.",
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
