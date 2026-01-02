"""Remote plugin for KISA U-65 NTP time sync checks."""

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
DEFAULT_NTP_CONF_PATHS = ("/etc/ntp.conf",)
DEFAULT_CHRONY_CONF_PATHS = ("/etc/chrony.conf", "/etc/chrony/chrony.conf")
DEFAULT_PROCESS_COMMAND = "ps -ef"
DEFAULT_PROCESS_PATTERN = "ntpd|chronyd|systemd-timesyncd"
DEFAULT_INSECURE_SOURCES = ("127.0.0.1", "127.127.1.0", "localhost", "::1")

NTP_DIRECTIVES = {"server", "pool", "peer"}


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


def _is_missing_error(error: Optional[str]) -> bool:
    if not error:
        return False
    lowered = error.lower()
    return (
        "no such file" in lowered
        or "not found" in lowered
        or "cannot access" in lowered
        or "cannot stat" in lowered
    )


def _find_process_lines(lines: List[str], pattern: re.Pattern[str]) -> List[str]:
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


class NtpTimeSyncCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        ntp_conf_paths = _normalize_list(
            self.context.config.get("ntp_conf_paths"),
            "ntp_conf_paths",
        ) or list(DEFAULT_NTP_CONF_PATHS)
        chrony_conf_paths = _normalize_list(
            self.context.config.get("chrony_conf_paths"),
            "chrony_conf_paths",
        ) or list(DEFAULT_CHRONY_CONF_PATHS)
        process_command = str(
            self.context.config.get("process_command") or DEFAULT_PROCESS_COMMAND
        ).strip()
        process_pattern = str(
            self.context.config.get("process_pattern") or DEFAULT_PROCESS_PATTERN
        ).strip()
        insecure_sources = _normalize_list(
            self.context.config.get("insecure_sources"),
            "insecure_sources",
        ) or list(DEFAULT_INSECURE_SOURCES)
        insecure_sources = [item.strip().lower() for item in insecure_sources if item.strip()]
        require_process = bool(self.context.config.get("require_process", True))
        require_time_servers = bool(self.context.config.get("require_time_servers", True))
        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        if not process_command:
            raise PluginConfigError("process_command must be a non-empty string")
        if not process_pattern:
            raise PluginConfigError("process_pattern must be a non-empty string")

        try:
            regex = re.compile(process_pattern, re.IGNORECASE)
        except re.error as exc:
            raise PluginConfigError(f"process_pattern regex error: {exc}") from exc

        client, host = self._get_ssh_client()

        errors: List[Dict[str, str]] = []
        modes: Dict[str, str] = {}
        checked_files = 0
        missing_files = 0
        servers: List[Dict[str, str]] = []

        process_result = self._run_command(process_command, client, host)
        process_lines: List[str] = []
        if process_result.lines is None:
            if process_result.error:
                errors.append({"command": process_command, "error": process_result.error})
        else:
            process_lines = _find_process_lines(process_result.lines, regex)

        for path in [*ntp_conf_paths, *chrony_conf_paths]:
            if not path:
                continue
            result = self._read_config_lines(Path(path), client, host)
            if result.path:
                modes[str(result.path)] = result.mode
            if result.missing:
                missing_files += 1
                continue
            if result.lines is None:
                if result.error:
                    errors.append({"path": str(result.path), "error": result.error})
                continue
            checked_files += 1
            servers.extend(self._parse_servers(result.lines, str(result.path)))

        issues = []
        if require_process and not process_lines:
            issues.append({"issue": "process_missing", "detail": process_pattern})

        if require_time_servers:
            if not servers:
                issues.append({"issue": "time_server_missing"})
            else:
                local_only = all(self._is_insecure_source(item["server"], insecure_sources) for item in servers)
                if local_only:
                    issues.append({"issue": "time_server_local_only"})

        if not issues:
            return self.results

        if not servers and not process_lines and errors:
            self._add_unavailable(
                os_type,
                {
                    "ntp_conf_paths": ntp_conf_paths,
                    "chrony_conf_paths": chrony_conf_paths,
                    "process_command": process_command,
                },
                errors,
                host,
            )
            return self.results

        evidence = {
            "os_type": os_type,
            "config_path": {
                "ntp_conf_paths": ntp_conf_paths,
                "chrony_conf_paths": chrony_conf_paths,
                "process_command": process_command,
            },
            "mode": self._merge_modes(modes),
            "detected_value": {
                "servers": servers[:max_results] or None,
                "processes": process_lines[:max_results] or None,
                "issues": issues,
            },
            "checked_files": checked_files,
            "missing_files": missing_files,
            "policy": {
                "process_pattern": process_pattern,
                "insecure_sources": insecure_sources,
                "require_process": require_process,
                "require_time_servers": require_time_servers,
            },
        }
        if host:
            evidence["host"] = host
        if errors:
            evidence["partial_errors"] = errors[:max_results]

        self.add_finding(
            vuln_id="KISA-U-65",
            title=f"{self._format_os(os_type)} 시각 동기화 설정 미흡",
            severity="Medium",
            evidence=evidence,
            tags=["KISA:U-65"],
            description="NTP/chrony 설정 또는 데몬 실행 상태가 기준을 만족하지 않습니다.",
            solution="NTP/chrony 데몬을 실행하고 시간 서버를 설정하세요.",
        )
        return self.results

    def _parse_servers(self, lines: Sequence[str], path: str) -> List[Dict[str, str]]:
        servers: List[Dict[str, str]] = []
        for raw_line in lines:
            line = _strip_comment(raw_line)
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            directive = parts[0].lower()
            if directive not in NTP_DIRECTIVES:
                continue
            server = parts[1]
            servers.append(
                {
                    "path": path,
                    "directive": directive,
                    "server": server,
                    "line": raw_line.strip(),
                }
            )
        return servers

    def _is_insecure_source(self, value: str, insecure_sources: Sequence[str]) -> bool:
        normalized = value.strip().lower()
        if normalized in insecure_sources:
            return True
        if normalized.startswith("127.127."):
            return True
        return False

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
                    return ReadResult(None, "remote", error, host, config_path, True)
                return ReadResult(None, "remote", error, host, config_path)
            return ReadResult(result.stdout.splitlines(), "remote", None, host, config_path)

        if allow_local:
            if not config_path.exists():
                return ReadResult(None, "local", "File not found", None, config_path, True)
            try:
                raw_lines = config_path.read_text().splitlines()
            except OSError as exc:
                return ReadResult(None, "local", str(exc), None, config_path)
            return ReadResult(raw_lines, "local", None, None, config_path)

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

    def _add_unavailable(self, os_type: str, config_path, errors, host: Optional[str]) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": config_path,
        }
        if host:
            evidence["host"] = host
        if errors:
            evidence["error"] = errors[0] if len(errors) == 1 else errors
        self.add_finding(
            vuln_id="KISA-U-65",
            title=f"{self._format_os(os_type)} 시각 동기화 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-65"],
            description="NTP/chrony 설정 또는 프로세스를 확인할 수 없습니다.",
            solution="대상 접근 권한과 설정 파일 경로를 확인하세요.",
        )

    def _merge_modes(self, modes: Dict[str, str]):
        if not modes:
            return None
        unique = set(modes.values())
        if len(unique) == 1:
            return next(iter(unique))
        return modes

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
