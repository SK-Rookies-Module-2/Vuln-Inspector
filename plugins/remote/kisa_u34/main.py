"""Remote plugin for KISA U-34 finger service disable checks."""

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
DEFAULT_INETD_PATH = "/etc/inetd.conf"
DEFAULT_XINETD_FINGER_PATH = "/etc/xinetd.d/finger"
DEFAULT_PROCESS_COMMAND = "ps -ef"
DEFAULT_NETSTAT_COMMAND = "netstat -an"
DEFAULT_FINGER_PORT = 79

FINGER_PROCESS_PATTERN = re.compile(r"\b(finger|fingerd)\b", re.IGNORECASE)


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


def _find_inetd_finger(lines: Sequence[str]) -> Optional[str]:
    for raw_line in lines:
        line = _strip_comment(raw_line)
        if not line:
            continue
        parts = line.split()
        if not parts:
            continue
        service = parts[0].lower()
        if service.startswith("finger"):
            return raw_line.strip()
    return None


def _parse_xinetd_disable(lines: Sequence[str]) -> Optional[str]:
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("disable"):
            _, sep, value = line.partition("=")
            if sep:
                return value.strip().lower()
            parts = line.split()
            if len(parts) >= 2:
                return parts[1].strip().lower()
    return None


def _find_finger_processes(lines: Sequence[str]) -> List[str]:
    matches = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if "grep" in lowered and "finger" in lowered:
            continue
        if FINGER_PROCESS_PATTERN.search(line):
            matches.append(raw_line.strip())
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


class FingerServiceDisableCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        inetd_conf_path = Path(self.context.config.get("inetd_conf_path") or DEFAULT_INETD_PATH)
        xinetd_finger_path = Path(
            self.context.config.get("xinetd_finger_path") or DEFAULT_XINETD_FINGER_PATH
        )
        check_inetd = bool(self.context.config.get("check_inetd", True))
        check_xinetd = bool(self.context.config.get("check_xinetd", True))
        check_process = bool(self.context.config.get("check_process", True))
        check_port = bool(self.context.config.get("check_port", True))
        process_command = str(self.context.config.get("process_command") or DEFAULT_PROCESS_COMMAND).strip()
        netstat_command = str(self.context.config.get("netstat_command") or DEFAULT_NETSTAT_COMMAND).strip()
        finger_port = self._to_positive_int(
            self.context.config.get("finger_port", DEFAULT_FINGER_PORT),
            "finger_port",
        )
        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        if check_process and not process_command:
            raise PluginConfigError("process_command must be a non-empty string")
        if check_port and not netstat_command:
            raise PluginConfigError("netstat_command must be a non-empty string")

        client, host = self._get_ssh_client()

        issues = []
        errors = []
        checked_sources = []
        missing_files: List[str] = []
        modes: Dict[str, Optional[str]] = {}

        if check_inetd:
            result = self._read_config_lines(inetd_conf_path, client, host)
            modes["inetd"] = result.mode
            if result.lines is None:
                if result.missing:
                    missing_files.append(str(inetd_conf_path))
                    checked_sources.append("inetd_conf")
                else:
                    errors.append(
                        {
                            "source": "inetd_conf",
                            "path": str(inetd_conf_path),
                            "error": result.error or "Read failed",
                        }
                    )
            else:
                checked_sources.append("inetd_conf")
                line = _find_inetd_finger(result.lines)
                if line:
                    issues.append(
                        {
                            "source": "inetd_conf",
                            "path": str(inetd_conf_path),
                            "line": line,
                            "issue": "finger_enabled",
                        }
                    )

        if check_xinetd:
            result = self._read_config_lines(xinetd_finger_path, client, host)
            modes["xinetd"] = result.mode
            if result.lines is None:
                if result.missing:
                    missing_files.append(str(xinetd_finger_path))
                    checked_sources.append("xinetd_finger")
                else:
                    errors.append(
                        {
                            "source": "xinetd_finger",
                            "path": str(xinetd_finger_path),
                            "error": result.error or "Read failed",
                        }
                    )
            else:
                checked_sources.append("xinetd_finger")
                disable_value = _parse_xinetd_disable(result.lines)
                if disable_value != "yes":
                    issues.append(
                        {
                            "source": "xinetd_finger",
                            "path": str(xinetd_finger_path),
                            "detected_value": disable_value or "missing",
                            "issue": "disable_not_yes",
                        }
                    )

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
                for line in _find_finger_processes(result.lines):
                    issues.append(
                        {
                            "source": "process",
                            "command": process_command,
                            "line": line,
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
                line = _find_listening_port(result.lines, finger_port)
                if line:
                    issues.append(
                        {
                            "source": "port",
                            "command": netstat_command,
                            "port": finger_port,
                            "line": line,
                            "issue": "port_listening",
                        }
                    )

        if not issues:
            if not checked_sources and errors:
                self._add_unavailable(
                    os_type,
                    inetd_conf_path,
                    xinetd_finger_path,
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
                "inetd_conf_path": str(inetd_conf_path),
                "xinetd_finger_path": str(xinetd_finger_path),
                "process_command": process_command,
                "netstat_command": netstat_command,
            },
            "mode": self._merge_modes(modes),
            "detected_value": limited,
            "count": len(issues),
            "checked_sources": checked_sources,
        }
        if host:
            evidence["host"] = host
        if missing_files:
            evidence["missing_files"] = missing_files
        if errors:
            evidence["partial_errors"] = errors[:max_results]

        self.add_finding(
            vuln_id="KISA-U-34",
            title=f"{self._format_os(os_type)} Finger 서비스 활성화",
            severity="High",
            evidence=evidence,
            tags=["KISA:U-34"],
            description="Finger 서비스가 활성화되어 있어 사용자 정보 노출 위험이 있습니다.",
            solution="inetd/xinetd 설정에서 finger 서비스를 비활성화하고 관련 프로세스를 종료하세요.",
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
        inetd_conf_path: Path,
        xinetd_finger_path: Path,
        process_command: str,
        netstat_command: str,
        errors: List[Dict[str, str]],
        mode: Optional[object],
        host: Optional[str],
    ) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": {
                "inetd_conf_path": str(inetd_conf_path),
                "xinetd_finger_path": str(xinetd_finger_path),
                "process_command": process_command,
                "netstat_command": netstat_command,
            },
            "mode": mode,
            "partial_errors": errors,
        }
        if host:
            evidence["host"] = host
        self.add_finding(
            vuln_id="KISA-U-34",
            title=f"{self._format_os(os_type)} Finger 서비스 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-34"],
            description="Finger 서비스 상태를 확인할 수 없습니다.",
            solution="대상 접근 권한과 설정 파일/명령 실행 권한을 확인하세요.",
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
