"""Remote plugin for KISA U-52 telnet disable checks."""

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
from plugins.remote.utils.text import strip_comments

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_INETD_CONF_PATH = "/etc/inetd.conf"
DEFAULT_XINETD_DIR = "/etc/xinetd.d"
DEFAULT_XINETD_SERVICES = ("telnet",)
DEFAULT_SYSTEMD_SOCKET_COMMAND = "systemctl list-units --type=socket"


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


def _tokenize(text: str) -> List[str]:
    return [token for token in re.split(r"[^a-zA-Z0-9]+", text.lower()) if token]


def _line_has_service(line: str, services: Sequence[str]) -> bool:
    tokens = _tokenize(line)
    for token in tokens:
        for service in services:
            if token == service or token.startswith(service):
                return True
    return False


def _parse_disable_setting(lines: List[str]) -> Tuple[Optional[str], Optional[str]]:
    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith("disable"):
            if "=" in stripped:
                _, value = stripped.split("=", 1)
                return value.strip().lower(), raw_line
            parts = stripped.split()
            if len(parts) >= 2:
                return parts[1].strip().lower(), raw_line
            return "", raw_line
    return None, None


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


class TelnetDisableCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        inetd_conf_path = Path(
            self.context.config.get("inetd_conf_path") or DEFAULT_INETD_CONF_PATH
        )
        xinetd_dir = Path(self.context.config.get("xinetd_dir") or DEFAULT_XINETD_DIR)
        xinetd_services = _normalize_list(
            self.context.config.get("xinetd_services"),
            "xinetd_services",
        ) or list(DEFAULT_XINETD_SERVICES)
        xinetd_services = [service.strip().lower() for service in xinetd_services if service.strip()]

        check_inetd = bool(self.context.config.get("check_inetd", True))
        check_xinetd = bool(self.context.config.get("check_xinetd", True))
        check_systemd = bool(self.context.config.get("check_systemd", True))
        systemd_socket_command = str(
            self.context.config.get("systemd_socket_command") or DEFAULT_SYSTEMD_SOCKET_COMMAND
        ).strip()

        if check_xinetd and not xinetd_services:
            raise PluginConfigError("xinetd_services must include at least one service")
        if check_systemd and not systemd_socket_command:
            raise PluginConfigError("systemd_socket_command must be a non-empty string")

        max_results = self._to_positive_int(self.context.config.get("max_results", 200), "max_results")

        issues: List[Dict[str, str]] = []
        errors: List[object] = []
        modes: Dict[str, str] = {}
        checked = 0
        host = None

        if check_inetd:
            result = self._read_lines(inetd_conf_path)
            modes["inetd_conf"] = result.mode
            if result.host:
                host = host or result.host
            if result.lines is None:
                if result.missing:
                    checked += 1
                else:
                    errors.append(result)
            else:
                checked += 1
                for line in result.lines:
                    if _line_has_service(line, xinetd_services):
                        issues.append(
                            {
                                "source": "inetd",
                                "path": str(inetd_conf_path),
                                "line": line,
                            }
                        )

        if check_xinetd:
            for service in xinetd_services:
                path = xinetd_dir / service
                result = self._read_lines(path)
                modes[f"xinetd:{service}"] = result.mode
                if result.host:
                    host = host or result.host
                if result.lines is None:
                    if result.missing:
                        checked += 1
                    else:
                        errors.append(result)
                    continue
                checked += 1
                value, raw_line = _parse_disable_setting(result.lines)
                if value is None:
                    issues.append(
                        {
                            "source": "xinetd",
                            "path": str(path),
                            "service": service,
                            "issue": "disable_missing",
                        }
                    )
                elif value not in ("yes", "true", "1"):
                    item = {
                        "source": "xinetd",
                        "path": str(path),
                        "service": service,
                        "issue": "disable_not_yes",
                        "value": value,
                    }
                    if raw_line:
                        item["line"] = raw_line
                    issues.append(item)

        if check_systemd:
            result = self._run_command(systemd_socket_command)
            modes["systemd_socket"] = result.mode
            if result.host:
                host = host or result.host
            if result.lines is None:
                errors.append(result)
            else:
                checked += 1
                for line in result.lines:
                    stripped = line.strip()
                    if not stripped or stripped.lower().startswith("unit "):
                        continue
                    if _line_has_service(stripped, xinetd_services):
                        issues.append(
                            {
                                "source": "systemd",
                                "command": systemd_socket_command,
                                "line": stripped,
                            }
                        )

        if issues:
            limited = issues[:max_results]
            evidence = {
                "os_type": os_type,
                "config_path": {
                    "inetd_conf_path": str(inetd_conf_path),
                    "xinetd_dir": str(xinetd_dir),
                    "xinetd_services": xinetd_services,
                    "systemd_socket_command": systemd_socket_command,
                },
                "mode": self._merge_modes(modes),
                "detected_value": limited,
                "count": len(issues),
            }
            if host:
                evidence["host"] = host
            if errors:
                evidence["partial_errors"] = [getattr(err, "error", None) for err in errors if getattr(err, "error", None)]

            self.add_finding(
                vuln_id="KISA-U-52",
                title=f"{self._format_os(os_type)} Telnet 서비스 활성화",
                severity="Medium",
                evidence=evidence,
                tags=["KISA:U-52"],
                description="Telnet 서비스가 비활성화되지 않았습니다.",
                solution="inetd/xinetd/systemd에서 Telnet 서비스를 비활성화하세요.",
            )
            return self.results

        if checked == 0 and errors:
            self._add_unavailable(
                os_type,
                {
                    "inetd_conf_path": str(inetd_conf_path),
                    "xinetd_dir": str(xinetd_dir),
                    "xinetd_services": xinetd_services,
                    "systemd_socket_command": systemd_socket_command,
                },
                errors,
            )

        return self.results

    def _read_lines(self, path: Path) -> ReadResult:
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
                quoted = shlex.quote(str(path))
                result = client.run(f"cat {quoted}")
            except AdapterError as exc:
                return ReadResult(None, "remote", str(exc), host, path, False)
            if result.exit_code != 0:
                err = (result.stderr or result.stdout or "").strip()
                if _is_missing_error(err):
                    return ReadResult(None, "remote", err or "File not found", host, path, True)
                return ReadResult(None, "remote", err or f"SSH exit code {result.exit_code}", host, path)
            raw_lines = result.stdout.splitlines()
            return ReadResult(strip_comments(raw_lines), "remote", None, host, path)

        if allow_local:
            if not path.exists():
                return ReadResult(None, "local", "File not found", None, path, True)
            try:
                raw_lines = path.read_text().splitlines()
            except OSError as exc:
                return ReadResult(None, "local", str(exc), None, path)
            return ReadResult(strip_comments(raw_lines), "local", None, None, path)

        return ReadResult(None, "remote", "Missing SSH credentials", host, path)

    def _run_command(self, command: str) -> CommandResult:
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
                    timeout=60,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                return CommandResult(None, "local", str(exc), None, command)
            if result.returncode != 0:
                error = result.stderr.strip() or f"Command exit code {result.returncode}"
                return CommandResult(None, "local", error, None, command)
            return CommandResult(result.stdout.splitlines(), "local", None, None, command)

        return CommandResult(None, "remote", "Missing SSH credentials", host, command)

    def _add_unavailable(self, os_type: str, config_path: Dict, errors: List[object]) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": config_path,
            "mode": self._merge_modes(
                {
                    str(idx): getattr(err, "mode", None)
                    for idx, err in enumerate(errors)
                    if getattr(err, "mode", None)
                }
            ),
        }
        host = next((getattr(err, "host", None) for err in errors if getattr(err, "host", None)), None)
        if host:
            evidence["host"] = host
        error_list = [getattr(err, "error", None) for err in errors if getattr(err, "error", None)]
        if error_list:
            evidence["error"] = error_list[0]
            evidence["errors"] = error_list

        self.add_finding(
            vuln_id="KISA-U-52",
            title=f"{self._format_os(os_type)} Telnet 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-52"],
            description="Telnet 서비스 상태를 확인할 수 없습니다.",
            solution="대상 접근 권한과 파일 경로/명령 실행 권한을 확인하세요.",
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
