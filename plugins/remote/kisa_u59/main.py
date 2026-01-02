"""Remote plugin for KISA U-59 SNMP version checks."""

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
DEFAULT_SNMP_CONF_PATHS = ("/etc/snmp/snmpd.conf",)
DEFAULT_COMMUNITY_KEYWORDS = (
    "rocommunity",
    "rwcommunity",
    "rocommunity6",
    "rwcommunity6",
    "com2sec",
    "com2sec6",
)
DEFAULT_PROCESS_COMMAND = "ps -ef"
DEFAULT_PROCESS_PATTERN = "snmpd"
DEFAULT_PROCESS_VERSION_PATTERN = "v1|v2c"


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
    return line.strip()


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


def _find_config_issues(
    lines: Sequence[str],
    community_keywords: Sequence[str],
    path: Path,
) -> List[Dict[str, str]]:
    issues = []
    keywords = [keyword.strip().lower() for keyword in community_keywords if keyword.strip()]
    for raw_line in lines:
        line = _strip_comment(raw_line)
        if not line:
            continue
        lower = line.lower()
        for keyword in keywords:
            if re.match(rf"^{re.escape(keyword)}\b", lower):
                issues.append(
                    {
                        "source": "config",
                        "path": str(path),
                        "issue": "community_directive",
                        "keyword": keyword,
                        "line": raw_line.strip(),
                    }
                )
                break
        if lower.startswith("group "):
            tokens = re.split(r"\s+", lower)
            if "v1" in tokens or "v2c" in tokens:
                issues.append(
                    {
                        "source": "config",
                        "path": str(path),
                        "issue": "group_v1_v2c",
                        "line": raw_line.strip(),
                    }
                )
    return issues


class SnmpVersionCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        snmp_conf_paths = _normalize_list(
            self.context.config.get("snmp_conf_paths"),
            "snmp_conf_paths",
        ) or list(DEFAULT_SNMP_CONF_PATHS)
        snmp_conf_paths = [path.strip() for path in snmp_conf_paths if path.strip()]
        if not snmp_conf_paths:
            raise PluginConfigError("snmp_conf_paths must include at least one path")

        community_keywords = _normalize_list(
            self.context.config.get("community_keywords"),
            "community_keywords",
        ) or list(DEFAULT_COMMUNITY_KEYWORDS)
        if not community_keywords:
            raise PluginConfigError("community_keywords must include at least one keyword")

        check_process = bool(self.context.config.get("check_process", True))
        process_command = str(
            self.context.config.get("process_command") or DEFAULT_PROCESS_COMMAND
        ).strip()
        process_pattern = str(
            self.context.config.get("process_pattern") or DEFAULT_PROCESS_PATTERN
        ).strip()
        process_version_pattern = str(
            self.context.config.get("process_version_pattern") or DEFAULT_PROCESS_VERSION_PATTERN
        ).strip()

        if check_process and not process_command:
            raise PluginConfigError("process_command must be a non-empty string")
        if check_process and not process_pattern:
            raise PluginConfigError("process_pattern must be a non-empty string")
        if check_process and not process_version_pattern:
            raise PluginConfigError("process_version_pattern must be a non-empty string")

        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        client, host = self._get_ssh_client()

        issues: List[Dict[str, object]] = []
        errors: List[Dict[str, str]] = []
        missing_files: List[str] = []
        modes: Dict[str, str] = {}
        checked_files = 0
        config_present = False

        for raw_path in snmp_conf_paths:
            path = Path(raw_path)
            result = self._read_config_lines(path, client, host)
            modes[str(path)] = result.mode
            if result.host:
                host = host or result.host
            if result.lines is None:
                if result.missing:
                    missing_files.append(str(path))
                    checked_files += 1
                else:
                    errors.append(
                        {
                            "source": "config",
                            "path": str(path),
                            "mode": result.mode,
                            "error": result.error or "Read failed",
                        }
                    )
                continue

            checked_files += 1
            config_present = True
            issues.extend(_find_config_issues(result.lines, community_keywords, path))

        snmp_process_lines: List[str] = []
        if check_process:
            result = self._run_command(process_command, client, host)
            modes["process"] = result.mode
            if result.host:
                host = host or result.host
            if result.lines is None:
                errors.append(
                    {
                        "source": "process",
                        "command": process_command,
                        "mode": result.mode,
                        "error": result.error or "Command failed",
                    }
                )
            else:
                try:
                    process_regex = re.compile(process_pattern, re.IGNORECASE)
                    version_regex = re.compile(process_version_pattern, re.IGNORECASE)
                except re.error as exc:
                    raise PluginConfigError(f"process regex error: {exc}") from exc

                snmp_process_lines = _find_process_lines(result.lines, process_regex)
                for line in snmp_process_lines:
                    if version_regex.search(line):
                        issues.append(
                            {
                                "source": "process",
                                "issue": "process_version_v1_v2c",
                                "line": line,
                            }
                        )

        if not issues:
            if snmp_process_lines and not config_present:
                self._add_unavailable(os_type, snmp_conf_paths, errors, snmp_process_lines, host)
                return self.results
            if not config_present and errors and not snmp_process_lines:
                self._add_unavailable(os_type, snmp_conf_paths, errors, snmp_process_lines, host)
            return self.results

        evidence = {
            "os_type": os_type,
            "config_path": {
                "snmp_conf_paths": snmp_conf_paths,
                "process_command": process_command if check_process else None,
                "process_pattern": process_pattern if check_process else None,
            },
            "mode": self._merge_modes(modes),
            "detected_value": issues[:max_results],
            "count": len(issues),
            "checked_files": checked_files,
        }
        if host:
            evidence["host"] = host
        if missing_files:
            evidence["missing_files"] = missing_files
        if errors:
            evidence["partial_errors"] = errors[:max_results]

        self.add_finding(
            vuln_id="KISA-U-59",
            title=f"{self._format_os(os_type)} SNMP v1/v2c 사용",
            severity="High",
            evidence=evidence,
            tags=["KISA:U-59"],
            description="SNMP v1/v2c 설정이 발견되었습니다.",
            solution="SNMP v3 사용으로 전환하고 v1/v2c 설정을 제거하세요.",
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
        config_paths: Sequence[str],
        errors: List[Dict[str, str]],
        process_lines: Sequence[str],
        host: Optional[str],
    ) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": {"snmp_conf_paths": list(config_paths)},
            "mode": self._merge_modes(
                {
                    str(idx): err.get("mode", "unknown")
                    for idx, err in enumerate(errors)
                    if err.get("mode")
                }
            ),
        }
        if host:
            evidence["host"] = host
        if errors:
            evidence["errors"] = errors
        if process_lines:
            evidence["snmp_processes"] = list(process_lines)

        self.add_finding(
            vuln_id="KISA-U-59",
            title=f"{self._format_os(os_type)} SNMP 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-59"],
            description="SNMP 설정 또는 프로세스를 확인할 수 없습니다.",
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
