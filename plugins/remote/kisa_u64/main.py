"""Remote plugin for KISA U-64 security patch level checks."""

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
DEFAULT_KERNEL_COMMAND = "uname -a"
DEFAULT_PACKAGE_COMMANDS = {
    "linux": ("rpm -qa",),
    "solaris": ("showrev -p",),
    "aix": ("oslevel -s",),
    "hpux": (),
}
VERSION_RE = re.compile(r"([0-9]+(?:\.[0-9]+){0,3})")


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


def _is_command_missing(error: Optional[str]) -> bool:
    if not error:
        return False
    lowered = error.lower()
    return "not found" in lowered or "command not found" in lowered


class SecurityPatchLevelCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        kernel_command = str(
            self.context.config.get("kernel_command") or DEFAULT_KERNEL_COMMAND
        ).strip()
        if not kernel_command:
            raise PluginConfigError("kernel_command must be a non-empty string")

        package_commands = _normalize_list(
            self.context.config.get("package_commands"),
            "package_commands",
        )
        if not package_commands:
            package_commands = list(DEFAULT_PACKAGE_COMMANDS.get(os_type, ()))
        package_commands = [cmd.strip() for cmd in package_commands if cmd.strip()]

        min_kernel_version = self.context.config.get("min_kernel_version")
        report_unknown = bool(self.context.config.get("report_unknown", True))
        max_lines = self._to_positive_int(
            self.context.config.get("max_lines_per_command", 200),
            "max_lines_per_command",
        )
        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        client, host = self._get_ssh_client()

        errors: List[Dict[str, str]] = []
        results: Dict[str, CommandResult] = {}

        kernel_result = self._run_command(kernel_command, client, host)
        results["kernel"] = kernel_result
        if kernel_result.lines is None and kernel_result.error and not _is_command_missing(
            kernel_result.error
        ):
            errors.append({"command": kernel_command, "error": kernel_result.error})

        package_results: List[CommandResult] = []
        for command in package_commands:
            result = self._run_command(command, client, host)
            package_results.append(result)
            if result.lines is None and result.error and not _is_command_missing(result.error):
                errors.append({"command": command, "error": result.error})

        any_output = bool(kernel_result.lines) or any(
            result.lines for result in package_results
        )
        if not any_output:
            if errors:
                self._add_unavailable(os_type, kernel_command, package_commands, errors, kernel_result, package_results)
            return self.results

        kernel_info = self._summarize_kernel(kernel_result, min_kernel_version, max_lines)
        package_info = [
            self._summarize_command(result, max_lines) for result in package_results
        ]
        package_info = package_info[:max_results]

        if kernel_info["status"] == "outdated":
            evidence = self._build_evidence(
                os_type,
                kernel_command,
                package_commands,
                kernel_result,
                package_results,
                kernel_info,
                package_info,
                errors,
            )
            self.add_finding(
                vuln_id="KISA-U-64",
                title=f"{self._format_os(os_type)} 보안 패치 미흡",
                severity="High",
                evidence=evidence,
                tags=["KISA:U-64"],
                description="커널 버전이 기준보다 낮습니다.",
                solution="벤더 권고 최신 보안 패치를 적용하세요.",
            )
            return self.results

        if report_unknown and (kernel_info["status"] != "ok" or package_info):
            evidence = self._build_evidence(
                os_type,
                kernel_command,
                package_commands,
                kernel_result,
                package_results,
                kernel_info,
                package_info,
                errors,
            )
            self.add_finding(
                vuln_id="KISA-U-64",
                title=f"{self._format_os(os_type)} 보안 패치 확인 필요",
                severity="Info",
                evidence=evidence,
                tags=["KISA:U-64"],
                description="수집된 버전 정보를 벤더 권고와 비교해야 합니다.",
                solution="커널/패키지 버전을 벤더 최신 권고 버전과 비교하세요.",
            )

        return self.results

    def _summarize_kernel(
        self,
        result: CommandResult,
        min_version: Optional[str],
        max_lines: int,
    ) -> Dict[str, object]:
        info: Dict[str, object] = {
            "command": result.command,
            "status": "unknown",
            "version": None,
            "min_version": min_version,
            "lines": self._limit_lines(result.lines, max_lines),
        }
        if result.lines is None:
            info["status"] = "missing"
            if result.error:
                info["error"] = result.error
            return info

        version = self._extract_version(result.lines)
        if version is None:
            return info

        info["version"] = version
        if not min_version:
            return info

        current = self._normalize_version(version)
        minimum = self._normalize_version(min_version)
        if current is None or minimum is None:
            return info

        if self._is_version_lower(current, minimum):
            info["status"] = "outdated"
            return info

        info["status"] = "ok"
        return info

    def _summarize_command(self, result: CommandResult, max_lines: int) -> Dict[str, object]:
        summary: Dict[str, object] = {
            "command": result.command,
            "line_count": 0,
            "lines": [],
            "mode": result.mode,
        }
        if result.lines is None:
            if result.error:
                summary["error"] = result.error
            return summary
        summary["line_count"] = len(result.lines)
        summary["lines"] = self._limit_lines(result.lines, max_lines)
        return summary

    def _limit_lines(self, lines: Optional[List[str]], max_lines: int) -> List[str]:
        if not lines:
            return []
        return [line for line in lines[:max_lines]]

    def _extract_version(self, lines: Sequence[str]) -> Optional[str]:
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue
            match = VERSION_RE.search(line)
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

    def _build_evidence(
        self,
        os_type: str,
        kernel_command: str,
        package_commands: List[str],
        kernel_result: CommandResult,
        package_results: Sequence[CommandResult],
        kernel_info: Dict[str, object],
        package_info: List[Dict[str, object]],
        errors: List[Dict[str, str]],
    ) -> Dict[str, object]:
        evidence = {
            "os_type": os_type,
            "config_path": {
                "kernel_command": kernel_command,
                "package_commands": package_commands,
            },
            "mode": self._merge_modes(
                {
                    "kernel": kernel_result.mode,
                    **{str(idx): res.mode for idx, res in enumerate(package_results)},
                }
            ),
            "detected_value": {
                "kernel": kernel_info,
                "packages": package_info,
            },
            "count": (1 if kernel_info else 0) + len(package_info),
        }
        host = kernel_result.host or next(
            (res.host for res in package_results if res.host), None
        )
        if host:
            evidence["host"] = host
        if errors:
            evidence["partial_errors"] = errors
        return evidence

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

    def _add_unavailable(
        self,
        os_type: str,
        kernel_command: str,
        package_commands: Sequence[str],
        errors: List[Dict[str, str]],
        kernel_result: CommandResult,
        package_results: Sequence[CommandResult],
    ) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": {
                "kernel_command": kernel_command,
                "package_commands": list(package_commands),
            },
            "mode": self._merge_modes(
                {
                    "kernel": kernel_result.mode,
                    **{str(idx): res.mode for idx, res in enumerate(package_results)},
                }
            ),
        }
        host = kernel_result.host or next(
            (res.host for res in package_results if res.host), None
        )
        if host:
            evidence["host"] = host
        if errors:
            evidence["error"] = errors[0].get("error")
            evidence["errors"] = errors

        self.add_finding(
            vuln_id="KISA-U-64",
            title=f"{self._format_os(os_type)} 보안 패치 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-64"],
            description="패치 상태를 확인할 수 없습니다.",
            solution="대상 접근 권한과 명령 실행 권한을 확인하세요.",
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
