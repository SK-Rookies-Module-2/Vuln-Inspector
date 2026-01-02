"""Remote plugin for KISA U-14 PATH safety checks."""

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
DEFAULT_PROFILE_PATHS = ("/etc/profile",)
DEFAULT_PATH_COMMAND = "sh -lc 'echo $PATH'"

PATH_ASSIGN_RE = re.compile(r"^\s*(?:export\s+)?PATH\s*=\s*(.+)$", re.IGNORECASE)


@dataclass
class ReadResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None


@dataclass
class CommandResult:
    output: Optional[str]
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
    return line


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


def _is_missing_file_error(error: Optional[str]) -> bool:
    if not error:
        return False
    lowered = error.lower()
    return "no such file" in lowered or "not found" in lowered or "cannot access" in lowered


def _extract_path_values(lines: List[str]) -> List[Dict[str, str]]:
    values: List[Dict[str, str]] = []
    for raw_line in lines:
        line = _strip_comment(raw_line)
        if not line:
            continue
        match = PATH_ASSIGN_RE.match(line)
        if not match:
            continue
        value = match.group(1).strip()
        if ";" in value:
            value = value.split(";", 1)[0].strip()
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]
        values.append({"value": value, "line": raw_line.strip()})
    return values


def _detect_dot_entries(path_value: str, allow_trailing_dot: bool) -> List[Dict[str, object]]:
    entries = path_value.split(":")
    issues: List[Dict[str, object]] = []
    for index, entry in enumerate(entries):
        if entry not in ("", "."):
            continue
        is_last = index == len(entries) - 1
        if allow_trailing_dot and is_last and len(entries) > 1:
            continue
        issues.append(
            {
                "index": index,
                "entry": entry or ".",
                "position": "end" if is_last else "middle" if index > 0 else "start",
            }
        )
    if len(entries) == 1 and entries[0] in ("", "."):
        issues = [
            {
                "index": 0,
                "entry": entries[0] or ".",
                "position": "start",
            }
        ]
    return issues


class RootPathSafetyCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        path_command = str(self.context.config.get("path_command") or DEFAULT_PATH_COMMAND).strip()
        profile_paths = _normalize_list(
            self.context.config.get("profile_paths"),
            "profile_paths",
        ) or list(DEFAULT_PROFILE_PATHS)
        check_runtime = bool(self.context.config.get("check_runtime_path", True))
        check_profile = bool(self.context.config.get("check_profile_paths", True))
        allow_trailing_dot = bool(self.context.config.get("allow_trailing_dot", True))

        runtime_result = None
        if check_runtime:
            if not path_command:
                raise PluginConfigError("path_command must be a non-empty string")
            runtime_result = self._run_command(path_command)

        profile_results = []
        profile_errors = []
        if check_profile:
            profile_results, profile_errors = self._read_optional_files(profile_paths)

        if (not runtime_result or runtime_result.output is None) and not profile_results:
            self._add_unavailable(
                os_type,
                {"path_command": path_command, "profile_paths": profile_paths},
                [*(profile_errors or []), *( [self._to_read_result(runtime_result)] if runtime_result else [] )],
            )
            return self.results

        runtime_detail = {}
        runtime_issues = []
        if runtime_result and runtime_result.output is not None:
            path_value = runtime_result.output.strip().splitlines()[0] if runtime_result.output else ""
            runtime_issues = _detect_dot_entries(path_value, allow_trailing_dot)
            runtime_detail = {
                "path": path_value,
                "issues": runtime_issues,
                "command": path_command,
            }

        profile_detail = []
        profile_issues = []
        for result in profile_results:
            values = _extract_path_values(result.lines or [])
            for item in values:
                issues = _detect_dot_entries(item["value"], allow_trailing_dot)
                if issues:
                    profile_issues.extend(issues)
                profile_detail.append(
                    {
                        "path": str(result.path) if result.path else None,
                        "value": item["value"],
                        "line": item["line"],
                        "issues": issues,
                    }
                )

        if not runtime_issues and not profile_issues:
            return self.results

        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path(
                {
                    "path_command": path_command,
                    "profile_paths": profile_paths,
                }
            ),
            "mode": self._merge_modes(
                {
                    **({ "runtime": runtime_result.mode } if runtime_result else {}),
                    **{f"profile_{idx}": res.mode for idx, res in enumerate(profile_results)},
                }
            ),
            "detected_value": {
                "runtime": runtime_detail or None,
                "profile": profile_detail or None,
            },
            "source": self._format_source(runtime_issues, profile_issues),
        }
        line = self._first_issue_line(runtime_detail, profile_detail)
        if line:
            evidence["line"] = line
        host = self._first_host([*(profile_results or []), *( [self._to_read_result(runtime_result)] if runtime_result else [])])
        if host:
            evidence["host"] = host

        self.add_finding(
            vuln_id="KISA-U-14",
            title=f"{self._format_os(os_type)} PATH 안전 설정 미흡",
            severity="High",
            evidence=evidence,
            tags=["KISA:U-14"],
            description="PATH에 현재 디렉터리(.)가 포함되어 있습니다.",
            solution="PATH에서 현재 디렉터리(.)를 제거하세요.",
        )
        return self.results

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
            return CommandResult(result.stdout.strip(), "remote", None, host, command)

        if allow_local:
            try:
                parsed = shlex.split(command)
                result = subprocess.run(
                    parsed,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                return CommandResult(None, "local", str(exc), None, command)
            if result.returncode != 0:
                error = result.stderr.strip() or f"Command exit code {result.returncode}"
                return CommandResult(None, "local", error, None, command)
            return CommandResult(result.stdout.strip(), "local", None, None, command)

        return CommandResult(None, "remote", "Missing SSH credentials", host, command)

    def _read_optional_files(
        self,
        paths: Sequence[str],
    ) -> Tuple[List[ReadResult], List[ReadResult]]:
        results: List[ReadResult] = []
        errors: List[ReadResult] = []
        for raw in paths:
            path = Path(raw)
            result = self._read_config_lines(path)
            if result.lines is None:
                if _is_missing_file_error(result.error):
                    continue
                errors.append(result)
                continue
            results.append(result)
        return results, errors

    def _read_config_lines(self, config_path: Path) -> ReadResult:
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
                command = f"cat {shlex.quote(str(config_path))}"
                result = client.run(command)
            except AdapterError as exc:
                return ReadResult(None, "remote", str(exc), host, config_path)
            if result.exit_code != 0:
                error = result.stderr.strip() or f"SSH exit code {result.exit_code}"
                return ReadResult(None, "remote", error, host, config_path)
            return ReadResult(
                result.stdout.splitlines(),
                "remote",
                None,
                host,
                config_path,
            )

        if allow_local:
            if config_path.exists():
                return ReadResult(
                    config_path.read_text().splitlines(),
                    "local",
                    None,
                    None,
                    config_path,
                )
            return ReadResult(None, "local", "File not found", None, config_path)

        return ReadResult(None, "remote", "Missing SSH credentials", host, config_path)

    def _add_unavailable(self, os_type: str, path, results: List[ReadResult]) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path(path),
            "mode": self._merge_modes({str(idx): res.mode for idx, res in enumerate(results)}),
        }
        host = self._first_host(results)
        if host:
            evidence["host"] = host
        errors = [res.error for res in results if res.error]
        if errors:
            evidence["error"] = errors[0] if len(errors) == 1 else errors
        self.add_finding(
            vuln_id="KISA-U-14",
            title=f"{self._format_os(os_type)} PATH 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-14"],
            description="PATH 또는 프로필 파일을 읽지 못해 점검을 완료할 수 없습니다.",
            solution="대상 접근 권한과 설정 파일 경로를 확인하세요.",
        )

    def _to_read_result(self, result: Optional[CommandResult]) -> ReadResult:
        return ReadResult(
            lines=[result.output] if result and result.output else None,
            mode=result.mode if result else "unknown",
            error=result.error if result else None,
            host=result.host if result else None,
            path=None,
        )

    def _first_issue_line(
        self,
        runtime_detail: Dict[str, object],
        profile_detail: List[Dict[str, object]],
    ) -> Optional[str]:
        if runtime_detail:
            path = runtime_detail.get("path")
            if path:
                return path
        for item in profile_detail:
            line = item.get("line")
            if line:
                return line
        return None

    def _first_host(self, results: Sequence[ReadResult]) -> Optional[str]:
        for result in results:
            if result.host:
                return result.host
        return None

    def _format_source(self, runtime_issues: List[Dict], profile_issues: List[Dict]) -> str:
        runtime = bool(runtime_issues)
        profile = bool(profile_issues)
        if runtime and profile:
            return "mixed"
        if runtime:
            return "runtime"
        if profile:
            return "profile"
        return "unknown"

    def _merge_modes(self, modes: Dict[str, str]):
        if not modes:
            return None
        unique = set(modes.values())
        if len(unique) == 1:
            return next(iter(unique))
        return modes

    def _stringify_config_path(self, value):
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, list):
            return [self._stringify_config_path(item) for item in value]
        if isinstance(value, dict):
            return {key: self._stringify_config_path(val) for key, val in value.items()}
        return value

    def _format_os(self, os_type: str) -> str:
        display = {
            "linux": "Linux",
            "solaris": "Solaris",
            "aix": "AIX",
            "hpux": "HP-UX",
        }
        return display.get(os_type, os_type.upper())
