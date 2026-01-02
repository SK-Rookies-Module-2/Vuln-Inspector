"""Remote plugin for KISA U-66 syslog policy checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import shlex
from typing import Dict, List, Optional, Sequence, Tuple

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_SYSLOG_PATHS = ("/etc/syslog.conf", "/etc/rsyslog.conf")
DEFAULT_REQUIRED_SELECTORS = ("*.info", "authpriv.*", "mail.*", "cron.*", "*.alert", "*.emerg")


@dataclass
class ReadResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None
    missing: bool = False


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


def _parse_selector_tokens(lines: Sequence[str]) -> List[str]:
    tokens: List[str] = []
    for raw_line in lines:
        line = _strip_comment(raw_line)
        if not line:
            continue
        if line.startswith("$"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        selector_part = parts[0].strip()
        if not selector_part:
            continue
        for selector in selector_part.split(";"):
            selector = selector.strip()
            if not selector or "." not in selector:
                continue
            facility_part, priority_part = selector.rsplit(".", 1)
            priority = priority_part.strip()
            if not priority:
                continue
            if priority.startswith("!"):
                continue
            if priority.startswith("="):
                priority = priority[1:]
            if priority.lower() == "none":
                continue
            facilities = [fac.strip() for fac in facility_part.split(",") if fac.strip()]
            for facility in facilities:
                tokens.append(f"{facility}.{priority}")
    return tokens


def _parse_required_patterns(selectors: Sequence[str]) -> List[Tuple[str, str, re.Pattern]]:
    patterns = []
    for selector in selectors:
        if "." not in selector:
            continue
        facility, priority = selector.split(".", 1)
        facility = facility.strip()
        priority = priority.strip()
        if not facility or not priority:
            continue
        facility_regex = r".+" if facility == "*" else re.escape(facility)
        priority_regex = r".+" if priority == "*" else re.escape(priority)
        patterns.append((facility, priority, re.compile(rf"^{facility_regex}\\.{priority_regex}$", re.IGNORECASE)))
    return patterns


def _match_required(tokens: Sequence[str], required: Sequence[str]) -> Tuple[List[str], List[str]]:
    patterns = _parse_required_patterns(required)
    missing = []
    matched = []
    for selector, _, pattern in patterns:
        found = False
        for token in tokens:
            if pattern.match(token):
                found = True
                break
        if found:
            matched.append(selector)
        else:
            missing.append(selector)
    return missing, matched


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


class SystemLoggingPolicyCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        syslog_conf_paths = _normalize_list(
            self.context.config.get("syslog_conf_paths"),
            "syslog_conf_paths",
        ) or list(DEFAULT_SYSLOG_PATHS)
        required_selectors = _normalize_list(
            self.context.config.get("required_selectors"),
            "required_selectors",
        ) or list(DEFAULT_REQUIRED_SELECTORS)

        allow_missing_config = bool(self.context.config.get("allow_missing_config", False))
        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        client, host = self._get_ssh_client()

        tokens: List[str] = []
        checked_files = []
        missing_files = []
        errors: List[Dict[str, str]] = []
        modes: Dict[str, Optional[str]] = {}

        for path_str in syslog_conf_paths:
            path = Path(path_str)
            result = self._read_config_lines(path, client, host)
            modes[str(path)] = result.mode
            if result.lines is None:
                if result.missing:
                    missing_files.append(str(path))
                else:
                    errors.append(
                        {
                            "path": str(path),
                            "error": result.error or "Read failed",
                        }
                    )
                continue
            checked_files.append(str(path))
            tokens.extend(_parse_selector_tokens(result.lines))

        if not checked_files:
            if allow_missing_config:
                return self.results
            self._add_unavailable(
                os_type,
                syslog_conf_paths,
                errors,
                self._merge_modes(modes),
                host,
                missing_files,
            )
            return self.results

        missing, matched = _match_required(tokens, required_selectors)
        if not missing:
            return self.results

        issues = [{"missing_selector": selector} for selector in missing]
        limited = issues[:max_results]
        evidence = {
            "os_type": os_type,
            "config_path": {"syslog_conf_paths": syslog_conf_paths},
            "mode": self._merge_modes(modes),
            "detected_value": limited,
            "count": len(issues),
            "checked_files": checked_files,
            "matched_selectors": matched[:max_results],
        }
        if host:
            evidence["host"] = host
        if missing_files:
            evidence["missing_files"] = missing_files
        if errors:
            evidence["partial_errors"] = errors[:max_results]

        self.add_finding(
            vuln_id="KISA-U-66",
            title=f"{self._format_os(os_type)} 시스템 로깅 설정 미흡",
            severity="Medium",
            evidence=evidence,
            tags=["KISA:U-66"],
            description="주요 로그 레벨이 정책에 따라 설정되어 있지 않습니다.",
            solution="syslog/rsyslog 설정에 필수 selector를 추가하세요.",
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

    def _add_unavailable(
        self,
        os_type: str,
        syslog_conf_paths: Sequence[str],
        errors: List[Dict[str, str]],
        mode: Optional[object],
        host: Optional[str],
        missing_files: Sequence[str],
    ) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": {"syslog_conf_paths": list(syslog_conf_paths)},
            "mode": mode,
            "partial_errors": errors,
            "missing_files": list(missing_files),
        }
        if host:
            evidence["host"] = host
        self.add_finding(
            vuln_id="KISA-U-66",
            title=f"{self._format_os(os_type)} 시스템 로깅 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-66"],
            description="시스템 로깅 설정을 확인할 수 없습니다.",
            solution="대상 접근 권한과 syslog 설정 파일 경로를 확인하세요.",
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
