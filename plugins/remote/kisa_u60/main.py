"""Remote plugin for KISA U-60 SNMP community checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shlex
from typing import Dict, List, Optional

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding
from plugins.remote.utils.text import strip_comments

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_SNMPD_CONF_PATH = "/etc/snmp/snmpd.conf"
COMMUNITY_DIRECTIVES = {"rocommunity", "rwcommunity"}


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


def _parse_community_lines(lines: List[str]) -> List[Dict[str, str]]:
    entries = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        directive = parts[0].lower()
        if directive not in COMMUNITY_DIRECTIVES:
            continue
        community = parts[1]
        entries.append(
            {
                "directive": directive,
                "community": community,
                "line": raw_line,
            }
        )
    return entries


def _is_insecure(community: str, tokens: List[str]) -> bool:
    lowered = community.lower()
    for token in tokens:
        token = token.strip().lower()
        if not token:
            continue
        if token in lowered:
            return True
    return False


class SnmpCommunityCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        snmpd_conf_path = Path(
            self.context.config.get("snmpd_conf_path") or DEFAULT_SNMPD_CONF_PATH
        )
        insecure_tokens = _normalize_list(
            self.context.config.get("insecure_tokens"),
            "insecure_tokens",
        ) or ["public", "private"]
        insecure_tokens = [token.strip() for token in insecure_tokens if token.strip()]
        if not insecure_tokens:
            raise PluginConfigError("insecure_tokens must include at least one token")

        max_results = self._to_positive_int(self.context.config.get("max_results", 200), "max_results")

        read_result = self._read_lines(snmpd_conf_path)
        if read_result.missing:
            return self.results
        if read_result.lines is None:
            self._add_unavailable(os_type, str(snmpd_conf_path), read_result)
            return self.results

        entries = _parse_community_lines(read_result.lines)
        issues = []
        for entry in entries:
            if _is_insecure(entry["community"], insecure_tokens):
                issues.append(entry)

        if issues:
            evidence = {
                "os_type": os_type,
                "config_path": str(snmpd_conf_path),
                "mode": read_result.mode,
                "detected_value": issues[:max_results],
                "count": len(issues),
            }
            if read_result.host:
                evidence["host"] = read_result.host
            if read_result.error:
                evidence["partial_errors"] = [read_result.error]

            self.add_finding(
                vuln_id="KISA-U-60",
                title=f"{self._format_os(os_type)} SNMP Community String 취약",
                severity="Medium",
                evidence=evidence,
                tags=["KISA:U-60"],
                description="SNMP Community String에 기본값(public/private)이 포함되어 있습니다.",
                solution="public/private 대신 예측하기 어려운 커뮤니티 문자열로 변경하세요.",
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

    def _add_unavailable(self, os_type: str, config_path: str, result: ReadResult) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": config_path,
            "mode": result.mode,
        }
        if result.host:
            evidence["host"] = result.host
        if result.error:
            evidence["error"] = result.error

        self.add_finding(
            vuln_id="KISA-U-60",
            title=f"{self._format_os(os_type)} SNMP Community 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-60"],
            description="snmpd.conf를 확인할 수 없습니다.",
            solution="대상 접근 권한과 파일 경로를 확인하세요.",
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
