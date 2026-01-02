"""Remote plugin for KISA U-61 SNMP access control checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shlex
from typing import Dict, List, Optional, Sequence, Tuple

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_SNMPD_CONF_PATH = "/etc/snmp/snmpd.conf"
DEFAULT_DIRECTIVES = (
    "com2sec",
    "com2sec6",
    "rocommunity",
    "rwcommunity",
    "rocommunity6",
    "rwcommunity6",
)
DEFAULT_INSECURE_SOURCES = ("default", "0.0.0.0", "0.0.0.0/0", "::", "::/0", "any")


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


class SnmpAccessControlCheck(BasePlugin):
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
        directives = _normalize_list(
            self.context.config.get("directives"),
            "directives",
        ) or list(DEFAULT_DIRECTIVES)
        directives = [item.strip().lower() for item in directives if item.strip()]
        if not directives:
            raise PluginConfigError("directives must include at least one directive")

        insecure_sources = _normalize_list(
            self.context.config.get("insecure_sources"),
            "insecure_sources",
        ) or list(DEFAULT_INSECURE_SOURCES)
        insecure_sources = [item.strip().lower() for item in insecure_sources if item.strip()]
        require_source = bool(self.context.config.get("require_source", True))
        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        read_result = self._read_lines(snmpd_conf_path)
        if read_result.missing:
            return self.results
        if read_result.lines is None:
            self._add_unavailable(os_type, str(snmpd_conf_path), read_result)
            return self.results

        issues = self._find_issues(read_result.lines, directives, insecure_sources, require_source)
        if not issues:
            return self.results

        evidence = {
            "os_type": os_type,
            "config_path": str(snmpd_conf_path),
            "mode": read_result.mode,
            "detected_value": issues[:max_results],
            "count": len(issues),
            "policy": {
                "directives": directives,
                "insecure_sources": insecure_sources,
                "require_source": require_source,
            },
        }
        if read_result.host:
            evidence["host"] = read_result.host
        if read_result.error:
            evidence["partial_errors"] = [read_result.error]

        self.add_finding(
            vuln_id="KISA-U-61",
            title=f"{self._format_os(os_type)} SNMP 접근제어 미흡",
            severity="High",
            evidence=evidence,
            tags=["KISA:U-61"],
            description="SNMP 접근제어에 특정 IP/네트워크 제한이 없습니다.",
            solution="SNMP 접근이 필요한 IP/네트워크만 허용하도록 제한하세요.",
        )
        return self.results

    def _find_issues(
        self,
        lines: Sequence[str],
        directives: Sequence[str],
        insecure_sources: Sequence[str],
        require_source: bool,
    ) -> List[Dict[str, object]]:
        issues = []
        directive_set = {item.lower() for item in directives}
        insecure_set = {item.lower() for item in insecure_sources}
        for raw_line in lines:
            line = _strip_comment(raw_line)
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            directive = parts[0].lower()
            if directive not in directive_set:
                continue
            source = self._extract_source(directive, parts)
            if not source:
                if require_source:
                    issues.append(
                        {
                            "directive": directive,
                            "issue": "source_missing",
                            "line": raw_line.strip(),
                        }
                    )
                continue
            normalized = source.lower().strip()
            if normalized in insecure_set:
                issues.append(
                    {
                        "directive": directive,
                        "issue": "source_insecure",
                        "source": source,
                        "line": raw_line.strip(),
                    }
                )
        return issues

    def _extract_source(self, directive: str, parts: List[str]) -> Optional[str]:
        if directive in ("com2sec", "com2sec6"):
            if len(parts) >= 4:
                return parts[2]
            return None
        if directive in ("rocommunity", "rwcommunity", "rocommunity6", "rwcommunity6"):
            if len(parts) >= 3:
                return parts[2]
            return None
        return None

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
            return ReadResult(raw_lines, "remote", None, host, path)

        if allow_local:
            if not path.exists():
                return ReadResult(None, "local", "File not found", None, path, True)
            try:
                raw_lines = path.read_text().splitlines()
            except OSError as exc:
                return ReadResult(None, "local", str(exc), None, path)
            return ReadResult(raw_lines, "local", None, None, path)

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
            vuln_id="KISA-U-61",
            title=f"{self._format_os(os_type)} SNMP 접근제어 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-61"],
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
