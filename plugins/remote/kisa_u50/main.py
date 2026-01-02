"""Remote plugin for KISA U-50 DNS zone transfer checks."""

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
DEFAULT_NAMED_CONF_PATHS = ("/etc/named.conf", "/etc/bind/named.conf.options")

ALLOW_TRANSFER_PATTERN = re.compile(r"allow-transfer\\s*\\{([^}]*)\\}", re.IGNORECASE | re.DOTALL)


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


def _strip_comments(text: str) -> str:
    out = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        out.append(line)
    return "\n".join(out)


def _parse_allow_transfer(lines: Sequence[str]) -> List[Dict[str, object]]:
    text = _strip_comments("\n".join(lines))
    matches = []
    for match in ALLOW_TRANSFER_PATTERN.finditer(text):
        raw = match.group(0).strip()
        body = match.group(1).strip()
        tokens = [token.strip().strip(";") for token in body.replace("\n", " ").split()]
        tokens = [token for token in tokens if token]
        matches.append({"raw": raw, "tokens": tokens})
    return matches


def _evaluate_allow_transfer(matches: Sequence[Dict[str, object]]) -> Tuple[str, Optional[str]]:
    if not matches:
        return "missing", None
    for match in matches:
        tokens = [token.lower() for token in match.get("tokens", [])]
        if not tokens:
            return "missing", match.get("raw")
        if "any" in tokens:
            return "any", match.get("raw")
    return "restricted", matches[0].get("raw")


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


class DnsZoneTransferCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        named_conf_paths = _normalize_list(
            self.context.config.get("named_conf_paths"),
            "named_conf_paths",
        ) or list(DEFAULT_NAMED_CONF_PATHS)
        allow_missing_config = bool(self.context.config.get("allow_missing_config", False))
        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        client, host = self._get_ssh_client()

        issues = []
        errors: List[Dict[str, str]] = []
        checked_files = []
        missing_files = []
        modes: Dict[str, Optional[str]] = {}

        for path_str in named_conf_paths:
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
            matches = _parse_allow_transfer(result.lines)
            status, raw = _evaluate_allow_transfer(matches)
            if status in ("any", "missing"):
                issues.append(
                    {
                        "path": str(path),
                        "issue": "allow_transfer_open" if status == "any" else "allow_transfer_missing",
                        "raw": raw,
                    }
                )

        if not issues:
            if not checked_files and not allow_missing_config:
                self._add_unavailable(
                    os_type,
                    named_conf_paths,
                    errors,
                    self._merge_modes(modes),
                    host,
                    missing_files,
                )
            return self.results

        limited = issues[:max_results]
        evidence = {
            "os_type": os_type,
            "config_path": {"named_conf_paths": named_conf_paths},
            "mode": self._merge_modes(modes),
            "detected_value": limited,
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
            vuln_id="KISA-U-50",
            title=f"{self._format_os(os_type)} DNS Zone Transfer 허용",
            severity="High",
            evidence=evidence,
            tags=["KISA:U-50"],
            description="DNS allow-transfer 설정이 과도하게 허용되어 있습니다.",
            solution="allow-transfer를 특정 IP 또는 none으로 제한하세요.",
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
        named_conf_paths: Sequence[str],
        errors: List[Dict[str, str]],
        mode: Optional[object],
        host: Optional[str],
        missing_files: Sequence[str],
    ) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": {"named_conf_paths": list(named_conf_paths)},
            "mode": mode,
            "partial_errors": errors,
            "missing_files": list(missing_files),
        }
        if host:
            evidence["host"] = host
        self.add_finding(
            vuln_id="KISA-U-50",
            title=f"{self._format_os(os_type)} DNS Zone Transfer 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-50"],
            description="DNS 설정 파일을 확인할 수 없습니다.",
            solution="대상 접근 권한과 named.conf 경로를 확인하세요.",
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
