"""Remote plugin for KISA U-62 login warning banner checks."""

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
DEFAULT_MOTD_PATH = "/etc/motd"
DEFAULT_ISSUE_PATH = "/etc/issue"
DEFAULT_ISSUE_NET_PATH = "/etc/issue.net"
DEFAULT_SSHD_CONFIG = "/etc/ssh/sshd_config"


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


def _parse_banner_path(lines: Sequence[str]) -> Optional[str]:
    for raw_line in lines:
        line = _strip_comment(raw_line)
        if not line:
            continue
        if line.lower().startswith("banner"):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1].strip()
            return None
    return None


def _contains_any(text: str, phrases: Sequence[str]) -> bool:
    lowered = text.lower()
    for phrase in phrases:
        if phrase.lower() in lowered:
            return True
    return False


def _find_disallowed(text: str, patterns: Sequence[str]) -> List[str]:
    hits = []
    for pattern in patterns:
        if not pattern:
            continue
        try:
            if re.search(pattern, text, re.IGNORECASE):
                hits.append(pattern)
        except re.error:
            if pattern.lower() in text.lower():
                hits.append(pattern)
    return hits


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


class LoginWarningBannerCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        motd_path = Path(self.context.config.get("motd_path") or DEFAULT_MOTD_PATH)
        issue_path = Path(self.context.config.get("issue_path") or DEFAULT_ISSUE_PATH)
        issue_net_path = Path(self.context.config.get("issue_net_path") or DEFAULT_ISSUE_NET_PATH)
        sshd_config_path = Path(self.context.config.get("sshd_config_path") or DEFAULT_SSHD_CONFIG)

        required_phrases = _normalize_list(
            self.context.config.get("required_banner_phrases"),
            "required_banner_phrases",
        )
        disallowed_patterns = _normalize_list(
            self.context.config.get("disallowed_patterns"),
            "disallowed_patterns",
        )

        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        client, host = self._get_ssh_client()

        banner_paths = [
            ("motd", motd_path),
            ("issue", issue_path),
            ("issue_net", issue_net_path),
        ]
        checked_files = []
        missing_files = []
        errors: List[Dict[str, str]] = []
        issues = []
        modes: Dict[str, Optional[str]] = {}

        sshd_result = self._read_config_lines(sshd_config_path, client, host)
        modes["sshd_config"] = sshd_result.mode
        banner_from_sshd = None
        if sshd_result.lines is None:
            if not sshd_result.missing:
                errors.append(
                    {
                        "source": "sshd_config",
                        "path": str(sshd_config_path),
                        "error": sshd_result.error or "Read failed",
                    }
                )
            else:
                missing_files.append(str(sshd_config_path))
        else:
            checked_files.append(str(sshd_config_path))
            banner_from_sshd = _parse_banner_path(sshd_result.lines)
            if banner_from_sshd:
                banner_paths.append(("sshd_banner", Path(banner_from_sshd)))

        for label, path in banner_paths:
            result = self._read_config_lines(path, client, host)
            modes[str(path)] = result.mode
            if result.lines is None:
                if result.missing:
                    missing_files.append(str(path))
                    continue
                errors.append(
                    {
                        "source": label,
                        "path": str(path),
                        "error": result.error or "Read failed",
                    }
                )
                continue
            checked_files.append(str(path))
            content = "\n".join(result.lines).strip()
            if not content:
                issues.append(
                    {
                        "path": str(path),
                        "issue": "banner_empty",
                        "source": label,
                    }
                )
                continue
            if required_phrases and not _contains_any(content, required_phrases):
                issues.append(
                    {
                        "path": str(path),
                        "issue": "warning_missing",
                        "source": label,
                    }
                )
            disallowed_hits = _find_disallowed(content, disallowed_patterns)
            if disallowed_hits:
                issues.append(
                    {
                        "path": str(path),
                        "issue": "system_info_exposed",
                        "source": label,
                        "patterns": disallowed_hits,
                    }
                )

        if not issues:
            if not checked_files and errors:
                self._add_unavailable(
                    os_type,
                    motd_path,
                    issue_path,
                    issue_net_path,
                    sshd_config_path,
                    errors,
                    self._merge_modes(modes),
                    host,
                    missing_files,
                )
            return self.results

        limited = issues[:max_results]
        evidence = {
            "os_type": os_type,
            "config_path": {
                "motd_path": str(motd_path),
                "issue_path": str(issue_path),
                "issue_net_path": str(issue_net_path),
                "sshd_config_path": str(sshd_config_path),
                "sshd_banner_path": banner_from_sshd,
            },
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
            vuln_id="KISA-U-62",
            title=f"{self._format_os(os_type)} 로그인 경고 메시지 설정 미흡",
            severity="Low",
            evidence=evidence,
            tags=["KISA:U-62"],
            description="로그인 경고 메시지가 없거나 시스템 정보가 노출되어 있습니다.",
            solution="경고 문구를 설정하고 시스템 정보가 노출되지 않도록 조치하세요.",
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
        motd_path: Path,
        issue_path: Path,
        issue_net_path: Path,
        sshd_config_path: Path,
        errors: List[Dict[str, str]],
        mode: Optional[object],
        host: Optional[str],
        missing_files: Sequence[str],
    ) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": {
                "motd_path": str(motd_path),
                "issue_path": str(issue_path),
                "issue_net_path": str(issue_net_path),
                "sshd_config_path": str(sshd_config_path),
            },
            "mode": mode,
            "partial_errors": errors,
            "missing_files": list(missing_files),
        }
        if host:
            evidence["host"] = host
        self.add_finding(
            vuln_id="KISA-U-62",
            title=f"{self._format_os(os_type)} 로그인 경고 메시지 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-62"],
            description="로그인 경고 메시지 설정을 확인할 수 없습니다.",
            solution="대상 접근 권한과 배너 파일 경로를 확인하세요.",
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
