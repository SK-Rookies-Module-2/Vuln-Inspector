"""Remote plugin for KISA U-48 SMTP expn/vrfy checks."""

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
DEFAULT_SENDMAIL_CF_PATH = "/etc/mail/sendmail.cf"


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


def _parse_privacy_options(lines: List[str]) -> List[Dict[str, object]]:
    matches = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if "privacyoptions" not in lowered:
            continue
        if "privacyoptions" in lowered and lowered.startswith("o"):
            key, _, value = line.partition(" ")
            options_part = value.strip()
        else:
            _, _, options_part = line.partition("=")
            options_part = options_part.strip()
        if not options_part:
            continue
        tokens = [item.strip().lower() for item in options_part.split(",") if item.strip()]
        if tokens:
            matches.append({"line": raw_line, "options": tokens})
    return matches


class SmtpExpnVrfyCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        sendmail_cf_path = Path(
            self.context.config.get("sendmail_cf_path") or DEFAULT_SENDMAIL_CF_PATH
        )
        required_tokens = _normalize_list(
            self.context.config.get("required_tokens"),
            "required_tokens",
        ) or ["noexpn", "novrfy"]
        required_set = {token.strip().lower() for token in required_tokens if token.strip()}
        if not required_set:
            raise PluginConfigError("required_tokens must include at least one token")
        allow_goaway = bool(self.context.config.get("allow_goaway", True))
        max_results = self._to_positive_int(self.context.config.get("max_results", 200), "max_results")

        read_result = self._read_lines(sendmail_cf_path)
        if read_result.missing:
            return self.results
        if read_result.lines is None:
            self._add_unavailable(os_type, str(sendmail_cf_path), read_result)
            return self.results

        matches = _parse_privacy_options(read_result.lines)
        if not matches:
            self._add_missing_options(os_type, sendmail_cf_path, None, None, read_result)
            return self.results

        issues = []
        for entry in matches:
            options = set(entry["options"])
            if allow_goaway and "goaway" in options:
                continue
            missing = sorted(required_set - options)
            if missing:
                issues.append(
                    {
                        "line": entry["line"],
                        "options": sorted(options),
                        "missing": missing,
                    }
                )

        if issues:
            limited = issues[:max_results]
            evidence = {
                "os_type": os_type,
                "config_path": str(sendmail_cf_path),
                "mode": read_result.mode,
                "detected_value": limited,
                "count": len(issues),
            }
            if read_result.host:
                evidence["host"] = read_result.host
            if read_result.error:
                evidence["partial_errors"] = [read_result.error]

            self.add_finding(
                vuln_id="KISA-U-48",
                title=f"{self._format_os(os_type)} SMTP expn/vrfy 제한 미설정",
                severity="Medium",
                evidence=evidence,
                tags=["KISA:U-48"],
                description="sendmail PrivacyOptions에 noexpn/novrfy 설정이 없습니다.",
                solution="sendmail.cf의 PrivacyOptions에 noexpn, novrfy 또는 goaway를 설정하세요.",
            )
        return self.results

    def _add_missing_options(
        self,
        os_type: str,
        path: Path,
        host: Optional[str],
        error: Optional[str],
        result: ReadResult,
    ) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": str(path),
            "mode": result.mode,
            "detected_value": "PrivacyOptions not found",
            "count": 1,
        }
        if host:
            evidence["host"] = host
        if error:
            evidence["partial_errors"] = [error]
        elif result.error:
            evidence["partial_errors"] = [result.error]

        self.add_finding(
            vuln_id="KISA-U-48",
            title=f"{self._format_os(os_type)} SMTP expn/vrfy 제한 미설정",
            severity="Medium",
            evidence=evidence,
            tags=["KISA:U-48"],
            description="sendmail 설정에서 PrivacyOptions 항목을 찾을 수 없습니다.",
            solution="sendmail.cf의 PrivacyOptions에 noexpn, novrfy 또는 goaway를 설정하세요.",
        )

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
            vuln_id="KISA-U-48",
            title=f"{self._format_os(os_type)} SMTP expn/vrfy 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-48"],
            description="sendmail 설정 파일을 확인할 수 없습니다.",
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
