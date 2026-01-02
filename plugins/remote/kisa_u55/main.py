"""Remote plugin for KISA U-55 FTP account shell checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shlex
from typing import Dict, List, Optional

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_PASSWD_PATH = "/etc/passwd"
DEFAULT_FTP_ACCOUNTS = ("ftp",)
DEFAULT_ALLOWED_SHELLS = ("/bin/false", "/sbin/nologin", "/usr/sbin/nologin")


@dataclass
class ReadResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None


@dataclass
class PasswdEntry:
    name: str
    shell: str
    line: str


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


def _parse_passwd(lines: List[str]) -> List[PasswdEntry]:
    entries: List[PasswdEntry] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name = parts[0].strip()
        shell = parts[6].strip()
        if not name:
            continue
        entries.append(PasswdEntry(name=name, shell=shell, line=raw_line.strip()))
    return entries


class FtpAccountShellCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        passwd_path = Path(self.context.config.get("passwd_path") or DEFAULT_PASSWD_PATH)
        ftp_accounts = _normalize_list(
            self.context.config.get("ftp_accounts"),
            "ftp_accounts",
        ) or list(DEFAULT_FTP_ACCOUNTS)
        allowed_shells = _normalize_list(
            self.context.config.get("allowed_shells"),
            "allowed_shells",
        ) or list(DEFAULT_ALLOWED_SHELLS)
        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        ftp_set = {name.strip() for name in ftp_accounts if name and name.strip()}
        allowed_set = {shell.strip() for shell in allowed_shells if shell and shell.strip()}

        result = self._read_config_lines(passwd_path)
        if result.lines is None:
            self._add_unavailable(os_type, passwd_path, result)
            return self.results

        entries = _parse_passwd(result.lines)
        findings = []
        for entry in entries:
            if entry.name not in ftp_set:
                continue
            if entry.shell in allowed_set:
                continue
            findings.append(
                {
                    "account": entry.name,
                    "shell": entry.shell,
                    "line": entry.line,
                }
            )

        if findings:
            limited = findings[:max_results]
            evidence = self._base_evidence(os_type, passwd_path, result)
            evidence["detected_value"] = limited
            evidence["count"] = len(findings)
            evidence["allowed_shells"] = sorted(allowed_set)
            self.add_finding(
                vuln_id="KISA-U-55",
                title=f"{self._format_os(os_type)} FTP 계정 쉘 제한 미흡",
                severity="Medium",
                evidence=evidence,
                tags=["KISA:U-55"],
                description="FTP 계정에 로그인 쉘이 설정되어 있습니다.",
                solution="FTP 계정 쉘을 /bin/false 또는 /sbin/nologin으로 변경하세요.",
            )

        return self.results

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
            return ReadResult(result.stdout.splitlines(), "remote", None, host, config_path)

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

    def _add_unavailable(self, os_type: str, path: Path, result: ReadResult) -> None:
        evidence = self._base_evidence(os_type, path, result)
        if result.error:
            evidence["error"] = result.error
        self.add_finding(
            vuln_id="KISA-U-55",
            title=f"{self._format_os(os_type)} FTP 계정 쉘 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-55"],
            description="/etc/passwd 파일을 읽지 못해 점검을 완료할 수 없습니다.",
            solution="대상 접근 권한과 설정 파일 경로를 확인하세요.",
        )

    def _base_evidence(self, os_type: str, path: Path, result: ReadResult) -> Dict:
        evidence = {
            "os_type": os_type,
            "config_path": str(path),
            "mode": result.mode,
        }
        if result.host:
            evidence["host"] = result.host
        return evidence

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
