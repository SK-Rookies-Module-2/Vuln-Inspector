"""Remote plugin for KISA U-11 system account shell checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shlex
from typing import Dict, List, Optional, Sequence

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_PASSWD_PATH = "/etc/passwd"


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


class SystemAccountShellCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        passwd_path = Path(self.context.config.get("passwd_path") or DEFAULT_PASSWD_PATH)
        system_accounts = _normalize_list(
            self.context.config.get("system_accounts"),
            "system_accounts",
        )
        non_login_shells = _normalize_list(
            self.context.config.get("non_login_shells"),
            "non_login_shells",
        )
        exclude_accounts = _normalize_list(
            self.context.config.get("exclude_accounts"),
            "exclude_accounts",
        )
        system_set = {name.strip() for name in system_accounts if name.strip()}
        exclude_set = {name.strip() for name in exclude_accounts if name.strip()}

        result = self._read_config_lines(passwd_path)
        if result.lines is None:
            self._add_unavailable(os_type, passwd_path, result)
            return self.results

        entries = _parse_passwd(result.lines)
        findings = []
        for entry in entries:
            if entry.name not in system_set:
                continue
            if entry.name in exclude_set:
                continue
            if entry.shell in non_login_shells:
                continue
            findings.append(
                {
                    "account": entry.name,
                    "shell": entry.shell,
                    "line": entry.line,
                }
            )

        if findings:
            evidence = self._base_evidence(os_type, passwd_path, result)
            evidence["detected_value"] = findings
            evidence["account"] = findings[0].get("account")
            evidence["line"] = findings[0].get("line")
            self.add_finding(
                vuln_id="KISA-U-11",
                title=f"{self._format_os(os_type)} 시스템 계정 쉘 설정 미흡",
                severity="Low",
                evidence=evidence,
                tags=["KISA:U-11"],
                description="로그인이 필요 없는 계정에 로그인 쉘이 부여되어 있습니다.",
                solution="시스템 계정의 쉘을 /bin/false 또는 /sbin/nologin으로 변경하세요.",
            )

        return self.results

    def _add_unavailable(self, os_type: str, path: Path, result: ReadResult) -> None:
        evidence = self._base_evidence(os_type, path, result)
        if result.error:
            evidence["error"] = result.error
        self.add_finding(
            vuln_id="KISA-U-11",
            title=f"{self._format_os(os_type)} 쉘 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-11"],
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

    def _format_os(self, os_type: str) -> str:
        display = {
            "linux": "Linux",
            "solaris": "Solaris",
            "aix": "AIX",
            "hpux": "HP-UX",
        }
        return display.get(os_type, os_type.upper())
