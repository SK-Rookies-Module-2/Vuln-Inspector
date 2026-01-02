"""Remote plugin for KISA U-05 UID 0 account checks."""

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


@dataclass
class ReadResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None


@dataclass
class UidZeroAccount:
    name: str
    uid: int
    line: str


def _parse_uid_zero_accounts(lines: List[str]) -> List[UidZeroAccount]:
    accounts: List[UidZeroAccount] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 3:
            continue
        username = parts[0].strip()
        uid_raw = parts[2].strip()
        try:
            uid = int(uid_raw)
        except (TypeError, ValueError):
            continue
        if uid == 0 and username and username != "root":
            accounts.append(
                UidZeroAccount(
                    name=username,
                    uid=uid,
                    line=raw_line.strip(),
                )
            )
    return accounts


class UidZeroAccountCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        passwd_path = Path(
            self.context.config.get("passwd_path") or DEFAULT_PASSWD_PATH
        )
        result = self._read_config_lines(passwd_path)
        if result.lines is None:
            self._add_unavailable(os_type, passwd_path, result)
            return self.results

        accounts = _parse_uid_zero_accounts(result.lines)
        if accounts:
            evidence = self._base_evidence(os_type, passwd_path, result)
            evidence["detected_value"] = [
                {
                    "account": account.name,
                    "uid": account.uid,
                    "line": account.line,
                }
                for account in accounts
            ]
            evidence["count"] = len(accounts)
            evidence["line"] = accounts[0].line
            self.add_finding(
                vuln_id="KISA-U-05",
                title=f"{self._format_os(os_type)} UID 0 계정 존재",
                severity="High",
                evidence=evidence,
                tags=["KISA:U-05"],
                description="root 이외의 UID 0 계정이 존재합니다.",
                solution="불필요한 UID 0 계정을 삭제하거나 UID를 변경하세요.",
            )

        return self.results

    def _add_unavailable(self, os_type: str, path: Path, result: ReadResult) -> None:
        evidence = self._base_evidence(os_type, path, result)
        if result.error:
            evidence["error"] = result.error
        self.add_finding(
            vuln_id="KISA-U-05",
            title=f"{self._format_os(os_type)} UID 0 계정 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-05"],
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
