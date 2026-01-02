"""Remote plugin for KISA U-08 admin group membership checks."""

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
DEFAULT_GROUP_PATH = "/etc/group"


@dataclass
class ReadResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None


@dataclass
class GroupEntry:
    name: str
    members: List[str]
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


def _parse_group(lines: List[str]) -> Dict[str, GroupEntry]:
    entries: Dict[str, GroupEntry] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 4:
            continue
        name = parts[0].strip()
        members_raw = parts[3].strip()
        if not name:
            continue
        members = [member.strip() for member in members_raw.split(",") if member.strip()]
        entries[name] = GroupEntry(name=name, members=members, line=raw_line.strip())
    return entries


class AdminGroupMembershipCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        group_path = Path(self.context.config.get("group_path") or DEFAULT_GROUP_PATH)
        admin_groups = _normalize_list(self.context.config.get("admin_groups"), "admin_groups")
        allowed_members = _normalize_list(
            self.context.config.get("allowed_members"),
            "allowed_members",
        )

        if not admin_groups:
            raise PluginConfigError("admin_groups must include at least one group")

        result = self._read_config_lines(group_path)
        if result.lines is None:
            self._add_unavailable(os_type, group_path, result)
            return self.results

        groups = _parse_group(result.lines)
        findings = []
        for group_name in admin_groups:
            entry = groups.get(group_name)
            if not entry:
                continue
            unexpected = [
                member
                for member in entry.members
                if member not in allowed_members
            ]
            if unexpected:
                findings.append(
                    {
                        "group": group_name,
                        "unexpected_members": unexpected,
                        "members": entry.members,
                        "line": entry.line,
                    }
                )

        if findings:
            evidence = self._base_evidence(os_type, group_path, result)
            evidence["detected_value"] = findings
            evidence["group"] = findings[0].get("group")
            evidence["line"] = findings[0].get("line")
            self.add_finding(
                vuln_id="KISA-U-08",
                title=f"{self._format_os(os_type)} 관리자 그룹 계정 과다",
                severity="Medium",
                evidence=evidence,
                tags=["KISA:U-08"],
                description="관리자 그룹에 불필요한 계정이 포함되어 있습니다.",
                solution="관리자 그룹에서 불필요한 계정을 제거하세요.",
            )

        return self.results

    def _add_unavailable(self, os_type: str, path: Path, result: ReadResult) -> None:
        evidence = self._base_evidence(os_type, path, result)
        if result.error:
            evidence["error"] = result.error
        self.add_finding(
            vuln_id="KISA-U-08",
            title=f"{self._format_os(os_type)} 관리자 그룹 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-08"],
            description="/etc/group 파일을 읽지 못해 점검을 완료할 수 없습니다.",
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
