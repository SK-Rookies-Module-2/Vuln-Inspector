"""Remote plugin for KISA U-09 unassigned GID checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shlex
from typing import Dict, List, Optional, Sequence, Set

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_GROUP_PATH = "/etc/group"
DEFAULT_PASSWD_PATH = "/etc/passwd"


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
    gid: int
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


def _normalize_int_list(value, name: str) -> Set[int]:
    if value is None:
        return set()
    if isinstance(value, int):
        return {value}
    if isinstance(value, list):
        gids = set()
        for item in value:
            try:
                gids.add(int(item))
            except (TypeError, ValueError):
                raise PluginConfigError(f"{name} must be an array of integers") from None
        return gids
    raise PluginConfigError(f"{name} must be an array of integers")


def _parse_group(lines: List[str]) -> Dict[str, GroupEntry]:
    entries: Dict[str, GroupEntry] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 3:
            continue
        name = parts[0].strip()
        gid_raw = parts[2].strip()
        if not name:
            continue
        try:
            gid = int(gid_raw)
        except (TypeError, ValueError):
            continue
        entries[name] = GroupEntry(name=name, gid=gid, line=raw_line.strip())
    return entries


def _parse_passwd_gids(lines: List[str]) -> Set[int]:
    gids: Set[int] = set()
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 4:
            continue
        gid_raw = parts[3].strip()
        try:
            gid = int(gid_raw)
        except (TypeError, ValueError):
            continue
        gids.add(gid)
    return gids


class UnassignedGidCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        group_path = Path(self.context.config.get("group_path") or DEFAULT_GROUP_PATH)
        passwd_path = Path(self.context.config.get("passwd_path") or DEFAULT_PASSWD_PATH)

        exclude_groups = _normalize_list(
            self.context.config.get("exclude_groups"),
            "exclude_groups",
        )
        exclude_gids = _normalize_int_list(
            self.context.config.get("exclude_gids"),
            "exclude_gids",
        )
        exclude_group_set = {name.strip() for name in exclude_groups if name.strip()}

        group_result = self._read_config_lines(group_path)
        passwd_result = self._read_config_lines(passwd_path)
        if group_result.lines is None or passwd_result.lines is None:
            self._add_unavailable(
                os_type,
                {"group": group_path, "passwd": passwd_path},
                [group_result, passwd_result],
            )
            return self.results

        group_entries = _parse_group(group_result.lines)
        passwd_gids = _parse_passwd_gids(passwd_result.lines)

        findings = []
        for entry in group_entries.values():
            if entry.name in exclude_group_set:
                continue
            if entry.gid in exclude_gids:
                continue
            if entry.gid not in passwd_gids:
                findings.append(
                    {
                        "group": entry.name,
                        "gid": entry.gid,
                        "line": entry.line,
                    }
                )

        if findings:
            evidence = {
                "os_type": os_type,
                "config_path": self._stringify_config_path(
                    {"group": group_path, "passwd": passwd_path}
                ),
                "mode": self._merge_modes(
                    {"group": group_result.mode, "passwd": passwd_result.mode}
                ),
                "detected_value": findings,
                "group": findings[0].get("group"),
                "gid": findings[0].get("gid"),
                "line": findings[0].get("line"),
            }
            host = group_result.host or passwd_result.host
            if host:
                evidence["host"] = host
            self.add_finding(
                vuln_id="KISA-U-09",
                title=f"{self._format_os(os_type)} 계정 없는 GID 존재",
                severity="Low",
                evidence=evidence,
                tags=["KISA:U-09"],
                description="계정에 할당되지 않은 GID를 가진 그룹이 존재합니다.",
                solution="불필요한 그룹을 삭제하거나 적절한 계정에 할당하세요.",
            )

        return self.results

    def _add_unavailable(self, os_type: str, path, results) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path(path),
            "mode": self._merge_modes({str(idx): res.mode for idx, res in enumerate(results)}),
        }
        host = next((res.host for res in results if res.host), None)
        if host:
            evidence["host"] = host
        errors = [res.error for res in results if res.error]
        if errors:
            evidence["error"] = errors[0] if len(errors) == 1 else errors
        self.add_finding(
            vuln_id="KISA-U-09",
            title=f"{self._format_os(os_type)} GID 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-09"],
            description="필수 파일을 읽지 못해 점검을 완료할 수 없습니다.",
            solution="대상 접근 권한과 설정 파일 경로를 확인하세요.",
        )

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

    def _merge_modes(self, modes: Dict[str, str]):
        if not modes:
            return None
        unique = set(modes.values())
        if len(unique) == 1:
            return next(iter(unique))
        return modes

    def _stringify_config_path(self, value):
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, list):
            return [self._stringify_config_path(item) for item in value]
        if isinstance(value, dict):
            return {key: self._stringify_config_path(val) for key, val in value.items()}
        return value

    def _format_os(self, os_type: str) -> str:
        display = {
            "linux": "Linux",
            "solaris": "Solaris",
            "aix": "AIX",
            "hpux": "HP-UX",
        }
        return display.get(os_type, os_type.upper())
