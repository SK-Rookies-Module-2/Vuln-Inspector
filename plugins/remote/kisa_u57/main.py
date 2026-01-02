"""Remote plugin for KISA U-57 ftpusers checks."""

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
DEFAULT_FTPUSERS_PATHS = ("/etc/ftpusers", "/etc/vsftpd/ftpusers", "/etc/proftpd.ftpusers")


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
    if not line or line.startswith("#") or line.startswith(";"):
        return ""
    for token in ("#", ";"):
        if token in line:
            line = line.split(token, 1)[0].rstrip()
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


class FtpusersFileCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        ftpusers_paths = _normalize_list(
            self.context.config.get("ftpusers_paths"),
            "ftpusers_paths",
        ) or list(DEFAULT_FTPUSERS_PATHS)
        required_users = _normalize_list(
            self.context.config.get("required_users"),
            "required_users",
        ) or ["root"]
        required_users = [user.strip().lower() for user in required_users if user.strip()]
        if not ftpusers_paths:
            raise PluginConfigError("ftpusers_paths must include at least one path")
        if not required_users:
            raise PluginConfigError("required_users must include at least one user")

        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        client, host = self._get_ssh_client()

        issues: List[Dict[str, object]] = []
        errors: List[Dict[str, str]] = []
        checked_files = 0
        missing_files = 0
        modes: Dict[str, str] = {}
        found_required = {user: False for user in required_users}

        for path in ftpusers_paths:
            result = self._read_config_lines(Path(path), client, host)
            if result.path:
                modes[str(result.path)] = result.mode
            if result.missing:
                missing_files += 1
                issues.append({"path": str(path), "status": "missing"})
                continue
            if result.lines is None:
                if result.error:
                    errors.append({"path": str(path), "error": result.error})
                continue

            checked_files += 1
            file_hits = self._find_required_users(result.lines, required_users)
            for user in required_users:
                if user in file_hits:
                    found_required[user] = True
            issues.append(
                {
                    "path": str(path),
                    "status": "checked",
                    "found_users": sorted(file_hits),
                }
            )

        missing_required = [user for user, present in found_required.items() if not present]
        if not missing_required:
            return self.results

        if checked_files == 0 and errors:
            self._add_unavailable(
                os_type,
                {"ftpusers_paths": ftpusers_paths},
                errors,
                host,
            )
            return self.results

        limited = issues[:max_results]
        evidence = {
            "os_type": os_type,
            "config_path": {"ftpusers_paths": ftpusers_paths},
            "mode": self._merge_modes(modes),
            "detected_value": {
                "files": limited,
                "missing_users": missing_required,
            },
            "count": len(issues),
            "checked_files": checked_files,
            "missing_files": missing_files,
        }
        if host:
            evidence["host"] = host
        if errors:
            evidence["partial_errors"] = errors[:max_results]

        self.add_finding(
            vuln_id="KISA-U-57",
            title=f"{self._format_os(os_type)} ftpusers 설정 미흡",
            severity="Medium",
            evidence=evidence,
            tags=["KISA:U-57"],
            description="ftpusers 파일에 필수 계정이 포함되어 있지 않습니다.",
            solution="ftpusers 파일에 root 등 중요 계정을 추가하세요.",
        )
        return self.results

    def _find_required_users(self, lines: Sequence[str], required_users: Sequence[str]) -> List[str]:
        hits = []
        targets = {user.lower() for user in required_users if user}
        for raw_line in lines:
            line = _strip_comment(raw_line)
            if not line:
                continue
            token = line.split()[0].strip().lower()
            if token in targets:
                hits.append(token)
        return hits

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
                error = result.stderr.strip() or f"SSH exit code {result.exit_code}"
                if _is_missing_error(error):
                    return ReadResult(None, "remote", error, host, config_path, True)
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
            return ReadResult(None, "local", "File not found", None, config_path, True)

        return ReadResult(None, "remote", "Missing SSH credentials", host, config_path)

    def _add_unavailable(self, os_type: str, config_path, errors, host: Optional[str]) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": config_path,
        }
        if host:
            evidence["host"] = host
        if errors:
            evidence["error"] = errors[0] if len(errors) == 1 else errors
        self.add_finding(
            vuln_id="KISA-U-57",
            title=f"{self._format_os(os_type)} ftpusers 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-57"],
            description="ftpusers 파일을 확인할 수 없습니다.",
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

    def _merge_modes(self, modes: Dict[str, str]):
        if not modes:
            return None
        unique = set(modes.values())
        if len(unique) == 1:
            return next(iter(unique))
        return modes

    def _format_os(self, os_type: str) -> str:
        display = {
            "linux": "Linux",
            "solaris": "Solaris",
            "aix": "AIX",
            "hpux": "HP-UX",
        }
        return display.get(os_type, os_type.upper())
