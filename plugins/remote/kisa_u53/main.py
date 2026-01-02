"""Remote plugin for KISA U-53 FTP banner exposure checks."""

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
DEFAULT_VSFTPD_PATHS = ("/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf")
DEFAULT_PROFTPD_PATH = "/etc/proftpd/proftpd.conf"

VSFTPD_BANNER_RE = re.compile(r"^\s*ftpd_banner\s*=\s*(.+)$", re.IGNORECASE)
PROFTPD_IDENT_RE = re.compile(r"^\s*ServerIdent\s+(.+)$", re.IGNORECASE)


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


class FtpBannerExposureCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        check_vsftpd = bool(self.context.config.get("check_vsftpd", True))
        vsftpd_paths = _normalize_list(
            self.context.config.get("vsftpd_conf_paths"),
            "vsftpd_conf_paths",
        ) or list(DEFAULT_VSFTPD_PATHS)
        check_proftpd = bool(self.context.config.get("check_proftpd", True))
        proftpd_path = str(self.context.config.get("proftpd_conf_path") or DEFAULT_PROFTPD_PATH).strip()

        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        if check_vsftpd and os_type == "linux" and not vsftpd_paths:
            raise PluginConfigError("vsftpd_conf_paths must include at least one path")
        if check_proftpd and os_type == "linux" and not proftpd_path:
            raise PluginConfigError("proftpd_conf_path must be a non-empty string")

        client, host = self._get_ssh_client()

        issues: List[Dict[str, object]] = []
        errors: List[Dict[str, str]] = []
        modes: Dict[str, str] = {}
        checked_files = 0
        missing_files = 0

        def handle_result(result: ReadResult) -> Optional[List[str]]:
            nonlocal checked_files, missing_files
            if result.path:
                modes[str(result.path)] = result.mode
            if result.missing:
                missing_files += 1
                return None
            if result.lines is None:
                if result.error:
                    errors.append({"path": str(result.path), "error": result.error})
                return None
            checked_files += 1
            return result.lines

        if check_vsftpd and os_type == "linux":
            for result in self._read_optional_files(vsftpd_paths, client, host):
                lines = handle_result(result)
                if not lines:
                    continue
                status, value, line = self._parse_vsftpd_banner(lines)
                if status in ("missing", "default"):
                    issues.append(
                        {
                            "service": "vsftpd",
                            "issue": f"banner_{status}",
                            "value": value,
                            "line": line,
                            "path": str(result.path) if result.path else None,
                        }
                    )

        if check_proftpd and os_type == "linux":
            result = self._read_config_lines(Path(proftpd_path), client, host)
            lines = handle_result(result)
            if lines:
                status, detail = self._parse_proftpd_ident(lines)
                if status in ("missing", "enabled", "version_exposed"):
                    issues.append(
                        {
                            "service": "proftpd",
                            "issue": f"serverident_{status}",
                            "value": detail.get("value"),
                            "line": detail.get("line"),
                            "path": str(result.path) if result.path else None,
                        }
                    )

        if not issues:
            if checked_files == 0 and errors:
                self._add_unavailable(
                    os_type,
                    {"vsftpd_conf_paths": vsftpd_paths, "proftpd_conf_path": proftpd_path},
                    errors,
                    host,
                )
            return self.results

        limited = issues[:max_results]
        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path(
                {
                    "vsftpd_conf_paths": vsftpd_paths,
                    "proftpd_conf_path": proftpd_path,
                }
            ),
            "mode": self._merge_modes(modes),
            "detected_value": limited,
            "count": len(issues),
            "checked_files": checked_files,
            "missing_files": missing_files,
        }
        if host:
            evidence["host"] = host
        if errors:
            evidence["partial_errors"] = errors[:max_results]

        self.add_finding(
            vuln_id="KISA-U-53",
            title=f"{self._format_os(os_type)} FTP 배너 정보 노출",
            severity="Low",
            evidence=evidence,
            tags=["KISA:U-53"],
            description="FTP 배너 설정이 기본값이거나 버전 정보가 노출됩니다.",
            solution="FTP 배너를 사용자 정의 문구로 변경하고 ServerIdent를 off로 설정하세요.",
        )
        return self.results

    def _parse_vsftpd_banner(self, lines: Sequence[str]) -> Tuple[str, Optional[str], Optional[str]]:
        for raw_line in lines:
            line = _strip_comment(raw_line)
            if not line:
                continue
            match = VSFTPD_BANNER_RE.match(line)
            if not match:
                continue
            value = match.group(1).strip().strip("'\"")
            lowered = value.lower()
            if not value:
                return "default", value, raw_line.strip()
            if "vsftpd" in lowered or "version" in lowered or "%v" in lowered:
                return "default", value, raw_line.strip()
            return "custom", value, raw_line.strip()
        return "missing", None, None

    def _parse_proftpd_ident(self, lines: Sequence[str]) -> Tuple[str, Dict[str, Optional[str]]]:
        for raw_line in lines:
            line = _strip_comment(raw_line)
            if not line:
                continue
            match = PROFTPD_IDENT_RE.match(line)
            if not match:
                continue
            value = match.group(1).strip()
            lowered = value.lower()
            if lowered.startswith("off"):
                return "off", {"value": value, "line": raw_line.strip()}
            if "version" in lowered or "%v" in lowered or "proftpd" in lowered:
                return "version_exposed", {"value": value, "line": raw_line.strip()}
            return "enabled", {"value": value, "line": raw_line.strip()}
        return "missing", {"value": None, "line": None}

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

    def _read_optional_files(
        self,
        paths: Sequence[str],
        client: Optional[SshClient],
        host: Optional[str],
    ) -> List[ReadResult]:
        results = []
        for path in paths:
            if not path:
                continue
            result = self._read_config_lines(Path(path), client, host)
            results.append(result)
        return results

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
            "config_path": self._stringify_config_path(config_path),
        }
        if host:
            evidence["host"] = host
        if errors:
            evidence["error"] = errors[0] if len(errors) == 1 else errors
        self.add_finding(
            vuln_id="KISA-U-53",
            title=f"{self._format_os(os_type)} FTP 배너 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-53"],
            description="FTP 배너 설정 파일을 확인할 수 없습니다.",
            solution="대상 접근 권한과 설정 파일 경로를 확인하세요.",
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
