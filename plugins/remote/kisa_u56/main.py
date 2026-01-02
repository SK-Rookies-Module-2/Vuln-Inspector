"""Remote plugin for KISA U-56 FTP access control checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import shlex
from typing import Dict, List, Optional, Sequence

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding
from plugins.remote.utils.text import parse_kv_lines, strip_comments

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_VSFTPD_CONF_PATH = "/etc/vsftpd.conf"
DEFAULT_VSFTPD_USERLIST_FILES = (
    "/etc/vsftpd.ftpusers",
    "/etc/vsftpd/user_list",
    "/etc/ftpusers",
)
DEFAULT_PROFTPD_CONF_PATHS = (
    "/etc/proftpd.conf",
    "/etc/proftpd/proftpd.conf",
)
DEFAULT_HOSTS_ALLOW_PATH = "/etc/hosts.allow"
DEFAULT_HOSTS_DENY_PATH = "/etc/hosts.deny"
FTP_TOKENS = {"ftp", "ftpd", "vsftpd", "proftpd"}


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


def _is_truthy(value: Optional[str]) -> bool:
    if value is None:
        return False
    return value.strip().lower() in ("yes", "true", "1", "on")


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


def _tokenize(text: str) -> List[str]:
    return [token for token in re.split(r"[^a-zA-Z0-9]+", text.lower()) if token]


def _line_has_token(line: str, tokens: Sequence[str]) -> bool:
    for token in _tokenize(line):
        if token in tokens:
            return True
    return False


def _find_limit_login(lines: List[str]) -> Optional[str]:
    for raw_line in lines:
        if re.search(r"(?i)\blimit\s+login\b", raw_line):
            return raw_line
    return None


def _has_all_all(line: str) -> bool:
    return re.search(r"(?i)\ball\s*:\s*all\b", line) is not None


class FtpAccessControlCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        vsftpd_conf_path = Path(
            self.context.config.get("vsftpd_conf_path") or DEFAULT_VSFTPD_CONF_PATH
        )
        vsftpd_userlist_files = _normalize_list(
            self.context.config.get("vsftpd_userlist_files"),
            "vsftpd_userlist_files",
        ) or list(DEFAULT_VSFTPD_USERLIST_FILES)
        proftpd_conf_paths = _normalize_list(
            self.context.config.get("proftpd_conf_paths"),
            "proftpd_conf_paths",
        ) or list(DEFAULT_PROFTPD_CONF_PATHS)
        hosts_allow_path = Path(
            self.context.config.get("hosts_allow_path") or DEFAULT_HOSTS_ALLOW_PATH
        )
        hosts_deny_path = Path(
            self.context.config.get("hosts_deny_path") or DEFAULT_HOSTS_DENY_PATH
        )

        check_vsftpd = bool(self.context.config.get("check_vsftpd", True))
        check_proftpd = bool(self.context.config.get("check_proftpd", True))
        check_tcp_wrapper = bool(self.context.config.get("check_tcp_wrapper", True))
        max_results = self._to_positive_int(self.context.config.get("max_results", 200), "max_results")

        issues: List[Dict[str, object]] = []
        errors: List[str] = []
        modes: Dict[str, str] = {}
        access_ok = False

        if check_vsftpd:
            vsftpd_result = self._check_vsftpd(vsftpd_conf_path, vsftpd_userlist_files)
            modes.update(vsftpd_result["modes"])
            errors.extend(vsftpd_result["errors"])
            if vsftpd_result["ok"]:
                access_ok = True
            elif vsftpd_result["issues"]:
                issues.extend(vsftpd_result["issues"])

        if check_proftpd:
            proftpd_result = self._check_proftpd(proftpd_conf_paths)
            modes.update(proftpd_result["modes"])
            errors.extend(proftpd_result["errors"])
            if proftpd_result["ok"]:
                access_ok = True
            elif proftpd_result["issues"]:
                issues.extend(proftpd_result["issues"])

        if check_tcp_wrapper:
            tcp_result = self._check_tcp_wrapper(hosts_allow_path, hosts_deny_path)
            modes.update(tcp_result["modes"])
            errors.extend(tcp_result["errors"])
            if tcp_result["ok"]:
                access_ok = True
            elif tcp_result["issues"]:
                issues.extend(tcp_result["issues"])

        if access_ok:
            return self.results

        if issues:
            evidence = {
                "os_type": os_type,
                "config_path": {
                    "vsftpd_conf_path": str(vsftpd_conf_path),
                    "vsftpd_userlist_files": vsftpd_userlist_files,
                    "proftpd_conf_paths": proftpd_conf_paths,
                    "hosts_allow_path": str(hosts_allow_path),
                    "hosts_deny_path": str(hosts_deny_path),
                },
                "mode": self._merge_modes(modes),
                "detected_value": issues[:max_results],
                "count": len(issues),
            }
            if errors:
                evidence["partial_errors"] = errors[:max_results]

            self.add_finding(
                vuln_id="KISA-U-56",
                title=f"{self._format_os(os_type)} FTP 접근 제어 미설정",
                severity="Low",
                evidence=evidence,
                tags=["KISA:U-56"],
                description="FTP 접근 제어 설정을 확인할 수 없거나 설정이 미흡합니다.",
                solution="ftpusers/userlist 또는 Limit LOGIN/TCP Wrapper로 접근을 제한하세요.",
            )
            return self.results

        if errors:
            self._add_unavailable(
                os_type,
                {
                    "vsftpd_conf_path": str(vsftpd_conf_path),
                    "proftpd_conf_paths": proftpd_conf_paths,
                    "hosts_allow_path": str(hosts_allow_path),
                    "hosts_deny_path": str(hosts_deny_path),
                },
                errors,
                modes,
            )

        return self.results

    def _check_vsftpd(self, conf_path: Path, userlist_files: Sequence[str]) -> Dict[str, object]:
        result = {"ok": False, "issues": [], "errors": [], "modes": {}}
        read_result = self._read_lines(conf_path)
        result["modes"]["vsftpd_conf"] = read_result.mode
        if read_result.missing:
            return result
        if read_result.lines is None:
            result["errors"].append(read_result.error or "Failed to read vsftpd config")
            return result

        settings = {
            key.lower(): value.strip()
            for key, value in parse_kv_lines(read_result.lines).items()
        }
        userlist_enable = settings.get("userlist_enable")
        userlist_deny = settings.get("userlist_deny")
        userlist_file = settings.get("userlist_file")

        vsftpd_issues = []
        if not _is_truthy(userlist_enable):
            vsftpd_issues.append("userlist_enable_disabled")
        if userlist_deny is None:
            vsftpd_issues.append("userlist_deny_missing")

        file_found = None
        if _is_truthy(userlist_enable):
            candidates = [userlist_file] if userlist_file else list(userlist_files)
            had_error = False
            for candidate in candidates:
                if not candidate:
                    continue
                file_result = self._read_lines(Path(candidate))
                result["modes"][f"userlist:{candidate}"] = file_result.mode
                if file_result.missing:
                    continue
                if file_result.lines is None:
                    had_error = True
                    result["errors"].append(
                        file_result.error or f"Failed to read {candidate}"
                    )
                    continue
                file_found = candidate
                break
            if not file_found and not had_error:
                vsftpd_issues.append("userlist_file_missing")

        if not vsftpd_issues and file_found:
            result["ok"] = True
        elif vsftpd_issues:
            result["issues"].append(
                {
                    "source": "vsftpd",
                    "path": str(conf_path),
                    "userlist_enable": userlist_enable,
                    "userlist_deny": userlist_deny,
                    "userlist_file": userlist_file or file_found,
                    "issues": vsftpd_issues,
                }
            )
        return result

    def _check_proftpd(self, conf_paths: Sequence[str]) -> Dict[str, object]:
        result = {"ok": False, "issues": [], "errors": [], "modes": {}}
        present_paths = []
        readable_paths = []
        for path in conf_paths:
            if not path:
                continue
            read_result = self._read_lines(Path(path))
            result["modes"][f"proftpd:{path}"] = read_result.mode
            if read_result.missing:
                continue
            present_paths.append(path)
            if read_result.lines is None:
                result["errors"].append(read_result.error or f"Failed to read {path}")
                continue
            readable_paths.append(path)
            line = _find_limit_login(read_result.lines)
            if line:
                result["ok"] = True
                return result

        if readable_paths and present_paths:
            result["issues"].append(
                {
                    "source": "proftpd",
                    "paths": readable_paths,
                    "issue": "limit_login_missing",
                }
            )
        return result

    def _check_tcp_wrapper(self, allow_path: Path, deny_path: Path) -> Dict[str, object]:
        result = {"ok": False, "issues": [], "errors": [], "modes": {}}
        allow_result = self._read_lines(allow_path)
        deny_result = self._read_lines(deny_path)
        result["modes"]["hosts_allow"] = allow_result.mode
        result["modes"]["hosts_deny"] = deny_result.mode

        allow_lines = allow_result.lines or []
        deny_lines = deny_result.lines or []
        present = not allow_result.missing or not deny_result.missing
        readable = False

        if allow_result.lines is None and not allow_result.missing:
            result["errors"].append(allow_result.error or "Failed to read hosts.allow")
        elif allow_result.lines is not None:
            readable = True
        if deny_result.lines is None and not deny_result.missing:
            result["errors"].append(deny_result.error or "Failed to read hosts.deny")
        elif deny_result.lines is not None:
            readable = True

        allow_matches = [line for line in allow_lines if _line_has_token(line, FTP_TOKENS)]
        deny_matches = [line for line in deny_lines if _line_has_token(line, FTP_TOKENS)]
        deny_all = any(_has_all_all(line) for line in deny_lines)

        if allow_matches or deny_matches or deny_all:
            result["ok"] = True
            return result

        if present and readable:
            result["issues"].append(
                {
                    "source": "tcp_wrapper",
                    "hosts_allow_path": str(allow_path),
                    "hosts_deny_path": str(deny_path),
                    "issue": "no_ftp_entries",
                }
            )
        return result

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

    def _add_unavailable(self, os_type: str, config_path: Dict, errors: List[str], modes: Dict[str, str]) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": config_path,
            "mode": self._merge_modes(modes),
        }
        if errors:
            evidence["error"] = errors[0]
            evidence["errors"] = errors

        self.add_finding(
            vuln_id="KISA-U-56",
            title=f"{self._format_os(os_type)} FTP 접근 제어 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-56"],
            description="FTP 접근 제어 설정을 확인할 수 없습니다.",
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

    def _format_os(self, os_type: str) -> str:
        display = {
            "linux": "Linux",
            "solaris": "Solaris",
            "aix": "AIX",
            "hpux": "HP-UX",
        }
        return display.get(os_type, os_type.upper())
