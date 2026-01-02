"""Remote plugin for KISA U-35 anonymous access restriction checks."""

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
DEFAULT_PASSWD_PATH = "/etc/passwd"
DEFAULT_VSFTPD_PATHS = ("/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf")
DEFAULT_PROFTPD_PATH = "/etc/proftpd/proftpd.conf"
DEFAULT_SAMBA_PATHS = ("/etc/samba/smb.conf", "/usr/lib/smb.conf")
DEFAULT_NFS_PATHS = ("/etc/exports", "/etc/dfs/dfstab")
DEFAULT_FTP_ACCOUNTS = ("ftp", "anonymous")

VSFTPD_ANON_RE = re.compile(r"^\s*anonymous_enable\s*=\s*(\S+)", re.IGNORECASE)
PROFTPD_ANON_RE = re.compile(r"^\s*<\s*anonymous\b", re.IGNORECASE)
SAMBA_GUEST_RE = re.compile(r"^\s*guest\s+ok\s*=\s*(yes|true|1)\b", re.IGNORECASE)
NFS_INSECURE_RE = re.compile(r"\binsecure\b", re.IGNORECASE)
NFS_ANON_RE = re.compile(r"\banon(uid|gid)?\b|\banon=", re.IGNORECASE)


@dataclass
class ReadResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None
    missing: bool = False


def _normalize_list(value, name: str) -> Optional[List[str]]:
    if value is None:
        return None
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


def _parse_passwd_accounts(lines: Sequence[str]) -> Dict[str, str]:
    accounts = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name = parts[0].strip()
        if not name:
            continue
        accounts[name] = raw_line.strip()
    return accounts


class AnonymousAccessRestrictionCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        passwd_path = Path(self.context.config.get("passwd_path") or DEFAULT_PASSWD_PATH)
        check_ftp_accounts = bool(self.context.config.get("check_ftp_accounts", True))
        ftp_account_names = _normalize_list(
            self.context.config.get("ftp_account_names"),
            "ftp_account_names",
        )
        if ftp_account_names is None:
            ftp_account_names = list(DEFAULT_FTP_ACCOUNTS)

        check_vsftpd = bool(self.context.config.get("check_vsftpd", True))
        vsftpd_paths = _normalize_list(
            self.context.config.get("vsftpd_conf_paths"),
            "vsftpd_conf_paths",
        ) or list(DEFAULT_VSFTPD_PATHS)
        check_proftpd = bool(self.context.config.get("check_proftpd", True))
        proftpd_path = str(self.context.config.get("proftpd_conf_path") or DEFAULT_PROFTPD_PATH).strip()

        check_samba = bool(self.context.config.get("check_samba", True))
        samba_paths = _normalize_list(
            self.context.config.get("samba_conf_paths"),
            "samba_conf_paths",
        ) or list(DEFAULT_SAMBA_PATHS)
        check_nfs = bool(self.context.config.get("check_nfs", True))
        nfs_paths = _normalize_list(
            self.context.config.get("nfs_export_paths"),
            "nfs_export_paths",
        ) or list(DEFAULT_NFS_PATHS)

        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        if check_vsftpd and os_type == "linux" and not vsftpd_paths:
            raise PluginConfigError("vsftpd_conf_paths must include at least one path")
        if check_proftpd and os_type == "linux" and not proftpd_path:
            raise PluginConfigError("proftpd_conf_path must be a non-empty string")
        if check_samba and not samba_paths:
            raise PluginConfigError("samba_conf_paths must include at least one path")
        if check_nfs and not nfs_paths:
            raise PluginConfigError("nfs_export_paths must include at least one path")
        if check_ftp_accounts and os_type != "linux" and not ftp_account_names:
            raise PluginConfigError("ftp_account_names must include at least one account")

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
                status, value, line = self._parse_vsftpd(lines)
                if status in ("enabled", "missing", "unknown"):
                    issues.append(
                        {
                            "service": "vsftpd",
                            "issue": f"anonymous_{status}",
                            "value": value,
                            "line": line,
                            "path": str(result.path) if result.path else None,
                        }
                    )

        if check_proftpd and os_type == "linux":
            result = self._read_config_lines(Path(proftpd_path), client, host)
            lines = handle_result(result)
            if lines:
                anon_line = self._find_proftpd_anonymous(lines)
                if anon_line:
                    issues.append(
                        {
                            "service": "proftpd",
                            "issue": "anonymous_section_present",
                            "line": anon_line,
                            "path": str(result.path) if result.path else None,
                        }
                    )

        if check_samba:
            for result in self._read_optional_files(samba_paths, client, host):
                lines = handle_result(result)
                if not lines:
                    continue
                for entry in self._find_samba_guest(lines):
                    issues.append(
                        {
                            "service": "samba",
                            "issue": "guest_ok_enabled",
                            "value": entry.get("value"),
                            "line": entry.get("line"),
                            "path": str(result.path) if result.path else None,
                        }
                    )

        if check_nfs:
            for result in self._read_optional_files(nfs_paths, client, host):
                lines = handle_result(result)
                if not lines:
                    continue
                for entry in self._find_nfs_issues(lines):
                    issues.append(
                        {
                            "service": "nfs",
                            "issue": entry.get("issue"),
                            "line": entry.get("line"),
                            "path": str(result.path) if result.path else None,
                        }
                    )

        if check_ftp_accounts and os_type != "linux":
            result = self._read_config_lines(passwd_path, client, host)
            lines = handle_result(result)
            if lines:
                accounts = _parse_passwd_accounts(lines)
                matches = []
                for name in ftp_account_names:
                    trimmed = name.strip()
                    if not trimmed:
                        continue
                    if trimmed in accounts:
                        matches.append(
                            {
                                "account": trimmed,
                                "line": accounts[trimmed],
                            }
                        )
                if matches:
                    issues.append(
                        {
                            "service": "ftp_accounts",
                            "issue": "anonymous_account_present",
                            "accounts": matches,
                            "path": str(result.path) if result.path else None,
                        }
                    )

        if not issues:
            if errors and checked_files == 0:
                self._add_unavailable(os_type, passwd_path, errors, host)
            return self.results

        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path(
                {
                    "passwd_path": passwd_path,
                    "vsftpd_conf_paths": vsftpd_paths,
                    "proftpd_conf_path": proftpd_path,
                    "samba_conf_paths": samba_paths,
                    "nfs_export_paths": nfs_paths,
                }
            ),
            "mode": self._merge_modes(modes),
            "detected_value": issues[:max_results],
            "count": len(issues),
            "checked_files": checked_files,
            "missing_files": missing_files,
        }
        if host:
            evidence["host"] = host
        if errors:
            evidence["partial_errors"] = errors[:max_results]

        self.add_finding(
            vuln_id="KISA-U-35",
            title=f"{self._format_os(os_type)} 공유 서비스 익명 접근 허용",
            severity="High",
            evidence=evidence,
            tags=["KISA:U-35"],
            description="공유 서비스에서 익명 접근이 허용된 설정이 확인되었습니다.",
            solution="FTP/Samba/NFS의 익명 접근을 차단하고 불필요한 계정을 제거하세요.",
        )
        return self.results

    def _parse_vsftpd(self, lines: Sequence[str]) -> Tuple[str, Optional[str], Optional[str]]:
        last_value = None
        last_line = None
        for raw_line in lines:
            line = _strip_comment(raw_line)
            if not line:
                continue
            match = VSFTPD_ANON_RE.match(line)
            if match:
                last_value = match.group(1)
                last_line = raw_line.strip()
        if last_value is None:
            return "missing", None, None
        normalized = last_value.strip().lower()
        if normalized in ("no", "false", "0"):
            return "disabled", normalized, last_line
        if normalized in ("yes", "true", "1"):
            return "enabled", normalized, last_line
        return "unknown", normalized, last_line

    def _find_proftpd_anonymous(self, lines: Sequence[str]) -> Optional[str]:
        for raw_line in lines:
            line = _strip_comment(raw_line)
            if not line:
                continue
            if PROFTPD_ANON_RE.search(line):
                return raw_line.strip()
        return None

    def _find_samba_guest(self, lines: Sequence[str]) -> List[Dict[str, str]]:
        entries = []
        for raw_line in lines:
            line = _strip_comment(raw_line)
            if not line:
                continue
            match = SAMBA_GUEST_RE.match(line)
            if match:
                entries.append({"value": match.group(1), "line": raw_line.strip()})
        return entries

    def _find_nfs_issues(self, lines: Sequence[str]) -> List[Dict[str, str]]:
        issues = []
        for raw_line in lines:
            line = _strip_comment(raw_line)
            if not line:
                continue
            if NFS_INSECURE_RE.search(line):
                issues.append({"issue": "nfs_insecure", "line": raw_line.strip()})
            if NFS_ANON_RE.search(line):
                issues.append({"issue": "nfs_anon", "line": raw_line.strip()})
        return issues

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
            results.append(self._read_config_lines(Path(path), client, host))
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
                error = result.stderr.strip() or result.stdout.strip() or f"SSH exit code {result.exit_code}"
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

    def _add_unavailable(
        self,
        os_type: str,
        path: Path,
        errors: List[Dict[str, str]],
        host: Optional[str],
    ) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": str(path),
            "mode": "remote",
        }
        if host:
            evidence["host"] = host
        if errors:
            evidence["partial_errors"] = errors

        self.add_finding(
            vuln_id="KISA-U-35",
            title=f"{self._format_os(os_type)} 공유 서비스 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-35"],
            description="공유 서비스 설정을 확인할 수 없습니다.",
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
