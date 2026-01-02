"""Remote plugin for KISA U-51 DNS dynamic update checks."""

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
DEFAULT_NAMED_CONF_PATHS = ("/etc/named.conf", "/etc/bind/named.conf.options")

ALLOW_UPDATE_BLOCK_RE = re.compile(r"allow-update\s*\{([^}]*)\}", re.IGNORECASE | re.DOTALL)
ALLOW_UPDATE_STATEMENT_RE = re.compile(r"allow-update\s+([^;]+);", re.IGNORECASE)
ALLOW_UPDATE_KEYWORD_RE = re.compile(r"allow-update", re.IGNORECASE)

ANY_TOKENS = {"any", "0.0.0.0/0", "::/0"}
NONE_TOKENS = {"none"}


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


def _sanitize_config_lines(lines: Sequence[str]) -> str:
    text = "\n".join(lines)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    cleaned = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "//" in line:
            line = line.split("//", 1)[0].rstrip()
        if "#" in line:
            line = line.split("#", 1)[0].rstrip()
        if not line:
            continue
        cleaned.append(line)
    return "\n".join(cleaned)


def _extract_allow_update_entries(text: str) -> Tuple[List[Dict[str, str]], bool]:
    entries: List[Dict[str, str]] = []
    for match in ALLOW_UPDATE_BLOCK_RE.finditer(text):
        raw = " ".join(match.group(0).split())
        value = match.group(1)
        entries.append({"raw": raw, "value": value})

    stripped = ALLOW_UPDATE_BLOCK_RE.sub(" ", text)
    for match in ALLOW_UPDATE_STATEMENT_RE.finditer(stripped):
        raw = " ".join(match.group(0).split())
        value = match.group(1)
        entries.append({"raw": raw, "value": value})

    return entries, bool(ALLOW_UPDATE_KEYWORD_RE.search(text))


def _tokenize_allow_update(value: str) -> List[str]:
    tokens = []
    for item in re.split(r"[;\s]+", value.strip()):
        if not item:
            continue
        tokens.append(item.lower())
    return tokens


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


class DnsDynamicUpdateCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        named_conf_paths = _normalize_list(
            self.context.config.get("named_conf_paths"),
            "named_conf_paths",
        ) or list(DEFAULT_NAMED_CONF_PATHS)
        named_conf_paths = [path.strip() for path in named_conf_paths if path.strip()]
        if not named_conf_paths:
            raise PluginConfigError("named_conf_paths must include at least one path")

        max_results = self._to_positive_int(
            self.context.config.get("max_results", 200),
            "max_results",
        )

        client, host = self._get_ssh_client()

        issues: List[Dict[str, object]] = []
        errors: List[ReadResult] = []
        missing_files: List[str] = []
        modes: Dict[str, str] = {}
        checked_files = 0
        config_present = False

        entries: List[Dict[str, object]] = []
        any_keyword = False
        unparsed_files: List[str] = []

        for raw_path in named_conf_paths:
            path = Path(raw_path)
            result = self._read_config_lines(path, client, host)
            modes[str(path)] = result.mode
            if result.host:
                host = host or result.host
            if result.lines is None:
                if result.missing:
                    missing_files.append(str(path))
                    checked_files += 1
                else:
                    errors.append(result)
                continue

            checked_files += 1
            config_present = True
            sanitized = _sanitize_config_lines(result.lines)
            file_entries, has_keyword = _extract_allow_update_entries(sanitized)
            if has_keyword:
                any_keyword = True
            if file_entries:
                for entry in file_entries:
                    entries.append({**entry, "path": str(path)})
            else:
                if has_keyword:
                    unparsed_files.append(str(path))

        for entry in entries:
            tokens = _tokenize_allow_update(str(entry.get("value") or ""))
            if not tokens:
                issues.append(
                    {
                        "path": entry.get("path"),
                        "issue": "allow_update_empty",
                        "statement": entry.get("raw"),
                    }
                )
                continue
            if any(token in ANY_TOKENS for token in tokens):
                issues.append(
                    {
                        "path": entry.get("path"),
                        "issue": "allow_update_any",
                        "statement": entry.get("raw"),
                        "tokens": tokens,
                    }
                )
                continue
            if any(token in NONE_TOKENS for token in tokens):
                continue

        if unparsed_files:
            for path in unparsed_files:
                issues.append(
                    {
                        "path": path,
                        "issue": "allow_update_unparsed",
                    }
                )

        if config_present and not entries and not any_keyword:
            issues.append(
                {
                    "issue": "allow_update_missing",
                    "paths": named_conf_paths,
                }
            )

        if not issues:
            if not config_present and errors:
                self._add_unavailable(os_type, named_conf_paths, errors)
            return self.results

        evidence = {
            "os_type": os_type,
            "config_path": {"named_conf_paths": named_conf_paths},
            "mode": self._merge_modes(modes),
            "detected_value": issues[:max_results],
            "count": len(issues),
            "checked_files": checked_files,
        }
        if host:
            evidence["host"] = host
        if missing_files:
            evidence["missing_files"] = missing_files
        if errors:
            evidence["partial_errors"] = [err.error for err in errors if err.error][:max_results]

        self.add_finding(
            vuln_id="KISA-U-51",
            title=f"{self._format_os(os_type)} DNS 동적 업데이트 제한 미흡",
            severity="Medium",
            evidence=evidence,
            tags=["KISA:U-51"],
            description="allow-update 설정이 안전하게 구성되어 있지 않습니다.",
            solution="allow-update를 none 또는 승인된 IP/key로 제한하세요.",
        )
        return self.results

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
                error = (result.stderr or result.stdout or "").strip()
                if _is_missing_error(error):
                    return ReadResult(None, "remote", error or "File not found", host, config_path, True)
                return ReadResult(None, "remote", error or f"SSH exit code {result.exit_code}", host, config_path)
            return ReadResult(result.stdout.splitlines(), "remote", None, host, config_path)

        if allow_local:
            if not config_path.exists():
                return ReadResult(None, "local", "File not found", None, config_path, True)
            try:
                lines = config_path.read_text().splitlines()
            except OSError as exc:
                return ReadResult(None, "local", str(exc), None, config_path)
            return ReadResult(lines, "local", None, None, config_path)

        return ReadResult(None, "remote", "Missing SSH credentials", host, config_path)

    def _add_unavailable(
        self,
        os_type: str,
        config_paths: Sequence[str],
        errors: List[ReadResult],
    ) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": {"named_conf_paths": list(config_paths)},
            "mode": self._merge_modes(
                {
                    str(idx): err.mode
                    for idx, err in enumerate(errors)
                    if getattr(err, "mode", None)
                }
            ),
        }
        host = next((err.host for err in errors if getattr(err, "host", None)), None)
        if host:
            evidence["host"] = host
        error_list = [err.error for err in errors if err.error]
        if error_list:
            evidence["error"] = error_list[0]
            evidence["errors"] = error_list

        self.add_finding(
            vuln_id="KISA-U-51",
            title=f"{self._format_os(os_type)} DNS 설정 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-51"],
            description="named 설정 파일을 확인할 수 없습니다.",
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
