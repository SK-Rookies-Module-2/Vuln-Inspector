"""KISA U-03 계정 잠금 임계값 점검 원격 플러그인."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import shlex
from typing import Dict, List, Optional, Tuple

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
PAM_MODULES = ("pam_tally.so", "pam_tally2.so", "pam_faillock.so")
DEFAULT_PATHS = {
    "linux": {
        "redhat": "/etc/pam.d/system-auth",
        "debian": "/etc/pam.d/common-auth",
    },
    "solaris": {
        "policy_conf": "/etc/security/policy.conf",
        "login": "/etc/default/login",
    },
    "aix": {
        "user": "/etc/security/user",
    },
    "hpux": {
        "trusted": "/tcb/files/auth/system/default",
        "default_security": "/etc/default/security",
    },
}

KV_RE = re.compile(r"^([A-Za-z0-9_.-]+)\s*=\s*(.+)$")
DENY_RE = re.compile(r"\bdeny\s*=\s*([0-9]+)\b", re.IGNORECASE)
UNLOCK_RE = re.compile(r"\bunlock_time\s*=\s*([^\s#]+)", re.IGNORECASE)


@dataclass
class ReadResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None


@dataclass
class PamModuleEntry:
    module: str
    line: str
    deny: Optional[int]
    unlock_time: Optional[str]


def _strip_comment(raw_line: str) -> str:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return ""
    if "#" in line:
        line = line.split("#", 1)[0].rstrip()
    return line


def _parse_last_kv(lines: List[str]) -> Tuple[Dict[str, str], Dict[str, str]]:
    parsed: Dict[str, str] = {}
    raw_map: Dict[str, str] = {}
    for raw_line in lines:
        line = _strip_comment(raw_line)
        if not line:
            continue
        match = KV_RE.match(line)
        if not match:
            continue
        key = match.group(1).strip().upper()
        value = match.group(2).strip()
        parsed[key] = value
        raw_map[key] = raw_line.strip()
    return parsed, raw_map


def _find_pam_module(tokens: List[str]) -> Optional[str]:
    for token in tokens:
        for module in PAM_MODULES:
            if token == module or token.endswith(f"/{module}") or token.endswith(module):
                return module
    return None


def _extract_pam_entries(lines: List[str]) -> List[PamModuleEntry]:
    entries: List[PamModuleEntry] = []
    for raw_line in lines:
        cleaned = _strip_comment(raw_line)
        if not cleaned:
            continue
        tokens = cleaned.split()
        module = _find_pam_module(tokens)
        if not module:
            continue
        deny_match = DENY_RE.search(cleaned)
        unlock_match = UNLOCK_RE.search(cleaned)
        deny_value = int(deny_match.group(1)) if deny_match else None
        unlock_value = unlock_match.group(1) if unlock_match else None
        entries.append(
            PamModuleEntry(
                module=module,
                line=raw_line.strip(),
                deny=deny_value,
                unlock_time=unlock_value,
            )
        )
    return entries


def _to_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _is_missing_file_error(error: Optional[str]) -> bool:
    if not error:
        return False
    lowered = error.lower()
    return "no such file" in lowered or "not found" in lowered or "cannot access" in lowered


class AccountLockoutThresholdCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        if os_type == "linux":
            self._check_linux()
        elif os_type == "solaris":
            self._check_solaris()
        elif os_type == "aix":
            self._check_aix()
        elif os_type == "hpux":
            self._check_hpux()

        return self.results

    def _check_linux(self) -> None:
        redhat_path = Path(
            self.context.config.get("pam_auth_path_redhat")
            or DEFAULT_PATHS["linux"]["redhat"]
        )
        debian_path = Path(
            self.context.config.get("pam_auth_path_debian")
            or DEFAULT_PATHS["linux"]["debian"]
        )
        primary = self._read_config_lines(redhat_path)
        result = primary

        if primary.lines is None and _is_missing_file_error(primary.error):
            secondary = self._read_config_lines(debian_path)
            if secondary.lines is None:
                self._add_unavailable(
                    "linux",
                    [redhat_path, debian_path],
                    [primary, secondary],
                )
                return
            result = secondary
        elif primary.lines is None:
            self._add_unavailable("linux", redhat_path, [primary])
            return

        entries = _extract_pam_entries(result.lines or [])
        if not entries:
            evidence = self._base_evidence("linux", result.path, result)
            evidence["detected_value"] = "missing pam_tally/pam_tally2/pam_faillock"
            self._add_vulnerability(
                os_type="linux",
                evidence=evidence,
                description="PAM 잠금 모듈 설정을 찾지 못했습니다.",
                solution="pam_tally/pam_tally2/pam_faillock에 deny<=10과 unlock_time을 설정하세요.",
            )
            return

        issues: List[Dict[str, object]] = []
        for entry in entries:
            if entry.deny is None:
                issues.append(
                    {
                        "issue": "deny_missing",
                        "module": entry.module,
                        "line": entry.line,
                    }
                )
            elif entry.deny > 10:
                issues.append(
                    {
                        "issue": "deny_too_high",
                        "module": entry.module,
                        "line": entry.line,
                        "value": entry.deny,
                    }
                )
            if entry.unlock_time is None:
                issues.append(
                    {
                        "issue": "unlock_time_missing",
                        "module": entry.module,
                        "line": entry.line,
                    }
                )

        if issues:
            evidence = self._base_evidence("linux", result.path, result)
            evidence["detected_value"] = issues
            evidence["line"] = issues[0].get("line")
            self._add_vulnerability(
                os_type="linux",
                evidence=evidence,
                description="계정 잠금 임계값이 누락되었거나 10회를 초과하거나 unlock_time이 없습니다.",
                solution="PAM 잠금 모듈에 deny<=10과 unlock_time을 설정하세요.",
            )

    def _check_solaris(self) -> None:
        policy_path = Path(
            self.context.config.get("policy_conf_path")
            or DEFAULT_PATHS["solaris"]["policy_conf"]
        )
        login_path = Path(
            self.context.config.get("login_path") or DEFAULT_PATHS["solaris"]["login"]
        )
        policy_result = self._read_config_lines(policy_path)
        if policy_result.lines is None:
            self._add_unavailable("solaris", policy_path, [policy_result])
            return
        login_result = self._read_config_lines(login_path)
        if login_result.lines is None:
            self._add_unavailable("solaris", login_path, [login_result])
            return

        policy_kv, policy_lines = _parse_last_kv(policy_result.lines)
        login_kv, login_lines = _parse_last_kv(login_result.lines)

        lock_value = policy_kv.get("LOCK_AFTER_RETRIES")
        lock_line = policy_lines.get("LOCK_AFTER_RETRIES")
        retries_value = login_kv.get("RETRIES")
        retries_line = login_lines.get("RETRIES")

        lock_ok = bool(lock_value) and lock_value.strip().upper() == "YES"
        retries_int = _to_int(retries_value)
        retries_ok = retries_int is not None and retries_int <= 10

        if not (lock_ok and retries_ok):
            evidence = self._base_evidence(
                "solaris",
                {
                    "policy_conf": policy_path,
                    "login": login_path,
                },
                policy_result,
            )
            evidence["mode"] = self._merge_modes(
                {
                    "policy_conf": policy_result.mode,
                    "login": login_result.mode,
                }
            )
            host = policy_result.host or login_result.host
            if host:
                evidence["host"] = host
            evidence["detected_value"] = {
                "LOCK_AFTER_RETRIES": lock_value,
                "RETRIES": retries_value,
            }
            evidence["line"] = {
                "LOCK_AFTER_RETRIES": lock_line,
                "RETRIES": retries_line,
            }
            self._add_vulnerability(
                os_type="solaris",
                evidence=evidence,
                description="LOCK_AFTER_RETRIES가 YES가 아니거나 RETRIES가 10회를 초과합니다.",
                solution="policy.conf에 LOCK_AFTER_RETRIES=YES, login에 RETRIES<=10으로 설정하세요.",
            )

    def _check_aix(self) -> None:
        user_path = Path(
            self.context.config.get("aix_user_path") or DEFAULT_PATHS["aix"]["user"]
        )
        result = self._read_config_lines(user_path)
        if result.lines is None:
            self._add_unavailable("aix", user_path, [result])
            return

        value, section, line = self._parse_aix_loginretries(result.lines)
        retries_int = _to_int(value)
        if retries_int is None or retries_int > 10:
            evidence = self._base_evidence("aix", result.path, result)
            evidence["detected_value"] = value or "missing"
            evidence["section"] = section
            if line:
                evidence["line"] = line
            self._add_vulnerability(
                os_type="aix",
                evidence=evidence,
                description="loginretries 값이 없거나 10회를 초과합니다.",
                solution="root/default 스탠자의 loginretries를 10 이하로 설정하세요.",
            )

    def _check_hpux(self) -> None:
        trusted_path = Path(
            self.context.config.get("hpux_trusted_path")
            or DEFAULT_PATHS["hpux"]["trusted"]
        )
        default_path = Path(
            self.context.config.get("hpux_default_security_path")
            or DEFAULT_PATHS["hpux"]["default_security"]
        )
        trusted_result = self._read_config_lines(trusted_path)
        result = trusted_result
        source = "trusted"

        if trusted_result.lines is None and _is_missing_file_error(trusted_result.error):
            default_result = self._read_config_lines(default_path)
            if default_result.lines is None:
                self._add_unavailable(
                    "hpux",
                    [trusted_path, default_path],
                    [trusted_result, default_result],
                )
                return
            result = default_result
            source = "default_security"
        elif trusted_result.lines is None:
            self._add_unavailable("hpux", trusted_path, [trusted_result])
            return

        key = "U_MAXTRIES" if source == "trusted" else "AUTH_MAXTRIES"
        kv_map, line_map = _parse_last_kv(result.lines or [])
        value = kv_map.get(key)
        line = line_map.get(key)
        retries_int = _to_int(value)
        if retries_int is None or retries_int > 10:
            evidence = self._base_evidence("hpux", result.path, result)
            evidence["detected_value"] = value or "missing"
            evidence["source"] = source
            if line:
                evidence["line"] = line
            self._add_vulnerability(
                os_type="hpux",
                evidence=evidence,
                description="계정 잠금 임계값이 없거나 10회를 초과합니다.",
                solution="u_maxtries 또는 AUTH_MAXTRIES를 10 이하로 설정하세요.",
            )

    def _parse_aix_loginretries(
        self, lines: List[str]
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        stanzas: Dict[str, Dict[str, str]] = {}
        line_map: Dict[Tuple[str, str], str] = {}
        current: Optional[str] = None
        for raw_line in lines:
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if raw_line.lstrip() == raw_line and stripped.endswith(":"):
                current = stripped[:-1].strip().lower()
                stanzas.setdefault(current, {})
                continue
            if current is None:
                continue
            if "=" in stripped:
                key, value = [part.strip() for part in stripped.split("=", 1)]
                stanzas[current][key.lower()] = value
                line_map[(current, key.lower())] = raw_line.strip()

        for section in ("root", "default"):
            value = stanzas.get(section, {}).get("loginretries")
            if value is not None:
                return value, section, line_map.get((section, "loginretries"))
        return None, None, None

    def _add_unavailable(
        self,
        os_type: str,
        config_path,
        results: List[ReadResult],
    ) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path(config_path),
            "mode": self._merge_modes({str(idx): res.mode for idx, res in enumerate(results)}),
        }
        host = next((res.host for res in results if res.host), None)
        if host:
            evidence["host"] = host
        errors = [res.error for res in results if res.error]
        if errors:
            evidence["error"] = errors[0] if len(errors) == 1 else errors
        self.add_finding(
            vuln_id="KISA-U-03",
            title=f"{self._format_os(os_type)} 계정 잠금 임계값 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-03"],
            description="필수 설정 파일을 읽지 못해 점검을 완료할 수 없습니다.",
            solution="대상 파일 경로와 접근 권한을 확인하세요.",
        )

    def _add_vulnerability(
        self,
        os_type: str,
        evidence: Dict,
        description: str,
        solution: str,
    ) -> None:
        self.add_finding(
            vuln_id="KISA-U-03",
            title=f"{self._format_os(os_type)} 계정 잠금 임계값 설정 미흡",
            severity="High",
            evidence=evidence,
            tags=["KISA:U-03"],
            description=description,
            solution=solution,
        )

    def _base_evidence(self, os_type: str, config_path, result: ReadResult) -> Dict:
        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path(config_path),
            "mode": result.mode,
        }
        if result.host:
            evidence["host"] = result.host
        return evidence

    def _stringify_config_path(self, value):
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, list):
            return [self._stringify_config_path(item) for item in value]
        if isinstance(value, dict):
            return {key: self._stringify_config_path(val) for key, val in value.items()}
        return value

    def _merge_modes(self, modes: Dict[str, str]):
        if not modes:
            return None
        unique = set(modes.values())
        if len(unique) == 1:
            return next(iter(unique))
        return modes

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
                return ReadResult(config_path.read_text().splitlines(), "local", None, None, config_path)
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
