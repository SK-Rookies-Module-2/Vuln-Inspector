"""KISA U-04 비밀번호 파일 보호 점검 원격 플러그인."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shlex
from typing import Dict, List, Optional, Tuple

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_PATHS = {
    "linux": {"passwd": "/etc/passwd", "shadow": "/etc/shadow"},
    "solaris": {"passwd": "/etc/passwd", "shadow": "/etc/shadow"},
    "aix": {"security_passwd": "/etc/security/passwd"},
    "hpux": {"tcb_dir": "/tcb/files/auth", "shadow": "/etc/shadow"},
}


@dataclass
class ReadResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None


@dataclass
class PathCheckResult:
    exists: Optional[bool]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None


def _find_passwd_non_shadow(lines: List[str]) -> Tuple[Optional[str], Optional[str]]:
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2:
            continue
        if parts[1] != "x":
            return parts[1], raw_line.strip()
    return None, None


class PasswordFileProtectionCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        if os_type in {"linux", "solaris"}:
            self._check_passwd_shadow(os_type)
        elif os_type == "aix":
            self._check_aix_security_passwd()
        elif os_type == "hpux":
            self._check_hpux_trusted_mode()

        return self.results

    def _check_passwd_shadow(self, os_type: str) -> None:
        passwd_path = Path(
            self.context.config.get("passwd_path") or DEFAULT_PATHS[os_type]["passwd"]
        )
        shadow_path = Path(
            self.context.config.get("shadow_path") or DEFAULT_PATHS[os_type]["shadow"]
        )
        passwd_result = self._read_config_lines(passwd_path)
        if passwd_result.lines is None:
            self._add_unavailable(os_type, passwd_path, [passwd_result])
            return

        shadow_result = self._check_path_exists(shadow_path, is_dir=False)
        passwd_value, passwd_line = _find_passwd_non_shadow(passwd_result.lines)

        issues: List[str] = []
        detected: Dict[str, object] = {}
        if passwd_value is not None:
            issues.append("/etc/passwd 두 번째 필드가 x가 아님")
            detected["passwd_field"] = passwd_value or "missing"
        if shadow_result.exists is False:
            issues.append("/etc/shadow 파일이 존재하지 않음")
            detected["shadow_exists"] = False

        if issues:
            evidence = self._base_evidence(
                os_type,
                {"passwd": passwd_path, "shadow": shadow_path},
                passwd_result,
            )
            evidence["mode"] = self._merge_modes(
                {"passwd": passwd_result.mode, "shadow": shadow_result.mode}
            )
            host = passwd_result.host or shadow_result.host
            if host:
                evidence["host"] = host
            evidence["detected_value"] = detected
            evidence["issues"] = issues
            if passwd_line:
                evidence["line"] = passwd_line
            self._add_vulnerability(
                os_type=os_type,
                evidence=evidence,
                description="; ".join(issues),
                solution="쉐도우 비밀번호 사용 여부를 확인하고 /etc/passwd의 두 번째 필드를 x로 유지하세요.",
            )
            return

        if shadow_result.exists is None:
            self._add_unavailable(
                os_type,
                {"passwd": passwd_path, "shadow": shadow_path},
                [shadow_result],
            )

    def _check_aix_security_passwd(self) -> None:
        passwd_path = Path(
            self.context.config.get("aix_security_passwd_path")
            or DEFAULT_PATHS["aix"]["security_passwd"]
        )
        result = self._read_config_lines(passwd_path)
        if result.lines is None:
            self._add_unavailable("aix", passwd_path, [result])
            return

        value, section, line = self._parse_aix_password(result.lines)
        if value is None or not str(value).strip():
            evidence = self._base_evidence("aix", passwd_path, result)
            evidence["detected_value"] = value or "missing"
            if section:
                evidence["section"] = section
            if line:
                evidence["line"] = line
            self._add_vulnerability(
                os_type="aix",
                evidence=evidence,
                description="AIX 보안 비밀번호 파일에 암호화된 비밀번호가 없습니다.",
                solution="root/default 스탠자에 암호화된 password 값을 설정하세요.",
            )

    def _check_hpux_trusted_mode(self) -> None:
        tcb_dir = Path(
            self.context.config.get("hpux_tcb_dir") or DEFAULT_PATHS["hpux"]["tcb_dir"]
        )
        shadow_path = Path(
            self.context.config.get("hpux_shadow_path") or DEFAULT_PATHS["hpux"]["shadow"]
        )
        tcb_result = self._check_path_exists(tcb_dir, is_dir=True)
        shadow_result = self._check_path_exists(shadow_path, is_dir=False)

        if tcb_result.exists is True or shadow_result.exists is True:
            return

        if tcb_result.exists is False and shadow_result.exists is False:
            evidence = self._base_evidence(
                "hpux",
                {"tcb_dir": tcb_dir, "shadow": shadow_path},
                tcb_result,
            )
            evidence["mode"] = self._merge_modes(
                {"tcb_dir": tcb_result.mode, "shadow": shadow_result.mode}
            )
            host = tcb_result.host or shadow_result.host
            if host:
                evidence["host"] = host
            evidence["detected_value"] = {"tcb_dir": False, "shadow_exists": False}
            self._add_vulnerability(
                os_type="hpux",
                evidence=evidence,
                description="Trusted Mode 디렉터리와 /etc/shadow 파일이 모두 없습니다.",
                solution="Trusted Mode를 활성화하거나 /etc/shadow를 사용하도록 설정하세요.",
            )
            return

        self._add_unavailable(
            "hpux",
            {"tcb_dir": tcb_dir, "shadow": shadow_path},
            [tcb_result, shadow_result],
        )

    def _parse_aix_password(
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
            value = stanzas.get(section, {}).get("password")
            if value is not None:
                return value, section, line_map.get((section, "password"))
        return None, None, None

    def _add_unavailable(self, os_type: str, config_path, results) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path(config_path),
            "mode": self._merge_modes(
                {str(idx): res.mode for idx, res in enumerate(results)}
            ),
        }
        host = next((res.host for res in results if res.host), None)
        if host:
            evidence["host"] = host
        errors = [res.error for res in results if res.error]
        if errors:
            evidence["error"] = errors[0] if len(errors) == 1 else errors
        self.add_finding(
            vuln_id="KISA-U-04",
            title=f"{self._format_os(os_type)} 비밀번호 파일 보호 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-04"],
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
            vuln_id="KISA-U-04",
            title=f"{self._format_os(os_type)} 비밀번호 파일 보호 미흡",
            severity="High",
            evidence=evidence,
            tags=["KISA:U-04"],
            description=description,
            solution=solution,
        )

    def _base_evidence(self, os_type: str, config_path, result) -> Dict:
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

    def _check_path_exists(self, path: Path, is_dir: bool) -> PathCheckResult:
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
                flag = "-d" if is_dir else "-f"
                command = f"test {flag} {shlex.quote(str(path))}"
                result = client.run(command)
            except AdapterError as exc:
                return PathCheckResult(None, "remote", str(exc), host, path)
            if result.exit_code == 0:
                return PathCheckResult(True, "remote", None, host, path)
            if result.exit_code == 1 and not result.stderr.strip():
                return PathCheckResult(False, "remote", None, host, path)
            error = result.stderr.strip() or f"SSH exit code {result.exit_code}"
            return PathCheckResult(None, "remote", error, host, path)

        if allow_local:
            exists = path.is_dir() if is_dir else path.is_file()
            return PathCheckResult(exists, "local", None, None, path)

        return PathCheckResult(None, "remote", "Missing SSH credentials", host, path)

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
