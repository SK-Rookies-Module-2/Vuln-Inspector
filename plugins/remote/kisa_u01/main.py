"""이 파일은 .py 원격 점검 플러그인 모듈로 root 원격 접속 제한을 검사합니다."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shlex
from typing import Dict, List, Optional, Tuple

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError, PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

ALLOWED_PROTOCOLS = {"ssh", "telnet"}
OS_TYPES = {"linux", "solaris", "aix", "hpux"}
DEFAULT_PATHS = {
    "linux": {"ssh": "/etc/ssh/sshd_config", "telnet": "/etc/securetty"},
    "solaris": {"ssh": "/etc/ssh/sshd_config", "telnet": "/etc/default/login"},
    "aix": {"ssh": "/etc/ssh/sshd_config", "telnet": "/etc/security/user"},
    "hpux": {"ssh": "/opt/ssh/etc/sshd_config", "telnet": "/etc/securetty"},
}


@dataclass
class ReadResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None


def _parse_permit_root_login(lines: List[str]) -> Tuple[Optional[str], Optional[str]]:
    # sshd_config 라인 목록에서 PermitRootLogin 값을 추출한다.
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("permitrootlogin"):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1].lower(), raw_line.strip()
            return None, raw_line.strip()
    return None, None


def _find_linux_telnet_pts(lines: List[str]) -> Optional[str]:
    # /etc/securetty에서 pts 항목이 있으면 취약으로 판단한다.
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("pts/") or "pts/" in line:
            return raw_line.strip()
    return None


def _find_console_entry(lines: List[str]) -> Optional[str]:
    # console 항목 존재 여부를 확인한다.
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "console":
            return raw_line.strip()
    return None


def _parse_solaris_console(lines: List[str]) -> Tuple[Optional[str], Optional[str]]:
    # /etc/default/login에서 CONSOLE 값을 읽는다.
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.upper().startswith("CONSOLE"):
            key, sep, value = line.partition("=")
            if sep:
                return value.strip(), raw_line.strip()
            return None, raw_line.strip()
    return None, None


def _parse_aix_rlogin(lines: List[str]) -> Tuple[Optional[str], Optional[str]]:
    # /etc/security/user에서 root/default 스탠자의 rlogin 값을 찾는다.
    stanzas: Dict[str, Dict[str, str]] = {}
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
            stanzas[current][key.lower()] = value.strip().lower()

    for section in ("root", "default"):
        value = stanzas.get(section, {}).get("rlogin")
        if value is not None:
            return value, section
    return None, None


class RootRemoteLoginCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        protocols = self._normalize_protocols(self.context.config.get("protocols"))
        if not protocols:
            raise PluginConfigError("protocols must include at least one protocol")

        if "ssh" in protocols:
            self._check_ssh(os_type)
        if "telnet" in protocols:
            self._check_telnet(os_type)

        return self.results

    def _normalize_protocols(self, raw_value) -> List[str]:
        if raw_value is None:
            raw_value = ["ssh", "telnet"]
        if isinstance(raw_value, str):
            raw_list = [raw_value]
        elif isinstance(raw_value, list):
            raw_list = raw_value
        else:
            raise PluginConfigError("protocols must be an array of strings")

        normalized = []
        for item in raw_list:
            if not isinstance(item, str):
                raise PluginConfigError("protocols must be an array of strings")
            normalized.append(item.lower())

        invalid = [protocol for protocol in normalized if protocol not in ALLOWED_PROTOCOLS]
        if invalid:
            raise PluginConfigError(f"Unsupported protocols: {sorted(set(invalid))}")
        return normalized

    def _check_ssh(self, os_type: str) -> None:
        config_path = self._resolve_path(os_type, "ssh")
        result = self._read_config_lines(config_path)
        if result.lines is None:
            self._add_unavailable(os_type, "ssh", config_path, result)
            return

        value, line = _parse_permit_root_login(result.lines)
        if value is None or value != "no":
            evidence = self._base_evidence(os_type, "ssh", config_path, result)
            evidence["detected_value"] = value or "missing"
            if line:
                evidence["line"] = line
            self.add_finding(
                vuln_id="KISA-U-01",
                title=f"{self._format_os(os_type)} SSH root 원격 로그인 허용",
                severity="High",
                evidence=evidence,
                tags=["KISA:U-01"],
                description="SSH 설정에서 PermitRootLogin이 no가 아니거나 누락되어 있습니다.",
                solution="sshd_config에서 PermitRootLogin을 no로 설정하고 SSH를 재시작하세요.",
            )

    def _check_telnet(self, os_type: str) -> None:
        config_path = self._resolve_path(os_type, "telnet")
        result = self._read_config_lines(config_path)
        if result.lines is None:
            self._add_unavailable(os_type, "telnet", config_path, result)
            return

        if os_type == "linux":
            line = _find_linux_telnet_pts(result.lines)
            if line:
                evidence = self._base_evidence(os_type, "telnet", config_path, result)
                evidence["detected_value"] = "pts entry"
                evidence["line"] = line
                self._add_telnet_finding(os_type, evidence, "securetty에 pts 항목이 존재합니다.")
        elif os_type == "solaris":
            value, line = _parse_solaris_console(result.lines)
            if value != "/dev/console":
                evidence = self._base_evidence(os_type, "telnet", config_path, result)
                evidence["detected_value"] = value or "missing"
                if line:
                    evidence["line"] = line
                self._add_telnet_finding(os_type, evidence, "CONSOLE=/dev/console 설정이 없거나 다른 값입니다.")
        elif os_type == "aix":
            value, section = _parse_aix_rlogin(result.lines)
            if value != "false":
                evidence = self._base_evidence(os_type, "telnet", config_path, result)
                evidence["detected_value"] = value or "missing"
                if section:
                    evidence["section"] = section
                self._add_telnet_finding(os_type, evidence, "rlogin 값이 false가 아니거나 누락되었습니다.")
        elif os_type == "hpux":
            entry = _find_console_entry(result.lines)
            if entry is None:
                evidence = self._base_evidence(os_type, "telnet", config_path, result)
                evidence["detected_value"] = "console missing"
                self._add_telnet_finding(os_type, evidence, "securetty에 console 항목이 없습니다.")

    def _add_telnet_finding(self, os_type: str, evidence: Dict, reason: str) -> None:
        self.add_finding(
            vuln_id="KISA-U-01",
            title=f"{self._format_os(os_type)} Telnet root 원격 로그인 허용",
            severity="High",
            evidence=evidence,
            tags=["KISA:U-01"],
            description=reason,
            solution=self._telnet_solution(os_type),
        )

    def _add_unavailable(self, os_type: str, protocol: str, path: Path, result: ReadResult) -> None:
        evidence = self._base_evidence(os_type, protocol, path, result)
        if result.error:
            evidence["error"] = result.error
        self.add_finding(
            vuln_id="KISA-U-01",
            title=f"{self._format_os(os_type)} {protocol.upper()} 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-01"],
            description="설정 파일을 읽지 못해 점검을 완료할 수 없습니다.",
            solution="대상 접근 권한과 설정 파일 경로를 확인하세요.",
        )

    def _base_evidence(self, os_type: str, protocol: str, path: Path, result: ReadResult) -> Dict:
        evidence = {
            "os_type": os_type,
            "protocol": protocol,
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
                return ReadResult(None, "remote", str(exc), host)
            if result.exit_code != 0:
                error = result.stderr.strip() or f"SSH exit code {result.exit_code}"
                return ReadResult(None, "remote", error, host)
            return ReadResult(result.stdout.splitlines(), "remote", None, host)

        if allow_local:
            if config_path.exists():
                return ReadResult(config_path.read_text().splitlines(), "local")
            return ReadResult(None, "local", "File not found")

        return ReadResult(None, "remote", "Missing SSH credentials", host)

    def _resolve_path(self, os_type: str, protocol: str) -> Path:
        if protocol == "ssh":
            override = self.context.config.get("sshd_config_path")
        else:
            override = self.context.config.get("telnet_config_path")
        return Path(override or DEFAULT_PATHS[os_type][protocol])

    def _format_os(self, os_type: str) -> str:
        if os_type == "hpux":
            return "HP-UX"
        return os_type.upper()

    def _telnet_solution(self, os_type: str) -> str:
        if os_type in {"linux", "hpux"}:
            return "securetty에서 root 원격 접속을 허용하는 항목을 제거하세요."
        if os_type == "solaris":
            return "CONSOLE=/dev/console을 설정해 root 원격 접속을 콘솔로 제한하세요."
        return "rlogin을 false로 설정해 root 원격 접속을 제한하세요."
