"""Remote plugin for KISA U-13 password hash algorithm checks."""

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
DEFAULT_PATHS = {
    "linux": {
        "login_defs": "/etc/login.defs",
        "pam_debian": "/etc/pam.d/common-password",
        "pam_redhat": "/etc/pam.d/system-auth",
    },
    "solaris": {"policy_conf": "/etc/security/policy.conf"},
    "aix": {"login_cfg": "/etc/security/login.cfg"},
}

LINUX_STRONG = {"SHA512", "SHA256"}
SOLARIS_STRONG = {"6", "5", "SHA512", "SHA256"}
AIX_STRONG = {"ssha512", "ssha256"}


@dataclass
class ReadResult:
    lines: Optional[List[str]]
    mode: str
    error: Optional[str] = None
    host: Optional[str] = None
    path: Optional[Path] = None


def _strip_comment(raw_line: str) -> str:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return ""
    if "#" in line:
        line = line.split("#", 1)[0].rstrip()
    return line


def _parse_kv(lines: List[str]) -> Tuple[Dict[str, str], Dict[str, str]]:
    values: Dict[str, str] = {}
    raw_map: Dict[str, str] = {}
    for raw_line in lines:
        line = _strip_comment(raw_line)
        if not line:
            continue
        if "=" in line:
            key, value = [part.strip() for part in line.split("=", 1)]
        else:
            parts = line.split()
            if len(parts) < 2:
                continue
            key, value = parts[0], parts[1]
        if not key:
            continue
        value = value.strip().strip('"').strip("'")
        key_upper = key.upper()
        values[key_upper] = value
        raw_map[key_upper] = raw_line.strip()
    return values, raw_map


def _is_missing_file_error(error: Optional[str]) -> bool:
    if not error:
        return False
    lowered = error.lower()
    return "no such file" in lowered or "not found" in lowered or "cannot access" in lowered


class PasswordHashAlgorithmCheck(BasePlugin):
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
        else:
            self._add_unsupported(os_type)

        return self.results

    def _check_linux(self) -> None:
        login_defs_path = Path(
            self.context.config.get("login_defs_path")
            or DEFAULT_PATHS["linux"]["login_defs"]
        )
        pam_debian_path = Path(
            self.context.config.get("pam_password_path_debian")
            or DEFAULT_PATHS["linux"]["pam_debian"]
        )
        pam_redhat_path = Path(
            self.context.config.get("pam_password_path_redhat")
            or DEFAULT_PATHS["linux"]["pam_redhat"]
        )

        login_defs_result = self._read_config_lines(login_defs_path)
        pam_results, pam_errors = self._read_optional_files(
            [pam_debian_path, pam_redhat_path]
        )

        if login_defs_result.lines is None and not pam_results:
            self._add_unavailable(
                "linux",
                {
                    "login_defs": login_defs_path,
                    "pam_paths": [pam_debian_path, pam_redhat_path],
                },
                [login_defs_result, *pam_errors],
            )
            return

        login_value, login_line = None, None
        login_ok = False
        if login_defs_result.lines is not None:
            values, raw_map = _parse_kv(login_defs_result.lines)
            login_value = values.get("ENCRYPT_METHOD")
            if login_value:
                login_ok = login_value.upper() in LINUX_STRONG
                login_line = raw_map.get("ENCRYPT_METHOD")

        pam_detail = self._scan_pam_hash(pam_results)
        pam_ok = pam_detail["strong"]

        if login_ok or pam_ok:
            return

        evidence = self._base_evidence(
            "linux",
            {
                "login_defs": login_defs_path,
                "pam_paths": [pam_debian_path, pam_redhat_path],
            },
            login_defs_result,
        )
        evidence["mode"] = self._merge_modes(
            {
                "login_defs": login_defs_result.mode,
                **{f"pam_{idx}": res.mode for idx, res in enumerate(pam_results)},
            }
        )
        evidence["detected_value"] = {
            "login_defs": {
                "value": login_value or "missing",
                "line": login_line,
            },
            "pam": pam_detail,
        }
        line = login_line or pam_detail.get("line")
        if line:
            evidence["line"] = line
        host = login_defs_result.host or self._first_host(pam_results)
        if host:
            evidence["host"] = host
        evidence["source"] = "linux"
        self._add_vulnerability("linux", evidence)

    def _check_solaris(self) -> None:
        policy_path = Path(
            self.context.config.get("policy_conf_path")
            or DEFAULT_PATHS["solaris"]["policy_conf"]
        )
        result = self._read_config_lines(policy_path)
        if result.lines is None:
            self._add_unavailable("solaris", policy_path, [result])
            return

        values, raw_map = _parse_kv(result.lines)
        value = values.get("CRYPT_DEFAULT")
        line = raw_map.get("CRYPT_DEFAULT")
        if value and value.upper() in SOLARIS_STRONG:
            return

        evidence = self._base_evidence("solaris", policy_path, result)
        evidence["detected_value"] = {"value": value or "missing", "line": line}
        if line:
            evidence["line"] = line
        evidence["source"] = "solaris"
        self._add_vulnerability("solaris", evidence)

    def _check_aix(self) -> None:
        login_cfg_path = Path(
            self.context.config.get("aix_login_cfg_path")
            or DEFAULT_PATHS["aix"]["login_cfg"]
        )
        result = self._read_config_lines(login_cfg_path)
        if result.lines is None:
            self._add_unavailable("aix", login_cfg_path, [result])
            return

        values, raw_map = _parse_kv(result.lines)
        value = values.get("PWD_ALGORITHM")
        line = raw_map.get("PWD_ALGORITHM")
        if value and value.lower() in AIX_STRONG:
            return

        evidence = self._base_evidence("aix", login_cfg_path, result)
        evidence["detected_value"] = {"value": value or "missing", "line": line}
        if line:
            evidence["line"] = line
        evidence["source"] = "aix"
        self._add_vulnerability("aix", evidence)

    def _scan_pam_hash(self, results: Sequence[ReadResult]) -> Dict[str, object]:
        strong_lines = []
        weak_lines = []
        other_lines = []
        for result in results:
            for raw_line in result.lines or []:
                line = _strip_comment(raw_line)
                if not line:
                    continue
                if "pam_unix.so" not in line:
                    continue
                lowered = line.lower()
                if "sha512" in lowered or "sha256" in lowered:
                    strong_lines.append({"path": str(result.path), "line": raw_line.strip()})
                elif "md5" in lowered or "blowfish" in lowered or "2a" in lowered:
                    weak_lines.append({"path": str(result.path), "line": raw_line.strip()})
                else:
                    other_lines.append({"path": str(result.path), "line": raw_line.strip()})
        detail = {
            "strong": bool(strong_lines),
            "strong_lines": strong_lines,
            "weak_lines": weak_lines,
            "other_lines": other_lines,
        }
        if strong_lines:
            detail["line"] = strong_lines[0]["line"]
        elif weak_lines:
            detail["line"] = weak_lines[0]["line"]
        elif other_lines:
            detail["line"] = other_lines[0]["line"]
        return detail

    def _add_vulnerability(self, os_type: str, evidence: Dict) -> None:
        self.add_finding(
            vuln_id="KISA-U-13",
            title=f"{self._format_os(os_type)} 안전한 비밀번호 암호화 미설정",
            severity="Medium",
            evidence=evidence,
            tags=["KISA:U-13"],
            description="안전한 비밀번호 암호화 알고리즘이 설정되어 있지 않습니다.",
            solution="SHA-256 또는 SHA-512 기반 암호화를 사용하도록 설정하세요.",
        )

    def _add_unavailable(self, os_type: str, path, results: List[ReadResult]) -> None:
        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path(path),
            "mode": self._merge_modes({str(idx): res.mode for idx, res in enumerate(results)}),
        }
        host = self._first_host(results)
        if host:
            evidence["host"] = host
        errors = [res.error for res in results if res.error]
        if errors:
            evidence["error"] = errors[0] if len(errors) == 1 else errors
        self.add_finding(
            vuln_id="KISA-U-13",
            title=f"{self._format_os(os_type)} 암호화 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-13"],
            description="필수 설정 파일을 읽지 못해 점검을 완료할 수 없습니다.",
            solution="대상 접근 권한과 설정 파일 경로를 확인하세요.",
        )

    def _add_unsupported(self, os_type: str) -> None:
        evidence = {"os_type": os_type, "reason": "unsupported_os"}
        self.add_finding(
            vuln_id="KISA-U-13",
            title=f"{self._format_os(os_type)} 암호화 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-13"],
            description="해당 OS는 가이드에 명시된 점검 기준이 없어 진단을 수행할 수 없습니다.",
            solution="OS별 정책 문서를 확인해 점검 기준을 정의하세요.",
        )

    def _read_optional_files(
        self,
        paths: Sequence[Path],
    ) -> Tuple[List[ReadResult], List[ReadResult]]:
        results: List[ReadResult] = []
        errors: List[ReadResult] = []
        for path in paths:
            result = self._read_config_lines(path)
            if result.lines is None:
                if _is_missing_file_error(result.error):
                    continue
                errors.append(result)
                continue
            results.append(result)
        return results, errors

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

    def _base_evidence(self, os_type: str, path, result: ReadResult) -> Dict:
        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path(path),
            "mode": result.mode,
        }
        if result.host:
            evidence["host"] = result.host
        return evidence

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

    def _first_host(self, results: Sequence[ReadResult]) -> Optional[str]:
        for result in results:
            if result.host:
                return result.host
        return None

    def _format_os(self, os_type: str) -> str:
        display = {
            "linux": "Linux",
            "solaris": "Solaris",
            "aix": "AIX",
            "hpux": "HP-UX",
        }
        return display.get(os_type, os_type.upper())
