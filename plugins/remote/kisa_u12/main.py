"""Remote plugin for KISA U-12 session timeout checks."""

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
DEFAULT_PROFILE_PATHS = ("/etc/profile", "/etc/bashrc", "/etc/bash.bashrc")
DEFAULT_CSH_PATHS = ("/etc/csh.login", "/etc/csh.cshrc")

TMOUT_RE = re.compile(r"\bTMOUT\s*=\s*([0-9]+)\b", re.IGNORECASE)
EXPORT_TMOUT_RE = re.compile(r"\bexport\s+TMOUT\b", re.IGNORECASE)
AUTOLOGOUT_RE = re.compile(r"\bautologout\b\s*=?\s*([0-9]+)\b", re.IGNORECASE)


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


def _is_missing_file_error(error: Optional[str]) -> bool:
    if not error:
        return False
    lowered = error.lower()
    return "no such file" in lowered or "not found" in lowered or "cannot access" in lowered


class SessionTimeoutCheck(BasePlugin):
    def check(self) -> List[Finding]:
        target_type = str(self.context.target.get("type") or "").upper()
        if target_type and target_type != "SERVER":
            raise PluginConfigError("Target type must be SERVER for remote checks")

        os_type = str(self.context.config.get("os_type", "")).lower().strip()
        if os_type not in OS_TYPES:
            raise PluginConfigError(f"os_type must be one of {sorted(OS_TYPES)}")

        profile_paths = _normalize_list(
            self.context.config.get("profile_paths"),
            "profile_paths",
        ) or list(DEFAULT_PROFILE_PATHS)
        user_profile_paths = _normalize_list(
            self.context.config.get("user_profile_paths"),
            "user_profile_paths",
        )
        csh_paths = _normalize_list(
            self.context.config.get("csh_paths"),
            "csh_paths",
        ) or list(DEFAULT_CSH_PATHS)

        max_timeout_seconds = self._to_positive_int(
            self.context.config.get("max_timeout_seconds", 600),
            "max_timeout_seconds",
        )
        require_export = bool(self.context.config.get("require_tmout_export", True))

        profile_results, profile_errors = self._read_optional_files(
            [*profile_paths, *user_profile_paths]
        )
        csh_results, csh_errors = self._read_optional_files(csh_paths)

        if not profile_results and not csh_results:
            self._add_unavailable(
                os_type,
                {
                    "profile_paths": profile_paths,
                    "user_profile_paths": user_profile_paths,
                    "csh_paths": csh_paths,
                },
                [*profile_errors, *csh_errors],
            )
            return self.results

        tmout_detail = self._evaluate_tmout(
            profile_results,
            max_timeout_seconds,
            require_export,
        )
        autologout_detail = self._evaluate_autologout(
            csh_results,
            max_timeout_seconds,
        )

        issues = []
        if tmout_detail.get("status") not in (None, "ok"):
            issues.append({"source": "tmout", "issue": tmout_detail.get("status")})
        if autologout_detail.get("status") not in (None, "ok"):
            issues.append({"source": "autologout", "issue": autologout_detail.get("status")})

        if not issues:
            return self.results

        evidence = {
            "os_type": os_type,
            "config_path": self._stringify_config_path(
                {
                    "profile_paths": profile_paths,
                    "user_profile_paths": user_profile_paths,
                    "csh_paths": csh_paths,
                }
            ),
            "mode": self._merge_modes(
                {**self._collect_modes(profile_results, "profile"), **self._collect_modes(csh_results, "csh")}
            ),
            "detected_value": {
                "tmout": tmout_detail,
                "autologout": autologout_detail,
                "issues": issues,
            },
            "source": self._format_source(issues),
        }
        line = self._first_issue_line(tmout_detail, autologout_detail)
        if line:
            evidence["line"] = line
        host = self._first_host([*profile_results, *csh_results])
        if host:
            evidence["host"] = host

        self.add_finding(
            vuln_id="KISA-U-12",
            title=f"{self._format_os(os_type)} 세션 종료 시간 미설정",
            severity="Low",
            evidence=evidence,
            tags=["KISA:U-12"],
            description="세션 타임아웃이 없거나 기준값을 초과합니다.",
            solution="TMOUT/ autologout 값을 600초(10분) 이하로 설정하세요.",
        )
        return self.results

    def _evaluate_tmout(
        self,
        results: Sequence[ReadResult],
        max_timeout_seconds: int,
        require_export: bool,
    ) -> Dict:
        if not results:
            return {"status": None, "values": [], "export_present": False}

        values = []
        export_present = False
        for result in results:
            for raw_line in result.lines or []:
                line = _strip_comment(raw_line)
                if not line:
                    continue
                if EXPORT_TMOUT_RE.search(line):
                    export_present = True
                match = TMOUT_RE.search(line)
                if not match:
                    continue
                value = int(match.group(1))
                values.append(
                    {
                        "path": str(result.path) if result.path else None,
                        "value": value,
                        "line": raw_line.strip(),
                    }
                )

        detail = {
            "values": values,
            "export_present": export_present,
            "max_timeout_seconds": max_timeout_seconds,
        }

        if not values:
            detail["status"] = "tmout_missing"
            return detail

        if any(item["value"] <= 0 for item in values):
            detail["status"] = "tmout_invalid"
            return detail

        if any(item["value"] > max_timeout_seconds for item in values):
            detail["status"] = "tmout_too_high"
            return detail

        if require_export and not export_present:
            detail["status"] = "tmout_no_export"
            return detail

        detail["status"] = "ok"
        return detail

    def _evaluate_autologout(
        self,
        results: Sequence[ReadResult],
        max_timeout_seconds: int,
    ) -> Dict:
        if not results:
            return {"status": None, "values": [], "max_timeout_seconds": max_timeout_seconds}

        values = []
        for result in results:
            for raw_line in result.lines or []:
                line = _strip_comment(raw_line)
                if not line:
                    continue
                match = AUTOLOGOUT_RE.search(line)
                if not match:
                    continue
                minutes = int(match.group(1))
                values.append(
                    {
                        "path": str(result.path) if result.path else None,
                        "minutes": minutes,
                        "line": raw_line.strip(),
                    }
                )

        detail = {
            "values": values,
            "max_timeout_seconds": max_timeout_seconds,
        }

        if not values:
            detail["status"] = "autologout_missing"
            return detail

        if any(item["minutes"] <= 0 for item in values):
            detail["status"] = "autologout_invalid"
            return detail

        if any(item["minutes"] * 60 > max_timeout_seconds for item in values):
            detail["status"] = "autologout_too_high"
            return detail

        detail["status"] = "ok"
        return detail

    def _first_issue_line(self, tmout_detail: Dict, autologout_detail: Dict) -> Optional[str]:
        for detail in (tmout_detail, autologout_detail):
            values = detail.get("values") or []
            if values:
                line = values[0].get("line")
                if line:
                    return line
        return None

    def _collect_modes(self, results: Sequence[ReadResult], prefix: str) -> Dict[str, str]:
        return {f"{prefix}_{idx}": result.mode for idx, result in enumerate(results)}

    def _first_host(self, results: Sequence[ReadResult]) -> Optional[str]:
        for result in results:
            if result.host:
                return result.host
        return None

    def _format_source(self, issues: List[Dict[str, str]]) -> str:
        sources = {issue.get("source") for issue in issues if issue.get("source")}
        if len(sources) == 1:
            return next(iter(sources))
        if sources:
            return "mixed"
        return "unknown"

    def _read_optional_files(self, paths: Sequence[str]) -> Tuple[List[ReadResult], List[ReadResult]]:
        results: List[ReadResult] = []
        errors: List[ReadResult] = []
        for raw in paths:
            path = Path(raw)
            result = self._read_config_lines(path)
            if result.lines is None:
                if _is_missing_file_error(result.error):
                    continue
                errors.append(result)
                continue
            results.append(result)
        return results, errors

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
            vuln_id="KISA-U-12",
            title=f"{self._format_os(os_type)} 세션 종료 시간 점검 불가",
            severity="Info",
            evidence=evidence,
            tags=["KISA:U-12"],
            description="프로필 파일을 읽지 못해 점검을 완료할 수 없습니다.",
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

    def _to_positive_int(self, value: object, name: str) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            raise PluginConfigError(f"{name} must be an integer")
        if parsed <= 0:
            raise PluginConfigError(f"{name} must be > 0")
        return parsed

    def _format_os(self, os_type: str) -> str:
        display = {
            "linux": "Linux",
            "solaris": "Solaris",
            "aix": "AIX",
            "hpux": "HP-UX",
        }
        return display.get(os_type, os_type.upper())
