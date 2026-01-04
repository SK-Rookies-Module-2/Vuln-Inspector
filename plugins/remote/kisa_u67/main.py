"""
KISA U-67 로그 파일 소유자/권한 점검 플러그인
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.adapters.ssh import SshClient
from app.core.errors import PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

from plugins.remote.utils.report import build_report

DEFAULT_LOG_DIR = "/var/log"
DEFAULT_OWNER = "root"
DEFAULT_ALLOWED_OWNERS = ["root", "syslog"]
DEFAULT_MAX_MODE = "0644"
DEFAULT_MAX_SHOW = 20
DEFAULT_MAX_ENTRIES = 300

U67_META = {
    "log_owner": {
        "label": "로그 파일 소유자",
        "where": "/var/log/*",
        "fix": "chown root /var/log/<파일 이름>",
    },
    "log_mode": {
        "label": "로그 파일 권한",
        "where": "/var/log/*",
        "fix": "chmod 644 /var/log/<파일 이름>",
    },
}


def _build_ssh_client(target: Dict[str, Any], cfg: Dict[str, Any]) -> SshClient:
    connection = target.get("connection_info", {}) or {}
    credentials = target.get("credentials", {}) or {}

    host = connection.get("host") or connection.get("ip")
    user = credentials.get("username")
    key_path = credentials.get("key_path")
    password = credentials.get("password")
    port = int(connection.get("port", 22))
    proxy_jump = connection.get("proxy_jump")
    proxy_command = connection.get("proxy_command")
    identities_only = bool(connection.get("identities_only", False))

    if not host or not user:
        raise PluginConfigError("SSH host/username가 필요합니다.")
    if not key_path and not password:
        raise PluginConfigError("SSH key_path 또는 password가 필요합니다.")

    return SshClient(
        host=host,
        user=user,
        key_path=key_path,
        password=password,
        port=port,
        proxy_jump=proxy_jump,
        proxy_command=proxy_command,
        identities_only=identities_only,
        sudo=bool(cfg.get("use_sudo", False)),
        sudo_user=cfg.get("sudo_user"),
    )


def _parse_mode_to_int(mode_str: str) -> Optional[int]:
    try:
        s = str(mode_str).strip()
        if not s:
            return None
        return int(s, 8)
    except Exception:
        return None


def _is_mode_too_open(mode_int: Optional[int], max_mode_int: int) -> bool:
    """
    max_mode_int(예: 0o644)에 비해 추가로 열린 권한 비트가 있으면 True.
    - 0600 OK (더 엄격)
    - 0644 OK
    - 0664 FAIL (group write 추가)
    """
    if mode_int is None:
        return True
    return (mode_int & ~max_mode_int) != 0


def _parse_find_output(lines: List[str]) -> List[Dict[str, Any]]:
    """
    find 출력 파싱 → dict 기반 엔트리 목록
    """
    entries: List[Dict[str, Any]] = []
    for raw in lines:
        if not raw.strip():
            continue
        parts = raw.split("\t")
        if len(parts) < 3:
            continue

        path = parts[0].strip()
        owner = parts[1].strip()
        mode_str = parts[2].strip()
        mode_int = _parse_mode_to_int(mode_str)

        entries.append(
            {
                "path": path,
                "owner": owner,
                "mode_str": mode_str,
                "mode_int": mode_int,
            }
        )
    return entries


def _to_allowed_owners(cfg: Dict[str, Any]) -> List[str]:
    """
    - allowed_owners 우선
    - 없으면 expected_owner (legacy)
    - 둘 다 없거나 비면 DEFAULT_ALLOWED_OWNERS
    """
    raw = cfg.get("allowed_owners", None)

    if raw is None:
        expected_owner = str(cfg.get("expected_owner", DEFAULT_OWNER)).strip()
        if expected_owner:
            owners = [expected_owner]
        else:
            owners = DEFAULT_ALLOWED_OWNERS[:]
    elif isinstance(raw, str):
        owners = [raw.strip()]
    else:
        owners = [str(x).strip() for x in raw if str(x).strip()]

    owners = [o for o in owners if o]
    return owners if owners else DEFAULT_ALLOWED_OWNERS[:]


def u67_severity(diagnose: Dict[str, Any]) -> str:
    return "High" if diagnose.get("is_vulnerable") else "Info"


def _format_list_lines(items: List[Dict[str, Any]], fmt) -> str:
    """
    fmt(item) -> str
    """
    max_show = DEFAULT_MAX_SHOW
    shown = items[:max_show]
    body = "\n".join([fmt(x) for x in shown])
    if len(items) > max_show:
        body += f"\n  ... +{len(items) - max_show} more"
    return body


def _append_detail_to_report(report: Dict[str, Any], wrong_owner: List[Dict[str, Any]], wrong_mode: List[Dict[str, Any]]) -> None:
    """
    build_report 결과(description/solution)에
    문제 파일 목록과 수정 명령 예시를 추가로 덧붙인다.
    """
    extra_desc: List[str] = []
    if wrong_owner:
        extra_desc.append("[소유자 불일치 파일]")
        extra_desc.append(
            _format_list_lines(
                wrong_owner,
                lambda e: f"  - {e['path']} (owner: {e['owner']})",
            )
        )
    if wrong_mode:
        extra_desc.append("[권한 과다 파일]")
        extra_desc.append(
            _format_list_lines(
                wrong_mode,
                lambda e: f"  - {e['path']} (mode: {e['mode_str']})",
            )
        )

    if extra_desc:
        report["description"] = report["description"].rstrip() + "\n\n" + "\n".join(extra_desc)

    extra_sol: List[str] = []
    if wrong_owner:
        extra_sol.append("[소유자 수정 명령 예시]")
        extra_sol.append(
            _format_list_lines(
                wrong_owner,
                lambda e: f"chown root {e['path']}",
            )
        )
    if wrong_mode:
        extra_sol.append("[권한 수정 명령 예시]")
        extra_sol.append(
            _format_list_lines(
                wrong_mode,
                lambda e: f"chmod 0644 {e['path']}",
            )
        )

    if extra_sol:
        report["solution"] = report["solution"].rstrip() + "\n\n" + "\n".join(extra_sol)


class LinuxKisaU67LogFilePerm(BasePlugin):
    def check(self) -> List[Finding]:
        cfg: Dict[str, Any] = self.context.config or {}
        target: Dict[str, Any] = self.context.target or {}

        log_dir = Path(cfg.get("log_dir", DEFAULT_LOG_DIR))
        max_depth = int(cfg.get("max_depth", 1))
        allowed_owners = _to_allowed_owners(cfg)

        max_mode_str = str(cfg.get("max_mode", DEFAULT_MAX_MODE)).strip()
        max_mode_int = _parse_mode_to_int(max_mode_str)
        if max_mode_int is None:
            raise PluginConfigError("max_mode는 8진수 문자열이어야 합니다. 예: 0644")

        client = _build_ssh_client(target, cfg)

        cmd = (
            "find "
            f"{shlex.quote(str(log_dir))} "
            f"-maxdepth {max_depth} -type f "
            r"-printf '%p\t%u\t%#m\n'"
        )

        result = client.run(cmd)
        if result.exit_code != 0:
            err = (result.stderr or result.stdout or "").strip()
            raise PluginConfigError(f"SSH command failed: {err}")

        entries = _parse_find_output(result.stdout.splitlines())

        # 없으면 Info로 정리
        if not entries:
            diagnose = {"is_vulnerable": False, "failed_keys": [], "checks": []}
            report = build_report(
                diagnose=diagnose,
                requirements={},
                effective_policy={},
                title="KISA U-67 로그 파일 소유자/권한 점검",
                ok_summary=f"{log_dir} 내에 점검할 로그 파일이 없습니다.",
                vuln_summary=f"{log_dir} 내에 점검할 로그 파일이 없습니다.",
                meta=U67_META,
                severity_fn=u67_severity,
                footer_note="로그 생성 정책을 확인하고 필요한 경우 로그 파일을 생성 후 권한을 설정하세요.",
            )
            self.add_finding(
                vuln_id="KISA-U-67",
                title="로그 파일 소유자/권한 점검",
                severity="Info",
                evidence={
                    "log_dir": str(log_dir),
                    "command": cmd,
                    "raw_output": result.stdout,
                    "entries": [],
                },
                tags=["KISA:U-67"],
                description=report["description"],
                solution=report["solution"],
            )
            return self.results

        wrong_owner = [e for e in entries if e["owner"] not in set(allowed_owners)]
        wrong_mode = [e for e in entries if _is_mode_too_open(e["mode_int"], max_mode_int)]

        checks = [
            {
                "key": "log_owner",
                "actual_raw": f"{len(wrong_owner)} files",
                "actual": len(wrong_owner),
                "expected": f"== 0 files (owners: {', '.join(allowed_owners)})",
                "ok": len(wrong_owner) == 0,
                "reason": "" if len(wrong_owner) == 0 else "소유자 불일치 파일 존재",
            },
            {
                "key": "log_mode",
                "actual_raw": f"{len(wrong_mode)} files",
                "actual": len(wrong_mode),
                "expected": f"== 0 files (mode within {max_mode_str})",
                "ok": len(wrong_mode) == 0,
                "reason": "" if len(wrong_mode) == 0 else "권한 과다 파일 존재",
            },
        ]
        failed_keys = [c["key"] for c in checks if not c["ok"]]
        diagnose = {
            "is_vulnerable": len(failed_keys) > 0,
            "failed_keys": failed_keys,
            "checks": checks,
        }

        report = build_report(
            diagnose=diagnose,
            requirements={
                "log_owner": {"op": "==", "value": "0 files"},
                "log_mode": {"op": "==", "value": "0 files"},
            },
            effective_policy={
                "log_owner": f"{len(wrong_owner)} files",
                "log_mode": f"{len(wrong_mode)} files",
            },
            title="KISA U-67 로그 파일 소유자/권한 점검",
            ok_summary=f"로그 파일 소유자/권한이 권고값({', '.join(allowed_owners)}, {max_mode_str} 이하)을 충족합니다.",
            vuln_summary="로그 파일 소유자/권한이 권고값을 충족하지 않습니다.",
            meta=U67_META,
            severity_fn=u67_severity,
            footer_note=f"로그 파일은 ({', '.join(allowed_owners)}) 소유, {max_mode_str} 이하 권한으로 관리하세요.",
        )

        # ✅ 미준수 시 파일 목록/명령 예시를 description/solution에 추가
        if diagnose["is_vulnerable"]:
            _append_detail_to_report(report, wrong_owner, wrong_mode)

        max_entries = int(cfg.get("max_entries", DEFAULT_MAX_ENTRIES))
        evidence = {
            "log_dir": str(log_dir),
            "command": cmd,
            "allowed_owners": allowed_owners,
            "max_mode": max_mode_str,
            "raw_output": result.stdout,
            "entries_sampled": [
                {"path": e["path"], "owner": e["owner"], "mode": e["mode_str"]}
                for e in entries[:max_entries]
            ],
            "entries_truncated": len(entries) > max_entries,
            "wrong_owner": wrong_owner,
            "wrong_mode": wrong_mode,
        }

        self.add_finding(
            vuln_id="KISA-U-67",
            title="로그 파일 소유자/권한 점검",
            severity=report["severity"],
            evidence=evidence,
            tags=["KISA:U-67"],
            description=report["description"],
            solution=report["solution"],
        )

        return self.results
