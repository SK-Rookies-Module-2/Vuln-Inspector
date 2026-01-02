"""KISA U-30 UMASK 설정 점검 플러그인

UMASK 설정은 /etc/profile과 /etc/login.defs 두 곳 모두에서 동일한
권고값(기본 022)을 사용하는지를 점검한다. 세부 로직은 추후 채운다.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.core.errors import PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

from plugins.remote.utils.ssh import ssh_read_config
from plugins.remote.utils.text import parse_kv_lines, strip_comments
from plugins.remote.utils.diagnose import diagnose_policy
from plugins.remote.utils.report import build_report

import re

U30_META = {
    "profile_umask": {
        "label": "프로파일 UMASK",
        "where": "/etc/profile",
        "fix": "umask 022 및 export umask로 설정",
    },
    "login_defs_umask": {
        "label": "login.defs UMASK",
        "where": "/etc/login.defs",
        "fix": "UMASK 022로 설정",
    },
}

DEFAULT_UMASK = "022"
_RE_PROFILE_UMASK = re.compile(r"^\s*umask\s+([0-7]{2,4})\b", re.IGNORECASE)


def u30_severity(diagnose: Dict[str, Any]) -> str:
    if not diagnose.get("is_vulnerable"):
        return "Info"
    return "High"


def get_requirements(cfg: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    expected = cfg.get("expected_umask", DEFAULT_UMASK)
    if expected is None:
        raise PluginConfigError("expected_umask is missing")
    expected_str = str(expected).strip()
    if not expected_str:
        raise PluginConfigError("expected_umask must not be empty")
    expected_int = normalize_umask_for_compare(expected_str)
    if expected_int is None:
        raise PluginConfigError("expected_umask must be a numeric string (e.g., 022)")

    return {
        "profile_umask": {"op": "==", "value": expected_int},
        "login_defs_umask": {"op": "==", "value": expected_int},
    }

def extract_umask(kv: Dict[str, str]) -> Optional[str]: 
    for key in ("umask", "UMASK"): 
        if key in kv: 
            return str(kv[key]).strip() 
    return None

def _strip_inline_comment(line: str) -> str:
    return line.split("#", 1)[0].rstrip()

def extract_last_profile_umask(lines: List[str]) -> Tuple[Optional[str], List[str]]:
    hits: List[str] = []
    last: Optional[str] = None
    for raw in lines or []:
        line = _strip_inline_comment(raw)
        if not line.strip():
            continue
        m = _RE_PROFILE_UMASK.match(line)
        if m:
            last = m.group(1).strip()
            hits.append(raw.rstrip("\n"))
    return last, hits

def normalize_umask_for_compare(v: Optional[str]) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(str(v).strip(), 10)
    except Exception:
        return None

class LinuxKisaU30UmaskPolicy(BasePlugin):
    def check(self) -> List[Finding]:
        cfg: Dict[str, Any] = self.context.config or {}
        target: Dict[str, Any] = self.context.target or {}

        profile_path = Path(cfg.get("profile_path", "/etc/profile"))
        login_defs_path = Path(cfg.get("login_defs_path", "/etc/login.defs"))

        profile = ssh_read_config(target, profile_path, cfg)
        login_defs = ssh_read_config(target, login_defs_path, cfg)

        profile_lines = strip_comments(profile.lines) if profile else []
        login_defs_lines = strip_comments(login_defs.lines) if login_defs else []

        profile_kv = parse_kv_lines(profile_lines) if profile else {}
        login_defs_kv = parse_kv_lines(login_defs_lines) if login_defs else {}

        profile_umask, profile_umask_hits = extract_last_profile_umask(profile_lines if profile else [])

        effective_policy = {
            "profile_umask": normalize_umask_for_compare(profile_umask),
            "login_defs_umask": normalize_umask_for_compare(extract_umask(login_defs_kv)),
        }

        requirements = get_requirements(cfg)
        diagnose = diagnose_policy(effective_policy, requirements)

        report = build_report(
            diagnose=diagnose,
            requirements=requirements,
            effective_policy=effective_policy,
            title="KISA U-30 UMASK 설정 점검",
            ok_summary="UMASK가 KISA U-30 권고값을 충족합니다.",
            vuln_summary="UMASK 설정이 KISA U-30 권고값을 충족하지 않습니다.",
            meta=U30_META,
            severity_fn=u30_severity,
            footer_note="UMASK는 /etc/profile과 /etc/login.defs에서 동일하게 적용되어야 합니다.",
        )

        self.add_finding(
            vuln_id="KISA-U-30",
            title="UMASK 설정 점검",
            severity=report["severity"],
            evidence={
                "profile": {
                    "path": str(profile.path) if profile else None,
                    "lines": profile.lines if profile else None,
                    "parsed": profile_kv,
                },
                "login_defs": {
                    "path": str(login_defs.path) if login_defs else None,
                    "lines": login_defs.lines if login_defs else None,
                    "parsed": login_defs_kv,
                },
                "effective_hits": {
                    "profile_umask_lines": profile_umask_hits,
                },
                "effective_policy": effective_policy,
                "diagnose": diagnose,
            },
            tags=["KISA:U-30"],
            description=report["description"],
            solution=report["solution"],
        )

        return self.results
