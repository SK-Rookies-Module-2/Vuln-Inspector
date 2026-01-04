"""
Debian 계열 리눅스
KISA U-02 비밀번호 정책 점검 플러그인
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Iterable
from pathlib import Path

from app.core.plugin_base import BasePlugin
from app.core.types import Finding
from app.core.errors import PluginConfigError

from plugins.remote.utils.ssh import ssh_read_config, RemoteFile
from plugins.remote.utils.text import strip_comments, parse_kv_lines
from plugins.remote.utils.pam import parse_pam_entries, pam_args_to_options
from plugins.remote.utils.diagnose import diagnose_policy
from plugins.remote.utils.report import build_report

U02_META = {
    "minlen": {
        "label": "최소 비밀번호 길이(minlen)",
        "where": "/etc/security/pwquality.conf 또는 PAM",
        "fix": "minlen=8 이상으로 설정",
    },
    "dcredit": {
        "label": "숫자 포함(dcredit)",
        "where": "/etc/security/pwquality.conf 또는 PAM",
        "fix": "dcredit=-1 이하로 설정",
    },
    "ucredit": {
        "label": "대문자 포함(ucredit)",
        "where": "/etc/security/pwquality.conf 또는 PAM",
        "fix": "ucredit=-1 이하로 설정",
    },
    "lcredit": {
        "label": "소문자 포함(lcredit)",
        "where": "/etc/security/pwquality.conf 또는 PAM",
        "fix": "lcredit=-1 이하로 설정",
    },
    "ocredit": {
        "label": "특수문자 포함(ocredit)",
        "where": "/etc/security/pwquality.conf 또는 PAM",
        "fix": "ocredit=-1 이하로 설정",
    },
    "difok": {
        "label": "이전 비밀번호 차이(difok)",
        "where": "/etc/security/pwquality.conf 또는 PAM",
        "fix": "difok=1 이상으로 설정",
    },
    "remember": {
        "label": "비밀번호 재사용 방지(remember)",
        "where": "/etc/pam.d/common-password",
        "fix": "pam_pwhistory.so remember=N 설정",
    },
    "PASS_MIN_DAYS": {
        "label": "비밀번호 최소 사용 기간",
        "where": "/etc/login.defs",
        "fix": "PASS_MIN_DAYS 1 이상",
    },
    "PASS_MAX_DAYS": {
        "label": "비밀번호 최대 사용 기간",
        "where": "/etc/login.defs",
        "fix": "PASS_MAX_DAYS 90 이하",
    },
}

def u02_severity(diagnose: dict) -> str:
    if not diagnose["is_vulnerable"]:
        return "Info"
    return "High"
    
def get_requirements(cfg: dict) -> dict:
    req = cfg.get("required_settings")
    if not isinstance(req, dict):
        raise PluginConfigError("required_settings is missing or not an object")

    required_keys = {
        "minlen": ">=",
        "dcredit": "<=",
        "ucredit": "<=",
        "lcredit": "<=",
        "ocredit": "<=",
        "difok": ">=",
        "remember": ">=",
        "PASS_MIN_DAYS": ">=",
        "PASS_MAX_DAYS": "<=",
    }

    out = {}
    for key, op in required_keys.items():
        if key not in req:
            raise PluginConfigError(f"required_settings.{key} is missing")
        try:
            value = int(req[key])
        except Exception as exc:
            raise PluginConfigError(f"required_settings.{key} invalid: {exc}") from exc
        out[key] = {"op": op, "value": value}
    return out

def extract_pam_password_modules(pam_entries: list[dict]):
    pwquality_opts = {}
    pwhistory_opts = {}
    unix_opts = {}

    for e in pam_entries or []:
        if e.get("ptype") != "password":
            continue

        module = e.get("module")
        opts = e.get("options") or {}

        if module == "pam_pwquality.so":
            pwquality_opts = opts
        elif module == "pam_pwhistory.so":
            pwhistory_opts = opts
        elif module == "pam_unix.so":
            unix_opts = opts

    return pwquality_opts, pwhistory_opts, unix_opts

def build_effective_policy(
    pwquality_conf: dict,
    pwquality_opts: dict,
    pwhistory_opts: dict,
    unix_opts: dict,
    login_defs: dict,
) -> dict:
    policy = {}

    # pwquality 계열
    for key in ["difok", "minlen", "dcredit", "ucredit", "lcredit", "ocredit"]:
        v = pwquality_opts.get(key)
        if v is None:
            v = pwquality_conf.get(key)
        policy[key] = v

    # remember
    v = pwhistory_opts.get("remember")
    if v is None:
        v = unix_opts.get("remember")
    policy["remember"] = v

    # password aging
    policy["PASS_MIN_DAYS"] = login_defs.get("PASS_MIN_DAYS")
    policy["PASS_MAX_DAYS"] = login_defs.get("PASS_MAX_DAYS")

    return policy

# def build_report(diagnose: dict, requirements: dict, effective_policy: dict) -> dict:
#     failed_keys = diagnose.get("failed_keys") or []
#     is_vuln = bool(diagnose.get("is_vulnerable"))

#     severity = "High" if is_vuln else "Info"

#     if not is_vuln:
#         description = (
#             "KISA U-02 비밀번호 정책 점검 결과, "
#             "비밀번호 복잡도/이력/사용기간 설정이 권고 기준을 충족합니다."
#         )
#         solution = "설정을 유지하세요."
#         return {"severity": severity, "description": description, "solution": solution}

#     lines = []
#     for key in failed_keys:
#         meta = POLICY_META.get(key, {})
#         label = meta.get("label", key)
#         where = meta.get("where", "관련 설정 파일")
#         expected = None
#         actual = effective_policy.get(key)
#         for c in diagnose.get("checks", []):
#             if c.get("key") == key:
#                 expected = c.get("expected")
#                 break
#         if expected is None:
#             expected = f"{requirements.get(key, {}).get('op','')} {requirements.get(key, {}).get('value','')}".strip()

#         lines.append(f"- {label}: 현재={actual!r}, 기준={expected} (위치: {where})")

#     description = (
#         "KISA U-02 비밀번호 정책 점검 결과, 권고 기준을 충족하지 못하는 항목이 확인되었습니다.\n"
#         "미준수 항목:\n" + "\n".join(lines)
#     )

#     fix_lines = []
#     for key in failed_keys:
#         meta = POLICY_META.get(key, {})
#         label = meta.get("label", key)
#         where = meta.get("where", "")
#         fix = meta.get("fix", "관련 설정을 권고 기준에 맞게 수정")
#         if where:
#             fix_lines.append(f"- {label}: {fix} (수정 위치: {where})")
#         else:
#             fix_lines.append(f"- {label}: {fix}")

#     solution = (
#         "다음 항목을 권고 기준에 맞게 설정한 뒤 비밀번호 변경 정책이 실제로 적용되는지 확인하세요.\n"
#         + "\n".join(fix_lines)
#         + "\n\n"
#         "참고: PAM 설정을 변경한 경우, pam_pwquality/pam_pwhistory 모듈이 pam_unix.so 보다 위에 위치해야 적용될 수 있습니다."
#     )

#     return {"severity": severity, "description": description, "solution": solution}

class LinuxKisaU02PasswordPolicy(BasePlugin):
    def check(self) -> List[Finding]:
        cfg: Dict[str, Any] = self.context.config or {}
        target: Dict[str, Any] = self.context.target or {}
        connection: Dict[str, Any] = target.get("connection_info", {}) or {}
        credentials: Dict[str, Any] = target.get("credentials", {}) or {}

        pwquality_path = cfg.get("pwquality_path")
        common_password_path = cfg.get("common_password_path")
        login_defs_path = cfg.get("login_defs_path")
        
        pwquality = ssh_read_config(target, Path(pwquality_path), self.context.config)
        common_password = ssh_read_config(target, Path(common_password_path), self.context.config)
        login_defs = ssh_read_config(target, Path(login_defs_path), self.context.config)

        # 파싱
        parse_kv_pwq = parse_kv_lines(pwquality.lines) if pwquality else {}
        parse_kv_defs = parse_kv_lines(login_defs.lines) if login_defs else {}
        pam_entries = parse_pam_entries(common_password.lines) if common_password else []

        # 설정 추출
        pwquality_opts, pwhistory_opts, unix_opts = extract_pam_password_modules(pam_entries)
        effective_policy = build_effective_policy(
            pwquality_conf=parse_kv_pwq,
            pwquality_opts=pwquality_opts,
            pwhistory_opts=pwhistory_opts,
            unix_opts=unix_opts,
            login_defs=parse_kv_defs,
        )

        # 진단
        requirements = get_requirements(cfg)
        diagnose = diagnose_policy(effective_policy, requirements)
        
        # 리포트 생성
        report = build_report(
            diagnose=diagnose,
            requirements=requirements,
            effective_policy=effective_policy,

            title="KISA U-02 비밀번호 정책 점검",
            ok_summary=(
                "KISA U-02 점검 결과, "
                "비밀번호 복잡도·이력·사용기간 설정이 권고 기준을 충족합니다."
            ),
            vuln_summary=(
                "KISA U-02 점검 결과, "
                "비밀번호 정책이 권고 기준을 충족하지 못하는 항목이 확인되었습니다."
            ),
            meta=U02_META,
            severity_fn=u02_severity,
            footer_note=(
                "참고: PAM 설정 변경 시 pam_pwquality 또는 pam_pwhistory 모듈이 "
                "pam_unix.so 보다 위에 위치해야 실제로 적용됩니다."
            ),
        )

        self.add_finding(
            vuln_id="KISA-U-02",
            title="비밀번호 정책 점검",
            severity=report["severity"],
            evidence={
                "pwquality": {
                    "path": str(pwquality.path) if pwquality else None,
                    # "raw": pwquality.raw if pwquality else None,
                    "lines": pwquality.lines if pwquality else None,
                    "parsed": parse_kv_pwq, 
                },
                "common_password": {
                    "path": str(common_password.path) if common_password else None,
                    # "raw": common_password.raw if common_password else None,
                    "lines": common_password.lines if common_password else None,
                    "parsed": pam_entries,
                },
                "login_defs": {
                    "path": str(login_defs.path) if login_defs else None,
                    # "raw": login_defs.raw if login_defs else None,
                    "lines": login_defs.lines if login_defs else None,
                    "parsed": parse_kv_defs,
                },
                "effective_policy": effective_policy,
                "diagnose": diagnose,
            },
            tags=["KISA:U-02"],
            description=report["description"],
            solution=report["solution"],
        )

        return self.results
