from typing import Any, Dict, Optional, Callable

def build_report(
    *,
    diagnose: Dict[str, Any],
    requirements: Dict[str, Any],
    effective_policy: Dict[str, Any],

    title: str,
    ok_summary: str,
    vuln_summary: str,

    meta: Optional[Dict[str, Dict[str, str]]] = None,

    severity_fn: Optional[Callable[[Dict[str, Any]], str]] = None,

    default_where: str = "관련 설정 파일",
    ok_solution: str = "현재 설정을 유지하세요.",
    footer_note: Optional[str] = None,
) -> Dict[str, str]:

    meta = meta or {}
    failed_keys = diagnose.get("failed_keys") or []
    is_vuln = bool(diagnose.get("is_vulnerable"))

    if severity_fn:
        severity = severity_fn(diagnose)
    else:
        severity = "High" if is_vuln else "Info"

    if not is_vuln:
        return {
            "severity": severity,
            "description": ok_summary,
            "solution": ok_solution,
        }

    expected_map = {
        c.get("key"): c.get("expected")
        for c in diagnose.get("checks", [])
        if c.get("key")
    }

    desc_lines = []
    fix_lines = []

    for key in failed_keys:
        m = meta.get(key, {})
        label = m.get("label", key)
        where = m.get("where", default_where)
        fix = m.get("fix", "관련 설정을 권고 기준에 맞게 수정")

        actual = effective_policy.get(key)
        expected = expected_map.get(key)

        if not expected:
            rule = requirements.get(key, {})
            expected = f"{rule.get('op','')} {rule.get('value','')}".strip() or "기준값 확인 필요"

        desc_lines.append(
            f"- {label}: 현재: {actual!r}, 기준: {expected} (위치: {where})"
        )
        fix_lines.append(
            f"- {label}: {fix} (수정 위치: {where})"
        )

    description = (
        f"{vuln_summary}\n"
        "미준수 항목:\n" + "\n".join(desc_lines)
    )

    solution = (
        "다음 항목을 권고 기준에 맞게 설정한 뒤 정책이 실제로 적용되는지 확인하세요.\n"
        + "\n".join(fix_lines)
    )

    if footer_note:
        solution += "\n\n" + footer_note

    return {
        "severity": severity,
        "description": description,
        "solution": solution,
    }