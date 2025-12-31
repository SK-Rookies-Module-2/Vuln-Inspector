"""이 파일은 .py 리포팅 모듈로 결과 요약 로직을 제공합니다."""

from typing import Dict, List

from app.core.types import Finding


def summarize_findings(findings: List[Finding]) -> Dict[str, int]:
    summary: Dict[str, int] = {}
    for finding in findings:
        summary[finding.severity] = summary.get(finding.severity, 0) + 1
    return summary
