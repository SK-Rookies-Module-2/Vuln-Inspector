"""이 파일은 .py 동적 점검 데모 플러그인 모듈로 IDOR 시나리오를 모사합니다."""

from typing import List

from app.core.plugin_base import BasePlugin
from app.core.types import Finding


class IdorScanner(BasePlugin):
    def check(self) -> List[Finding]:
        status_code = int(self.context.config.get("status_code", 200))
        if status_code == 200:
            self.add_finding(
                vuln_id="OWASP-A01-DEMO",
                title="Potential IDOR detected",
                severity="High",
                evidence={"status_code": status_code},
                tags=["OWASP:2025:A01"],
                description="Demo finding for access-control validation.",
                solution="Enforce authorization checks on resource access.",
            )
        return self.results
