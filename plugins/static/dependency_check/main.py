"""이 파일은 .py 정적 분석 데모 플러그인 모듈로 의존성 스캔 흐름을 모사합니다."""

from typing import List

from app.core.plugin_base import BasePlugin
from app.core.types import Finding


class DependencyCheck(BasePlugin):
    def check(self) -> List[Finding]:
        manifest_path = self.context.config.get("manifest_path", "requirements.txt")
        self.add_finding(
            vuln_id="DEMO-A03-001",
            title="Demo dependency finding",
            severity="Medium",
            evidence={"manifest": manifest_path},
            tags=["OWASP:2025:A03"],
            description="Demo finding generated for pipeline validation.",
            solution="Replace the vulnerable dependency with a patched version.",
        )
        return self.results
