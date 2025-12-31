"""이 파일은 .py 원격 점검 데모 플러그인 모듈로 KISA U-01 체크를 모사합니다."""

from typing import List

from app.core.plugin_base import BasePlugin
from app.core.types import Finding


class RootLoginCheck(BasePlugin):
    def check(self) -> List[Finding]:
        permit_root_login = self.context.config.get("permit_root_login", True)
        if permit_root_login:
            self.add_finding(
                vuln_id="KISA-U-01-DEMO",
                title="Root remote login permitted",
                severity="High",
                evidence={"permit_root_login": permit_root_login},
                tags=["KISA:U-01"],
                description="Demo finding for KISA U-01 mapping validation.",
                solution="Disable direct root login via SSH.",
            )
        return self.results
