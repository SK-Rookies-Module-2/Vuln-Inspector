"""외부 도구 기반 정적 진단 스켈레톤."""

from __future__ import annotations

from typing import List

from app.core.errors import PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding


class StrixStaticScan(BasePlugin):
    def check(self) -> List[Finding]:
        # TODO: Strix 외부 스캐너 실행 및 보고서 파싱 로직 추가
        raise PluginConfigError("Strix static scan is not configured yet")
