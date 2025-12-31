"""이 파일은 .py 플러그인 베이스 모듈로 결과 생성 공통 로직을 제공합니다."""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from .taxonomy import TaxonomyIndex
from .types import Finding, PluginContext


class BasePlugin(ABC):
    def __init__(self, context: PluginContext, taxonomy: Optional[TaxonomyIndex] = None):
        self.context = context
        self.taxonomy = taxonomy or TaxonomyIndex({})
        self.results: List[Finding] = []

    @abstractmethod
    def check(self) -> List[Finding]:
        raise NotImplementedError

    def add_finding(
        self,
        vuln_id: str,
        title: str,
        severity: str,
        evidence: Dict,
        tags: Optional[List[str]] = None,
        description: Optional[str] = None,
        solution: Optional[str] = None,
        raw_data: Optional[Dict] = None,
    ) -> Finding:
        expanded_tags = self.taxonomy.expand_tags(tags or [])
        finding = Finding(
            vuln_id=vuln_id,
            title=title,
            severity=severity,
            evidence=evidence,
            tags=expanded_tags,
            description=description,
            solution=solution,
            raw_data=raw_data,
        )
        self.results.append(finding)
        return finding
