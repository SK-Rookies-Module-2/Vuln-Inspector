"""이 파일은 .py 플러그인 베이스 모듈로 결과 생성 공통 로직을 제공합니다."""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from .types import Finding, PluginContext


class BasePlugin(ABC):
    def __init__(self, context: PluginContext):
        # API에서 전달된 Target/Config 정보를 보관한다.
        self.context = context
        # 실행 중 누적되는 결과를 저장한다.
        self.results: List[Finding] = []

    @abstractmethod
    def check(self) -> List[Finding]:
        # 각 플러그인은 check()에서 진단 로직을 수행한다.
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
        # 입력된 태그를 그대로 사용해 표준 Finding을 생성한다.
        normalized_tags = tags or []
        finding = Finding(
            vuln_id=vuln_id,
            title=title,
            severity=severity,
            evidence=evidence,
            tags=normalized_tags,
            description=description,
            solution=solution,
            raw_data=raw_data,
        )
        # 결과 목록에 추가하고 호출 측에 반환한다.
        self.results.append(finding)
        return finding
