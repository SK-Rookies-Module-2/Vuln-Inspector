"""이 파일은 .py 타입 정의 모듈로 플러그인 컨텍스트와 결과 모델을 제공합니다."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class PluginContext:
    target: Dict
    config: Dict = field(default_factory=dict)


@dataclass
class Finding:
    vuln_id: str
    title: str
    severity: str
    evidence: Dict
    tags: List[str]
    description: Optional[str] = None
    solution: Optional[str] = None
    raw_data: Optional[Dict] = None
