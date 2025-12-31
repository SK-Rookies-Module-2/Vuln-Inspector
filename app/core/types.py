"""이 파일은 .py 타입 정의 모듈로 플러그인 컨텍스트와 결과 모델을 제공합니다."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class PluginContext:
    # 플러그인이 실행될 때 전달되는 공통 컨텍스트이다.
    target: Dict
    # plugin.yml의 config_schema로 검증된 설정값을 전달한다.
    config: Dict = field(default_factory=dict)
    # Job ID는 리포팅/아티팩트 저장 경로에 사용된다.
    job_id: Optional[int] = None


@dataclass
class Finding:
    # 플러그인 결과를 표준화한 구조체로 DB 저장 전에 사용된다.
    vuln_id: str
    title: str
    severity: str
    # evidence는 근거(로그, URL, 파일 경로 등)를 담는다.
    evidence: Dict
    # tags는 KISA/OWASP 등 분류 태그 목록이다.
    tags: List[str]
    description: Optional[str] = None
    solution: Optional[str] = None
    raw_data: Optional[Dict] = None
