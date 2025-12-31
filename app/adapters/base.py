"""이 파일은 .py 외부 도구 어댑터 베이스 모듈로 실행 인터페이스를 제공합니다."""

from abc import ABC, abstractmethod
from typing import Dict


class ExternalAdapter(ABC):
    @abstractmethod
    def run(self, context: Dict) -> Dict:
        raise NotImplementedError
