"""이 파일은 .py 어댑터 패키지 초기화 모듈로 레지스트리를 노출합니다."""

from .base import ExternalAdapter
from .registry import AdapterRegistry

__all__ = ["AdapterRegistry", "ExternalAdapter"]
