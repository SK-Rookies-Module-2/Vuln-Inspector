"""이 파일은 .py 어댑터 레지스트리 모듈로 외부 도구를 관리합니다."""

from typing import Dict

from .base import ExternalAdapter


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: Dict[str, ExternalAdapter] = {}

    def register(self, name: str, adapter: ExternalAdapter) -> None:
        if name in self._adapters:
            raise KeyError(f"Adapter already registered: {name}")
        self._adapters[name] = adapter

    def get(self, name: str) -> ExternalAdapter:
        if name not in self._adapters:
            raise KeyError(f"Adapter not registered: {name}")
        return self._adapters[name]
