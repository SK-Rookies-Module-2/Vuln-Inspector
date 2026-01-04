"""외부 스캐너 어댑터 패키지."""

from .runner import ExternalRunner, ExternalScanResult
from .strix import StrixRunner

__all__ = ["ExternalRunner", "ExternalScanResult", "StrixRunner"]
