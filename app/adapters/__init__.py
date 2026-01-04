"""이 파일은 .py 어댑터 패키지 초기화 모듈로 공통 어댑터를 노출합니다."""

from .external import ExternalRunner, ExternalScanResult, StrixRunner
from .ssh import CommandResult, SshClient

__all__ = [
    "CommandResult",
    "ExternalRunner",
    "ExternalScanResult",
    "SshClient",
    "StrixRunner",
]
