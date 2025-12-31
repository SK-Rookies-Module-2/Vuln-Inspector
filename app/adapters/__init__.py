"""이 파일은 .py 어댑터 패키지 초기화 모듈로 공통 어댑터를 노출합니다."""

from .base import ExternalAdapter
from .http import HttpClient, HttpResult
from .registry import AdapterRegistry
from .sca import ScaRunner, ToolResult
from .ssh import CommandResult, SshClient

__all__ = [
    "AdapterRegistry",
    "CommandResult",
    "ExternalAdapter",
    "HttpClient",
    "HttpResult",
    "ScaRunner",
    "SshClient",
    "ToolResult",
]
