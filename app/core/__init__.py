"""이 파일은 .py 코어 패키지 초기화 모듈로 주요 심볼을 재노출합니다."""

from .config import DEFAULT_MAPPING_FILE, PLUGINS_DIR
from .logging import setup_logging
from .plugin_base import BasePlugin
from .plugin_loader import PluginLoader
from .taxonomy import TaxonomyIndex
from .types import Finding, PluginContext

__all__ = [
    "BasePlugin",
    "DEFAULT_MAPPING_FILE",
    "Finding",
    "PluginContext",
    "PluginLoader",
    "PLUGINS_DIR",
    "TaxonomyIndex",
    "setup_logging",
]
