"""이 파일은 .py 오케스트레이터 서비스 모듈로 플러그인 실행 흐름을 제공합니다."""

import logging
from pathlib import Path
from typing import List, Optional

from app.core.config import PLUGINS_DIR
from app.core.plugin_loader import PluginLoader, PluginMeta
from app.core.taxonomy import TaxonomyIndex
from app.core.types import PluginContext

logger = logging.getLogger(__name__)


class Orchestrator:
    def __init__(
        self,
        plugins_dir: Optional[Path] = None,
        taxonomy: Optional[TaxonomyIndex] = None,
    ) -> None:
        self.taxonomy = taxonomy or TaxonomyIndex.from_default()
        self.loader = PluginLoader(plugins_dir or PLUGINS_DIR, self.taxonomy)

    def list_plugins(self) -> List[PluginMeta]:
        return self.loader.discover()

    def run(self) -> None:
        plugins = self.list_plugins()
        logger.info("Discovered %d plugins", len(plugins))

    def execute_plugin(self, plugin_id: str, context: PluginContext) -> None:
        for meta in self.list_plugins():
            if meta.plugin_id == plugin_id:
                plugin = self.loader.load_plugin(meta, context)
                plugin.check()
                return
        raise KeyError(f"Plugin not found: {plugin_id}")
