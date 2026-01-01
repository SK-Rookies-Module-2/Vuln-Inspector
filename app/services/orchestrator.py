"""이 파일은 .py 오케스트레이터 서비스 모듈로 플러그인 실행 흐름을 제공합니다."""

import logging
from pathlib import Path
from typing import List, Optional

from app.core.config import PLUGINS_DIR
from app.core.plugin_loader import PluginLoader, PluginMeta
from app.core.types import PluginContext

logger = logging.getLogger(__name__)


class Orchestrator:
    def __init__(
        self,
        plugins_dir: Optional[Path] = None,
    ) -> None:
        # 플러그인 디렉토리에서 메타 정보를 로드할 로더를 만든다.
        self.loader = PluginLoader(plugins_dir or PLUGINS_DIR)

    def list_plugins(self) -> List[PluginMeta]:
        # plugin.yml을 탐색해 메타데이터 리스트를 반환한다.
        return self.loader.discover()

    def run(self) -> None:
        # 오케스트레이터의 실행 진입점(현재는 플러그인 목록 로그 출력).
        plugins = self.list_plugins()
        logger.info("Discovered %d plugins", len(plugins))

    def execute_plugin(self, plugin_id: str, context: PluginContext) -> None:
        # 지정한 plugin_id를 찾아 로드/실행한다.
        for meta in self.list_plugins():
            if meta.plugin_id == plugin_id:
                plugin = self.loader.load_plugin(meta, context)
                # 플러그인의 주요 진단 로직을 수행한다.
                plugin.check()
                return
        # 발견되지 않으면 호출자가 처리할 수 있도록 예외를 던진다.
        raise KeyError(f"Plugin not found: {plugin_id}")
