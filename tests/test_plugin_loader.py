"""이 파일은 .py 테스트 모듈로 플러그인 탐색 동작을 검증합니다."""

from pathlib import Path

from app.core.plugin_loader import PluginLoader
from app.core.taxonomy import TaxonomyIndex


def test_discover_plugins() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    loader = PluginLoader(repo_root / "plugins", TaxonomyIndex.from_default())
    plugins = loader.discover()
    plugin_ids = {meta.plugin_id for meta in plugins}
    assert "remote_linux_kisa_u01" in plugin_ids
