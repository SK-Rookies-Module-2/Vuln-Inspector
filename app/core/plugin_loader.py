"""이 파일은 .py 플러그인 로더 모듈로 메타데이터 로딩과 동적 임포트를 수행합니다."""

import importlib.util
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import yaml

from .plugin_base import BasePlugin
from .taxonomy import TaxonomyIndex
from .types import PluginContext


@dataclass(frozen=True)
class PluginMeta:
    plugin_id: str
    name: str
    version: str
    plugin_type: str
    category: Optional[str]
    tags: List[str]
    description: Optional[str]
    config_schema: Optional[dict]
    entry_point: str
    class_name: str
    plugin_dir: Path

    @property
    def module_path(self) -> Path:
        return self.plugin_dir / self.entry_point


class PluginLoader:
    def __init__(self, plugins_dir: Path, taxonomy: TaxonomyIndex):
        self.plugins_dir = Path(plugins_dir)
        self.taxonomy = taxonomy

    def discover(self) -> List[PluginMeta]:
        metas: List[PluginMeta] = []
        for plugin_file in sorted(self.plugins_dir.rglob("plugin.yml")):
            meta = self._load_meta(plugin_file)
            if meta:
                metas.append(meta)
        return metas

    def load_plugin(self, meta: PluginMeta, context: PluginContext) -> BasePlugin:
        module = self._import_module(meta)
        plugin_class = getattr(module, meta.class_name, None)
        if plugin_class is None:
            raise ImportError(f"Class {meta.class_name} not found in {meta.module_path}")
        if not issubclass(plugin_class, BasePlugin):
            raise TypeError(f"{meta.class_name} does not extend BasePlugin")
        return plugin_class(context, taxonomy=self.taxonomy)

    def _load_meta(self, plugin_file: Path) -> Optional[PluginMeta]:
        data = yaml.safe_load(plugin_file.read_text()) or {}
        required = ["id", "name", "version", "type", "entry_point", "class_name"]
        for field in required:
            if field not in data:
                raise ValueError(f"Missing required field {field} in {plugin_file}")

        return PluginMeta(
            plugin_id=str(data["id"]),
            name=str(data["name"]),
            version=str(data["version"]),
            plugin_type=str(data["type"]),
            category=data.get("category"),
            tags=data.get("tags", []) or [],
            description=data.get("description"),
            config_schema=data.get("config_schema"),
            entry_point=str(data["entry_point"]),
            class_name=str(data["class_name"]),
            plugin_dir=plugin_file.parent,
        )

    def _import_module(self, meta: PluginMeta):
        module_path = meta.module_path
        if not module_path.exists():
            raise FileNotFoundError(f"Entry point not found: {module_path}")

        spec = importlib.util.spec_from_file_location(meta.plugin_id, module_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load module from {module_path}")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
