"""이 파일은 .py 정적 채널 데모 실행 스크립트로 의존성 고정 여부를 점검합니다."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from app.core.plugin_loader import PluginLoader
from app.core.types import PluginContext

PLUGIN_ID = "static_dependency_check"


def main() -> None:
    loader = PluginLoader(REPO_ROOT / "plugins")
    meta = next((item for item in loader.discover() if item.plugin_id == PLUGIN_ID), None)
    if meta is None:
        raise SystemExit(f"Plugin not found: {PLUGIN_ID}")

    context = PluginContext(
        target={"type": "GIT_REPO", "path": str(REPO_ROOT)},
        config={"manifest_path": "requirements.txt"},
    )
    plugin = loader.load_plugin(meta, context)
    findings = plugin.check()

    print(f"Findings: {len(findings)}")
    for finding in findings:
        print(f"- {finding.vuln_id} | {finding.title} | {finding.tags} | {finding.evidence}")


if __name__ == "__main__":
    main()
