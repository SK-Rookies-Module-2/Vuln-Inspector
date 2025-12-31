"""이 파일은 .py 동적 채널 데모 실행 스크립트로 로컬 HTTP 서버를 점검합니다."""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from app.core.plugin_loader import PluginLoader
from app.core.taxonomy import TaxonomyIndex
from app.core.types import PluginContext

PLUGIN_ID = "dynamic_idor_scanner"


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/api/users/2":
            payload = {"id": 2, "name": "demo-user"}
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args) -> None:
        return


def _start_server() -> Tuple[HTTPServer, int]:
    server = HTTPServer(("127.0.0.1", 0), DemoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_port


def main() -> None:
    loader = PluginLoader(REPO_ROOT / "plugins", TaxonomyIndex.from_default())
    meta = next((item for item in loader.discover() if item.plugin_id == PLUGIN_ID), None)
    if meta is None:
        raise SystemExit(f"Plugin not found: {PLUGIN_ID}")

    server, port = _start_server()
    try:
        context = PluginContext(
            target={"type": "WEB_URL", "base_url": f"http://127.0.0.1:{port}"},
            config={
                "base_url": f"http://127.0.0.1:{port}",
                "endpoint_path": "/api/users/2",
                "require_auth": True,
            },
        )
        plugin = loader.load_plugin(meta, context)
        findings = plugin.check()
    finally:
        server.shutdown()
        server.server_close()

    print(f"Findings: {len(findings)}")
    for finding in findings:
        print(f"- {finding.vuln_id} | {finding.title} | {finding.tags} | {finding.evidence}")


if __name__ == "__main__":
    main()
