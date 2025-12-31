"""이 파일은 .py 동적 점검 플러그인 모듈로 IDOR 접근 제어 점검을 수행합니다."""

from __future__ import annotations

from typing import List

from app.adapters.http import HttpClient

from app.core.plugin_base import BasePlugin
from app.core.types import Finding


class IdorScanner(BasePlugin):
    def check(self) -> List[Finding]:
        base_url = self.context.config.get("base_url")
        if not base_url:
            base_url = self.context.target.get("connection_info", {}).get("url", "")
        if not base_url:
            return self.results
        endpoint_path = self.context.config.get("endpoint_path", "/api/users/1")
        headers = self.context.config.get("headers", {})
        timeout = int(self.context.config.get("timeout", 5))
        verify_ssl = bool(self.context.config.get("verify_ssl", True))
        target_url = f"{base_url.rstrip('/')}{endpoint_path}"

        client = HttpClient(timeout=timeout, verify_ssl=verify_ssl)
        result = client.get(target_url, headers=headers)
        status, body = result.status, result.body
        if status == 200:
            self.add_finding(
                vuln_id="OWASP-A01-IDOR",
                title="잠재적 IDOR 취약점",
                severity="High",
                evidence={
                    "url": target_url,
                    "status_code": status,
                    "response_sample": body[:120],
                },
                tags=["OWASP:2025:A01"],
                description="권한 검증 없이 리소스 접근이 가능할 수 있습니다.",
                solution="리소스 접근 시 권한 검증을 적용하세요.",
            )
        return self.results
