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
        auth_headers = self.context.config.get("auth_headers", {})
        require_auth = bool(self.context.config.get("require_auth", False))
        timeout = int(self.context.config.get("timeout", 5))
        verify_ssl = bool(self.context.config.get("verify_ssl", True))
        target_url = f"{base_url.rstrip('/')}{endpoint_path}"

        client = HttpClient(timeout=timeout, verify_ssl=verify_ssl)
        unauth_result = client.get(target_url, headers=headers)
        auth_result = None
        if auth_headers:
            merged_headers = {**headers, **auth_headers}
            auth_result = client.get(target_url, headers=merged_headers)

        if require_auth and unauth_result.status == 200:
            auth_status = auth_result.status if auth_result else None
            self.add_finding(
                vuln_id="OWASP-A01-UNAUTH",
                title="인증 필요 엔드포인트에 대한 무인증 접근",
                severity="Medium",
                evidence={
                    "url": target_url,
                    "unauth_status": unauth_result.status,
                    "auth_status": auth_status,
                    "response_sample": unauth_result.body[:120],
                },
                tags=["OWASP:2025:A01"],
                description="인증이 필요한 엔드포인트가 무인증으로 접근되는지 확인했습니다.",
                solution="인증/인가 검증을 적용하고 접근을 제한하세요.",
            )
        return self.results
