"""이 파일은 .py 동적 점검 플러그인 모듈로 IDOR 접근 제어 점검을 수행합니다."""

from __future__ import annotations

from typing import List, Tuple
from urllib import request
from urllib.error import HTTPError, URLError

from app.core.plugin_base import BasePlugin
from app.core.types import Finding


def _http_get(url: str) -> Tuple[int, str]:
    try:
        with request.urlopen(url, timeout=5) as response:
            body = response.read().decode("utf-8", errors="replace")
            return response.status, body
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, body
    except URLError:
        return 0, ""


class IdorScanner(BasePlugin):
    def check(self) -> List[Finding]:
        base_url = self.context.config.get("base_url", "")
        endpoint_path = self.context.config.get("endpoint_path", "/api/users/1")
        target_url = f"{base_url.rstrip('/')}{endpoint_path}"

        status, body = _http_get(target_url)
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
