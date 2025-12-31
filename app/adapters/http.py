"""이 파일은 .py HTTP 어댑터로 기본 요청 기능을 제공합니다."""

from __future__ import annotations

from dataclasses import dataclass
import ssl
from typing import Dict, Optional
from urllib import request
from urllib.error import HTTPError, URLError

from app.core.errors import AdapterError


@dataclass
class HttpResult:
    status: int
    body: str
    headers: Dict[str, str]


class HttpClient:
    def __init__(self, timeout: int = 5, verify_ssl: bool = True) -> None:
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> HttpResult:
        return self.request("GET", url, headers=headers)

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        timeout: Optional[int] = None,
    ) -> HttpResult:
        headers = headers or {}
        timeout_value = self.timeout if timeout is None else timeout
        req = request.Request(url=url, method=method, headers=headers, data=body)
        context = None
        if not self.verify_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        try:
            with request.urlopen(req, timeout=timeout_value, context=context) as response:
                body_text = response.read().decode("utf-8", errors="replace")
                return HttpResult(response.status, body_text, dict(response.headers))
        except HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            return HttpResult(exc.code, body_text, dict(exc.headers))
        except URLError as exc:
            raise AdapterError(f"HTTP request failed: {exc}") from exc
