"""API 호출을 담당하는 간단한 클라이언트."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests


@dataclass
class APIClient:
    base_url: str
    timeout: int = 10

    def _url(self, path: str) -> str:
        # 상대 경로를 API_BASE_URL에 결합한다.
        return f"{self.base_url.rstrip('/')}{path}"

    def _request(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        # 공통 요청 래퍼(오류 메시지 포함).
        url = self._url(path)
        try:
            response = requests.request(
                method,
                url,
                json=payload,
                params=params,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise RuntimeError(f"API 연결 실패: {exc}") from exc

        if response.status_code >= 400:
            detail = _safe_json(response.text)
            raise RuntimeError(f"API 오류 {response.status_code}: {detail}")

        if not response.text:
            return {}
        return response.json()

    def _build_params(self, **kwargs: Any) -> Dict[str, Any]:
        # None 값은 제외하고 쿼리스트링을 구성한다.
        return {key: value for key, value in kwargs.items() if value is not None}

    def create_target(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("POST", "/api/v1/targets", payload)

    def get_target(self, target_id: int) -> Dict[str, Any]:
        return self._request("GET", f"/api/v1/targets/{target_id}")

    def list_targets(self, limit: int = 100, offset: int = 0) -> Any:
        params = self._build_params(limit=limit, offset=offset)
        return self._request("GET", "/api/v1/targets", params=params)

    def delete_target(self, target_id: int) -> Any:
        return self._request("DELETE", f"/api/v1/targets/{target_id}")

    def create_job(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("POST", "/api/v1/jobs", payload)

    def list_jobs(
        self,
        target_id: Optional[int] = None,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Any:
        params = self._build_params(target_id=target_id, status=status, limit=limit, offset=offset)
        return self._request("GET", "/api/v1/jobs", params=params)

    def delete_job(self, job_id: int) -> Any:
        return self._request("DELETE", f"/api/v1/jobs/{job_id}")

    def run_job(self, job_id: int) -> Dict[str, Any]:
        return self._request("POST", f"/api/v1/jobs/{job_id}/run")

    def get_job_status(self, job_id: int) -> Dict[str, Any]:
        return self._request("GET", f"/api/v1/jobs/{job_id}/status")

    def get_job_findings(self, job_id: int) -> Any:
        return self._request("GET", f"/api/v1/jobs/{job_id}/findings")

    def list_findings(
        self,
        job_id: Optional[int] = None,
        target_id: Optional[int] = None,
        severity: Optional[str] = None,
        tag: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Any:
        params = self._build_params(
            job_id=job_id,
            target_id=target_id,
            severity=severity,
            tag=tag,
            limit=limit,
            offset=offset,
        )
        return self._request("GET", "/api/v1/findings", params=params)

    def delete_finding(self, finding_id: int) -> Any:
        return self._request("DELETE", f"/api/v1/findings/{finding_id}")

    def create_report(self, job_id: int, report_format: str) -> Dict[str, Any]:
        return self._request("POST", f"/api/v1/jobs/{job_id}/report", {"format": report_format})

    def get_report(self, report_id: int) -> Dict[str, Any]:
        return self._request("GET", f"/api/v1/reports/{report_id}")


def _safe_json(text: str) -> str:
    # 응답이 JSON이면 detail만 추출하고 아니면 원문을 반환한다.
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return text
    return str(data.get("detail", data))
