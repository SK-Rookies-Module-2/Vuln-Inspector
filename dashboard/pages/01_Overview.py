"""대시보드 요약 페이지."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Tuple

import streamlit as st

from lib.api_client import APIClient


def _count_by_key(items: List[Dict[str, Any]], key: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        value = str(item.get(key, "UNKNOWN"))
        counts[value] = counts.get(value, 0) + 1
    return counts


@st.cache_data(ttl=5)
def _load_overview(base_url: str, limit: int) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    client = APIClient(base_url)
    targets = client.list_targets(limit=limit, offset=0)
    jobs = client.list_jobs(limit=limit, offset=0)
    findings = client.list_findings(limit=limit, offset=0)
    return targets, jobs, findings


def main() -> None:
    st.header("요약 대시보드")
    api_base_url = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
    st.caption(f"API_BASE_URL = {api_base_url}")

    limit = st.number_input("조회 limit", min_value=10, max_value=1000, value=200, step=50)
    if st.button("새로고침"):
        st.cache_data.clear()

    try:
        targets, jobs, findings = _load_overview(api_base_url, int(limit))
    except Exception as exc:
        st.error(str(exc))
        return

    col1, col2, col3 = st.columns(3)
    col1.metric("등록 대상", len(targets))
    col2.metric("스캔 Job", len(jobs))
    col3.metric("Finding", len(findings))

    st.subheader("등록 대상 목록")
    st.dataframe(targets, use_container_width=True)

    st.subheader("Job 상태 요약")
    job_status = _count_by_key(jobs, "status")
    st.dataframe(
        [{"status": key, "count": value} for key, value in job_status.items()],
        use_container_width=True,
    )

    st.subheader("Finding 심각도 요약")
    finding_sev = _count_by_key(findings, "severity")
    st.dataframe(
        [{"severity": key, "count": value} for key, value in finding_sev.items()],
        use_container_width=True,
    )

    st.subheader("최근 Job")
    st.dataframe(jobs[:5], use_container_width=True)

    st.subheader("최근 Finding")
    st.dataframe(findings[:5], use_container_width=True)


if __name__ == "__main__":
    main()
