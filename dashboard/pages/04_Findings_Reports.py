"""결과 조회/보고서 생성 페이지."""

from __future__ import annotations

import os

import streamlit as st

from lib.api_client import APIClient


def main() -> None:
    st.header("결과 조회 및 보고서")

    api_base_url = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
    client = APIClient(api_base_url)

    st.subheader("Finding 목록")
    list_job_id = st.text_input("job_id (선택)", value="")
    list_target_id = st.text_input("target_id (선택)", value="")
    list_severity = st.text_input("severity (선택)", value="")
    list_tag = st.text_input("tag (선택)", value="")
    list_limit = st.number_input("limit", min_value=1, max_value=1000, value=100, step=10, key="finding_limit")
    list_offset = st.number_input("offset", min_value=0, value=0, step=10, key="finding_offset")
    if st.button("Finding 목록 조회"):
        try:
            job_id = int(list_job_id) if list_job_id.strip() else None
            target_id = int(list_target_id) if list_target_id.strip() else None
            severity = list_severity.strip() or None
            tag = list_tag.strip() or None
            result = client.list_findings(
                job_id=job_id,
                target_id=target_id,
                severity=severity,
                tag=tag,
                limit=int(list_limit),
                offset=int(list_offset),
            )
            st.dataframe(result, use_container_width=True)
        except Exception as exc:
            st.error(str(exc))

    st.subheader("Finding 조회")
    job_id = st.number_input("job_id", min_value=1, step=1, value=1)
    if st.button("Finding 조회"):
        try:
            result = client.get_job_findings(int(job_id))
            st.json(result)
        except Exception as exc:
            st.error(str(exc))

    st.subheader("보고서 생성")
    report_job_id = st.number_input("job_id", min_value=1, step=1, value=1, key="report_job_id")
    report_format = st.selectbox("포맷", ["json", "csv"])
    if st.button("보고서 생성"):
        try:
            result = client.create_report(int(report_job_id), report_format)
            report_id = result.get("id")
            st.success(f"보고서 생성 완료: id={report_id}")
            st.json(result)
            if report_id:
                st.markdown(f"다운로드: `{api_base_url}/api/v1/reports/{report_id}/file`")
        except Exception as exc:
            st.error(str(exc))


if __name__ == "__main__":
    main()
