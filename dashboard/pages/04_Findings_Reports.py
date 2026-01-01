"""결과 조회/보고서 생성 페이지."""

from __future__ import annotations

import os

import streamlit as st

from lib.api_client import APIClient


def main() -> None:
    st.header("결과 조회 및 보고서")

    api_base_url = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
    client = APIClient(api_base_url)

    st.subheader("Finding 조회")
    job_id = st.number_input("job_id", min_value=1, step=1, value=1)
    if st.button("Finding 조회"):
        try:
            result = client.get_job_findings(int(job_id))
            st.json(result)
        except Exception as exc:
            st.error(str(exc))

    st.subheader("Finding 삭제")
    delete_finding_id = st.number_input("삭제할 finding_id", min_value=1, step=1, value=1, key="delete_finding_id")
    if st.button("삭제"):
        try:
            client.delete_finding(int(delete_finding_id))
            st.success("Finding 삭제 완료")
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
