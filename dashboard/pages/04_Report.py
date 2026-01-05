"""Report viewer page."""

from __future__ import annotations

import os
from typing import Any, Dict, List

import streamlit as st

from lib.api_client import APIClient
from lib.report_viewer import fetch_report_json, render_report


@st.cache_data(ttl=5)
def _load_reports(base_url: str, limit: int, job_id: int | None) -> List[Dict[str, Any]]:
    client = APIClient(base_url)
    return client.list_reports(job_id=job_id, limit=limit, offset=0)


def _format_report_label(report: Dict[str, Any]) -> str:
    report_id = report.get("id")
    report_format = report.get("format")
    generated_at = report.get("generated_at")
    job_id = report.get("job_id")
    return f"id={report_id} | job={job_id} | {report_format} | {generated_at}"


def _report_file_url(base_url: str, report_id: int) -> str:
    return f"{base_url.rstrip('/')}/api/v1/reports/{report_id}/file"


def _report_meta_rows(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {"field": "id", "value": report.get("id")},
        {"field": "job_id", "value": report.get("job_id")},
        {"field": "format", "value": report.get("format")},
        {"field": "file_path", "value": report.get("file_path")},
        {"field": "generated_at", "value": report.get("generated_at")},
    ]


def main() -> None:
    st.header("Reports")

    api_base_url = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
    st.caption(f"API_BASE_URL = {api_base_url}")

    col_filters, col_actions = st.columns(2)
    with col_filters:
        filter_job_id = st.number_input("job_id filter (0 = all)", min_value=0, step=1, value=0)
        limit_reports = st.number_input("limit", min_value=10, max_value=1000, value=200, step=50)
    with col_actions:
        if st.button("Refresh"):
            st.cache_data.clear()

    job_id_filter = int(filter_job_id) if int(filter_job_id) > 0 else None
    try:
        reports = _load_reports(api_base_url, int(limit_reports), job_id_filter)
    except Exception as exc:
        st.error(str(exc))
        return

    if not reports:
        st.info("No reports available.")
        return

    report_map: Dict[str, Dict[str, Any]] = {}
    labels = []
    for report in sorted(reports, key=lambda item: item.get("id", 0), reverse=True):
        label = _format_report_label(report)
        labels.append(label)
        report_map[label] = report

    selected_label = st.selectbox("Report list", options=labels)
    selected_report = report_map.get(selected_label, {})

    st.subheader("Report metadata")
    st.dataframe(_report_meta_rows(selected_report), use_container_width=True)

    report_id = selected_report.get("id")
    if report_id:
        st.markdown(f"[Download report file]({_report_file_url(api_base_url, int(report_id))})")

    if st.button("View report", key="report_view"):
        report_format = str(selected_report.get("format", "")).lower()
        if report_format != "json":
            st.warning("Only JSON reports can be rendered as tables.")
        else:
            try:
                payload = fetch_report_json(api_base_url, int(report_id))
            except Exception as exc:
                st.error(str(exc))
            else:
                st.session_state["report_payload"] = payload
                st.session_state["report_payload_id"] = report_id

    payload = st.session_state.get("report_payload")
    payload_id = st.session_state.get("report_payload_id")
    if payload:
        st.caption(f"현재 표시 중인 report_id: {payload_id}")
        render_report(payload)


if __name__ == "__main__":
    main()
