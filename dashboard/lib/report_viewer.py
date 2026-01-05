"""Helpers to fetch and render JSON reports in the dashboard."""

from __future__ import annotations

import json
from typing import Any, Dict, List

import requests
import streamlit as st


def fetch_report_json(base_url: str, report_id: int, timeout: int = 10) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}/api/v1/reports/{report_id}/file"
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    try:
        return response.json()
    except ValueError as exc:
        raise RuntimeError("보고서 파일이 JSON 형식이 아닙니다.") from exc


def render_report(payload: Dict[str, Any]) -> None:
    job = payload.get("job") or {}
    target = payload.get("target") or {}
    findings = payload.get("findings") or []
    summary = job.get("summary") or {}

    st.subheader("보고서 요약")
    _render_summary(summary)

    col_job, col_target = st.columns(2)
    with col_job:
        st.markdown("**Job 정보**")
        st.dataframe(_kv_rows(_job_info(job)), use_container_width=True)
    with col_target:
        st.markdown("**Target 정보**")
        st.dataframe(_kv_rows(_target_info(target)), use_container_width=True)

    st.subheader("Finding 목록")
    if not findings:
        st.info("보고서에 포함된 Finding이 없습니다.")
    else:
        rows = [_finding_row(item) for item in findings]
        st.dataframe(rows, use_container_width=True)
        _render_finding_detail(findings)

    with st.expander("원본 JSON 보기"):
        st.json(payload)


def _render_summary(summary: Dict[str, Any]) -> None:
    if not summary:
        st.info("요약 정보가 없습니다.")
        return
    items = [{"severity": key, "count": value} for key, value in summary.items()]
    st.dataframe(items, use_container_width=True)


def _job_info(job: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": job.get("id"),
        "status": job.get("status"),
        "start_time": job.get("start_time"),
        "end_time": job.get("end_time"),
        "scan_scope": ", ".join(job.get("scan_scope") or []),
    }


def _target_info(target: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": target.get("id"),
        "name": target.get("name"),
        "type": target.get("type"),
        "connection_info": _to_json(target.get("connection_info")),
        "description": target.get("description"),
    }


def _finding_row(item: Dict[str, Any]) -> Dict[str, Any]:
    tags = item.get("tags") or []
    evidence = item.get("evidence") or {}
    return {
        "id": item.get("id"),
        "vuln_id": item.get("vuln_id"),
        "title": item.get("title"),
        "severity": item.get("severity"),
        "tags": ", ".join(tags),
        "evidence": _truncate(_to_json(evidence), 220),
    }


def _render_finding_detail(findings: List[Dict[str, Any]]) -> None:
    labels = [f"{item.get('id')} | {item.get('title')}" for item in findings]
    selected = st.selectbox("Finding 상세 보기", options=labels)
    index = labels.index(selected)
    st.json(findings[index])


def _kv_rows(values: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [{"항목": key, "값": value} for key, value in values.items()]


def _to_json(value: Any) -> str:
    if value is None:
        return ""
    return json.dumps(value, ensure_ascii=False)


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."
