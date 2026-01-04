"""대상/Job/Finding 통합 관리 페이지."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

import streamlit as st

from lib.api_client import APIClient
from lib.schemas import parse_json


@st.cache_data(ttl=5)
def _load_targets(base_url: str, limit: int) -> List[Dict[str, Any]]:
    client = APIClient(base_url)
    return client.list_targets(limit=limit, offset=0)


@st.cache_data(ttl=5)
def _load_jobs(base_url: str, limit: int) -> List[Dict[str, Any]]:
    client = APIClient(base_url)
    return client.list_jobs(limit=limit, offset=0)


@st.cache_data(ttl=5)
def _load_findings(base_url: str, limit: int, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
    client = APIClient(base_url)
    return client.list_findings(limit=limit, offset=0, **filters)


def main() -> None:
    st.header("관리: Targets / Jobs / Findings")

    api_base_url = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
    st.caption(f"API_BASE_URL = {api_base_url}")

    client = APIClient(api_base_url)

    tab_targets, tab_jobs, tab_findings = st.tabs(["Targets", "Jobs", "Findings"])

    with tab_targets:
        st.subheader("대상(Target) 관리")

        with st.form("manage_create_target"):
            name = st.text_input("대상 이름", value="demo-target")
            target_type = st.selectbox("대상 유형", ["SERVER", "WEB_URL", "GIT_REPO"])
            connection_info = st.text_area(
                "connection_info (JSON)",
                value='{"host":"127.0.0.1","port":22}',
            )
            credentials = st.text_area(
                "credentials (JSON)",
                value='{"username":"root","password":"example"}',
            )
            description = st.text_input("설명(선택)", value="")
            submitted = st.form_submit_button("대상 등록")

        if submitted:
            try:
                payload = {
                    "name": name,
                    "type": target_type,
                    "connection_info": parse_json(connection_info),
                    "credentials": parse_json(credentials),
                    "description": description or None,
                }
                result = client.create_target(payload)
                st.success(f"대상 등록 완료: id={result.get('id')}")
                st.cache_data.clear()
            except Exception as exc:
                st.error(str(exc))

        col_get, col_delete = st.columns(2)
        with col_get:
            st.subheader("대상 조회")
            target_id = st.number_input("target_id", min_value=1, step=1, value=1, key="manage_target_id")
            if st.button("조회", key="manage_target_get"):
                try:
                    result = client.get_target(int(target_id))
                    st.json(result)
                except Exception as exc:
                    st.error(str(exc))

        with col_delete:
            st.subheader("대상 삭제")
            delete_target_id = st.number_input(
                "삭제할 target_id", min_value=1, step=1, value=1, key="manage_delete_target_id"
            )
            if st.button("삭제", key="manage_target_delete"):
                try:
                    client.delete_target(int(delete_target_id))
                    st.success("대상 삭제 완료")
                    st.cache_data.clear()
                except Exception as exc:
                    st.error(str(exc))

        st.subheader("대상 목록")
        limit_targets = st.number_input("조회 limit", min_value=10, max_value=1000, value=200, step=50, key="targets_limit")
        if st.button("새로고침", key="targets_refresh"):
            st.cache_data.clear()
        try:
            targets = _load_targets(api_base_url, int(limit_targets))
            st.dataframe(targets, use_container_width=True)
        except Exception as exc:
            st.error(str(exc))

    with tab_jobs:
        st.subheader("Job 관리")

        with st.form("manage_create_job"):
            target_id = st.number_input("target_id", min_value=1, step=1, value=1, key="manage_job_target_id")
            scan_scope = st.text_input("scan_scope (쉼표 구분)", value="remote_linux_kisa_u01")
            scan_config = st.text_area(
                "scan_config (JSON)",
                value=json.dumps({}, ensure_ascii=False, indent=2),
                height=160,
            )
            run_now = st.checkbox("즉시 실행(run_now)", value=True)
            submitted = st.form_submit_button("Job 생성")

        if submitted:
            try:
                payload = {
                    "target_id": int(target_id),
                    "scan_scope": [item.strip() for item in scan_scope.split(",") if item.strip()],
                    "scan_config": parse_json(scan_config),
                    "run_now": run_now,
                }
                result = client.create_job(payload)
                st.success(f"Job 생성 완료: id={result.get('id')}")
                st.json(result)
                st.cache_data.clear()
            except Exception as exc:
                st.error(str(exc))

        col_run, col_status, col_delete = st.columns(3)
        with col_run:
            st.subheader("Job 실행")
            job_id = st.number_input("job_id", min_value=1, step=1, value=1, key="manage_job_run_id")
            if st.button("실행", key="manage_job_run"):
                try:
                    result = client.run_job(int(job_id))
                    st.json(result)
                except Exception as exc:
                    st.error(str(exc))

        with col_status:
            st.subheader("Job 상태")
            job_status_id = st.number_input("job_id", min_value=1, step=1, value=1, key="manage_job_status_id")
            if st.button("상태 조회", key="manage_job_status"):
                try:
                    result = client.get_job_status(int(job_status_id))
                    st.json(result)
                except Exception as exc:
                    st.error(str(exc))

        with col_delete:
            st.subheader("Job 삭제")
            delete_job_id = st.number_input("삭제할 job_id", min_value=1, step=1, value=1, key="manage_delete_job_id")
            if st.button("삭제", key="manage_job_delete"):
                try:
                    client.delete_job(int(delete_job_id))
                    st.success("Job 삭제 완료")
                    st.cache_data.clear()
                except Exception as exc:
                    st.error(str(exc))

        st.subheader("Job 목록")
        limit_jobs = st.number_input("조회 limit", min_value=10, max_value=1000, value=200, step=50, key="jobs_limit")
        if st.button("새로고침", key="jobs_refresh"):
            st.cache_data.clear()
        try:
            jobs = _load_jobs(api_base_url, int(limit_jobs))
            st.dataframe(jobs, use_container_width=True)
        except Exception as exc:
            st.error(str(exc))

    with tab_findings:
        st.subheader("Finding 관리")
        st.caption("Finding은 API에서 생성되지 않으며 스캔 결과로만 생성됩니다.")

        col_query, col_delete = st.columns(2)
        with col_query:
            st.subheader("Finding 조회")
            job_id = st.number_input("job_id", min_value=1, step=1, value=1, key="manage_findings_job_id")
            if st.button("조회", key="manage_findings_get"):
                try:
                    result = client.get_job_findings(int(job_id))
                    st.json(result)
                except Exception as exc:
                    st.error(str(exc))

        with col_delete:
            st.subheader("Finding 삭제")
            delete_finding_id = st.number_input(
                "삭제할 finding_id", min_value=1, step=1, value=1, key="manage_delete_finding_id"
            )
            if st.button("삭제", key="manage_findings_delete"):
                try:
                    client.delete_finding(int(delete_finding_id))
                    st.success("Finding 삭제 완료")
                    st.cache_data.clear()
                except Exception as exc:
                    st.error(str(exc))

        st.subheader("Finding 목록")
        col_filters_1, col_filters_2 = st.columns(2)
        with col_filters_1:
            filter_job_id = st.number_input("job_id (필터)", min_value=1, step=1, value=1, key="manage_filter_job_id")
            filter_severity = st.text_input("severity (필터)", value="", key="manage_filter_severity")
        with col_filters_2:
            filter_target_id = st.number_input("target_id (필터)", min_value=1, step=1, value=1, key="manage_filter_target_id")
            filter_tag = st.text_input("tag (필터)", value="", key="manage_filter_tag")

        filters = {
            "job_id": int(filter_job_id) if filter_job_id else None,
            "target_id": int(filter_target_id) if filter_target_id else None,
            "severity": filter_severity or None,
            "tag": filter_tag or None,
        }

        limit_findings = st.number_input(
            "조회 limit", min_value=10, max_value=1000, value=200, step=50, key="findings_limit"
        )
        if st.button("새로고침", key="findings_refresh"):
            st.cache_data.clear()

        try:
            findings = _load_findings(api_base_url, int(limit_findings), filters)
            st.dataframe(findings, use_container_width=True)
        except Exception as exc:
            st.error(str(exc))


if __name__ == "__main__":
    main()
