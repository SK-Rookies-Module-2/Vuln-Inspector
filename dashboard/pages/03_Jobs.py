"""스캔 Job 생성/실행 페이지."""

from __future__ import annotations

import json
import os

import streamlit as st

from lib.api_client import APIClient
from lib.schemas import parse_json


def _parse_scope(text: str) -> list[str]:
    # 쉼표로 구분된 플러그인 ID 입력을 리스트로 변환한다.
    scope = [item.strip() for item in text.split(",") if item.strip()]
    return scope


def main() -> None:
    st.header("스캔 실행")

    api_base_url = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
    client = APIClient(api_base_url)

    st.subheader("Job 목록")
    list_target_id = st.text_input("target_id (선택)", value="")
    list_status = st.text_input("status (선택)", value="")
    list_limit = st.number_input("limit", min_value=1, max_value=1000, value=100, step=10, key="job_limit")
    list_offset = st.number_input("offset", min_value=0, value=0, step=10, key="job_offset")
    if st.button("Job 목록 조회"):
        try:
            target_id = int(list_target_id) if list_target_id.strip() else None
            status = list_status.strip() or None
            result = client.list_jobs(
                target_id=target_id,
                status=status,
                limit=int(list_limit),
                offset=int(list_offset),
            )
            st.dataframe(result, use_container_width=True)
        except Exception as exc:
            st.error(str(exc))

    st.subheader("Job 생성")
    with st.form("create_job"):
        target_id = st.number_input("target_id", min_value=1, step=1, value=1)
        scan_scope = st.text_input(
            "scan_scope (쉼표 구분)",
            value="static_dependency_check,remote_linux_kisa_u01",
        )
        scan_config = st.text_area(
            "scan_config (JSON)",
            value=json.dumps(
                {
                    "static_dependency_check": {"manifest_path": "requirements.txt"},
                    "remote_linux_kisa_u01": {"ssh_port": 22, "use_sudo": False},
                },
                ensure_ascii=False,
                indent=2,
            ),
            height=200,
        )
        run_now = st.checkbox("즉시 실행(run_now)", value=True)
        submitted = st.form_submit_button("Job 생성")

    if submitted:
        try:
            payload = {
                "target_id": int(target_id),
                "scan_scope": _parse_scope(scan_scope),
                "scan_config": parse_json(scan_config),
                "run_now": run_now,
            }
            result = client.create_job(payload)
            st.success(f"Job 생성 완료: id={result.get('id')}")
            st.json(result)
        except Exception as exc:
            st.error(str(exc))

    st.subheader("Job 수동 실행")
    job_id = st.number_input("job_id", min_value=1, step=1, value=1, key="job_run_id")
    if st.button("실행"):
        try:
            result = client.run_job(int(job_id))
            st.json(result)
        except Exception as exc:
            st.error(str(exc))

    st.subheader("Job 상태 조회")
    job_status_id = st.number_input("job_id", min_value=1, step=1, value=1, key="job_status_id")
    if st.button("상태 조회"):
        try:
            result = client.get_job_status(int(job_status_id))
            st.json(result)
        except Exception as exc:
            st.error(str(exc))


if __name__ == "__main__":
    main()
