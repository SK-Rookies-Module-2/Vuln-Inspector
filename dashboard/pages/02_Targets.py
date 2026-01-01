"""대상 등록/조회 페이지."""

from __future__ import annotations

import os

import streamlit as st

from lib.api_client import APIClient
from lib.schemas import parse_json


def main() -> None:
    st.header("대상 등록/조회")

    api_base_url = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
    client = APIClient(api_base_url)

    st.subheader("대상 등록")
    with st.form("create_target"):
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
        submitted = st.form_submit_button("등록")

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
            st.json(result)
        except Exception as exc:
            st.error(str(exc))

    st.subheader("대상 조회")
    target_id = st.number_input("target_id", min_value=1, step=1, value=1)
    if st.button("조회"):
        try:
            result = client.get_target(int(target_id))
            st.json(result)
        except Exception as exc:
            st.error(str(exc))

    st.subheader("대상 삭제")
    delete_target_id = st.number_input("삭제할 target_id", min_value=1, step=1, value=1, key="delete_target_id")
    if st.button("삭제"):
        try:
            client.delete_target(int(delete_target_id))
            st.success("대상 삭제 완료")
        except Exception as exc:
            st.error(str(exc))


if __name__ == "__main__":
    main()
