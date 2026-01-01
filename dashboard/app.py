"""Streamlit 대시보드 진입점."""

from __future__ import annotations

import os

import streamlit as st


def main() -> None:
    # 기본 페이지 구성과 API URL 안내를 제공한다.
    st.set_page_config(page_title="Vuln Inspector Dashboard", layout="wide")
    st.title("Vuln Inspector 대시보드")
    st.caption("API 기반 진단 흐름을 실행/모니터링하기 위한 Streamlit 대시보드입니다.")

    api_base_url = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
    st.info(f"API_BASE_URL = {api_base_url}")

    st.markdown(
        """
        - 좌측 사이드바의 페이지를 통해 대상 등록, 스캔 실행, 결과 확인을 진행합니다.
        - API 서버가 실행 중이어야 동작합니다.
        """
    )


if __name__ == "__main__":
    main()
