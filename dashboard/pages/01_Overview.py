"""대시보드 요약 페이지."""

from __future__ import annotations

import os

import streamlit as st


def main() -> None:
    st.header("요약 대시보드")
    st.write("현재 제공되는 API는 상세 목록 조회가 제한되어 있어, 요약 정보는 수동 입력 기반으로 제공합니다.")

    api_base_url = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
    st.code(api_base_url)

    st.markdown(
        """
        - 대상/Job 목록 조회 API가 아직 없으므로, 각 페이지에서 ID 기반 조회를 사용합니다.
        - 향후 목록 API가 추가되면 이 화면에 통계 위젯을 확장할 수 있습니다.
        """
    )


if __name__ == "__main__":
    main()
