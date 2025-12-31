"""이 파일은 .py 로깅 초기화 모듈로 기본 로그 포맷을 설정합니다."""

import logging


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
