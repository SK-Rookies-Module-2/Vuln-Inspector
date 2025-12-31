"""이 파일은 .py 엔트리포인트로 오케스트레이터 기본 실행을 제공합니다."""

from app.core.logging import setup_logging
from app.services.orchestrator import Orchestrator


def main() -> None:
    setup_logging()
    orchestrator = Orchestrator()
    orchestrator.run()


if __name__ == "__main__":
    main()
