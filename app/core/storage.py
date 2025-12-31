"""이 파일은 .py 저장 경로 모듈로 아티팩트/증적/리포트 디렉터리를 관리합니다."""

from __future__ import annotations

from pathlib import Path

from .config import REPORTS_DIR, STORAGE_DIR


def ensure_reports_dir(job_id: int) -> Path:
    # 보고서 저장 경로를 생성하고 반환한다.
    path = REPORTS_DIR / str(job_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_evidences_dir(job_id: int) -> Path:
    # 진단 증적(로그/스크린샷 등) 저장 경로를 생성한다.
    path = STORAGE_DIR / "evidences" / str(job_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_artifacts_dir(job_id: int) -> Path:
    # 빌드/클론 등 부가 산출물 저장 경로를 생성한다.
    path = STORAGE_DIR / "artifacts" / str(job_id)
    path.mkdir(parents=True, exist_ok=True)
    return path
