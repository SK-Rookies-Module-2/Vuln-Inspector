"""이 파일은 .py 저장 경로 모듈로 아티팩트/증적/리포트 디렉터리를 관리합니다."""

from __future__ import annotations

from pathlib import Path

from .config import REPORTS_DIR, STORAGE_DIR


def ensure_reports_dir(job_id: int) -> Path:
    path = REPORTS_DIR / str(job_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_evidences_dir(job_id: int) -> Path:
    path = STORAGE_DIR / "evidences" / str(job_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_artifacts_dir(job_id: int) -> Path:
    path = STORAGE_DIR / "artifacts" / str(job_id)
    path.mkdir(parents=True, exist_ok=True)
    return path
