"""이 파일은 .py 설정 모듈로 경로와 기본 위치를 정의합니다."""

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
APP_DIR = REPO_ROOT / "app"
PLUGINS_DIR = REPO_ROOT / "plugins"
DATA_DIR = APP_DIR / "data"
MAPPINGS_DIR = DATA_DIR / "mappings"
DEFAULT_MAPPING_FILE = MAPPINGS_DIR / "kisa_owasp.yml"
STORAGE_DIR = REPO_ROOT / "storage"
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{(STORAGE_DIR / 'vuln_inspector.db').as_posix()}",
)
API_PREFIX = "/api/v1"
