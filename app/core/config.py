"""이 파일은 .py 설정 모듈로 경로와 기본 위치를 정의합니다."""

import os
from pathlib import Path
from urllib.parse import quote_plus

from dotenv import load_dotenv

load_dotenv()

REPO_ROOT = Path(__file__).resolve().parents[2]
APP_DIR = REPO_ROOT / "app"
PLUGINS_DIR = REPO_ROOT / "plugins"
STORAGE_DIR = REPO_ROOT / "storage"
REPORTS_DIR = STORAGE_DIR / "reports"
DB_USER = os.getenv("DB_USER", "vuln")
DB_PASSWORD = os.getenv("DB_PASSWORD", "vuln")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "vuln_inspector")

DEFAULT_DATABASE_URL = (
    "postgresql+psycopg://"
    f"{quote_plus(DB_USER)}:{quote_plus(DB_PASSWORD)}@"
    f"{DB_HOST}:{DB_PORT}/{DB_NAME}"
)
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)
API_PREFIX = "/api/v1"
