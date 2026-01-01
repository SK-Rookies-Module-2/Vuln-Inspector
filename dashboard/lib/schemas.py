"""대시보드 입력을 위한 간단한 스키마 보조 모듈."""

from __future__ import annotations

import json
from typing import Any, Dict


def parse_json(text: str) -> Dict[str, Any]:
    # 텍스트 입력을 JSON 객체로 변환한다.
    raw = (text or "").strip()
    if not raw:
        return {}
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("JSON 객체만 허용됩니다.")
    return value
