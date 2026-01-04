"""Strix 리포트 파서 스켈레톤."""

from __future__ import annotations

from pathlib import Path
from typing import List

from app.core.types import Finding


def parse_strix_report(report_path: Path) -> List[Finding]:
    # TODO: Strix 리포트를 Finding 리스트로 변환
    raise NotImplementedError("Strix report parser is not implemented")
