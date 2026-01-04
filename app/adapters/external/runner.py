"""외부 스캐너 실행 스켈레톤."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence


@dataclass
class ExternalScanResult:
    exit_code: int
    report_path: Optional[Path] = None
    log_path: Optional[Path] = None
    summary: Optional[str] = None


class ExternalRunner:
    def run(
        self,
        command: Sequence[str],
        workdir: Optional[Path] = None,
        timeout: int = 1800,
    ) -> ExternalScanResult:
        # TODO: 외부 도구 실행/로그 캡처 구현
        raise NotImplementedError("External runner is not implemented")
