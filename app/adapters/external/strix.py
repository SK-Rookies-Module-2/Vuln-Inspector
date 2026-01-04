"""Strix 외부 스캐너 실행 스켈레톤."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from .runner import ExternalRunner, ExternalScanResult


class StrixRunner(ExternalRunner):
    def run_static(
        self,
        *,
        repo_url: Optional[str] = None,
        repo_ref: Optional[str] = None,
        repo_path: Optional[Path] = None,
        timeout: int = 1800,
    ) -> ExternalScanResult:
        # TODO: Strix static 스캔 실행 로직
        raise NotImplementedError("Strix static runner is not implemented")

    def run_dynamic(
        self,
        *,
        base_url: str,
        auth_headers: Optional[dict] = None,
        timeout: int = 1800,
    ) -> ExternalScanResult:
        # TODO: Strix dynamic 스캔 실행 로직
        raise NotImplementedError("Strix dynamic runner is not implemented")
