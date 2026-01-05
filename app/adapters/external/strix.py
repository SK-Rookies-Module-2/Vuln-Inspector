"""Strix external scanner runner."""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Sequence

from .runner import ExternalRunner, ExternalScanResult


class StrixRunner(ExternalRunner):
    def _build_command(
        self,
        target: str,
        *,
        scan_mode: Optional[str] = None,
        instruction: Optional[str] = None,
        instruction_file: Optional[str] = None,
        non_interactive: bool = True,
        run_name: Optional[str] = None,
    ) -> Sequence[str]:
        cmd = ["strix"]
        if non_interactive:
            cmd.append("-n")
        cmd.extend(["--target", target])
        if scan_mode:
            cmd.extend(["--scan-mode", scan_mode])
        if instruction_file:
            cmd.extend(["--instruction-file", instruction_file])
        elif instruction:
            cmd.extend(["--instruction", instruction])
        if run_name:
            cmd.extend(["--run-name", run_name])
        return cmd

    def run_static(
        self,
        *,
        repo_url: Optional[str] = None,
        repo_ref: Optional[str] = None,
        repo_path: Optional[Path] = None,
        timeout: int = 1800,
        scan_mode: Optional[str] = None,
        instruction: Optional[str] = None,
        instruction_file: Optional[str] = None,
        non_interactive: bool = True,
        run_name: Optional[str] = None,
        workdir: Optional[Path] = None,
    ) -> ExternalScanResult:
        target = None
        if repo_path:
            target = str(repo_path)
        elif repo_url:
            target = repo_url
        if not target:
            raise ValueError("repo_path or repo_url is required for static scan")

        command = self._build_command(
            target,
            scan_mode=scan_mode,
            instruction=instruction,
            instruction_file=instruction_file,
            non_interactive=non_interactive,
            run_name=run_name,
        )
        return self.run(command=command, workdir=workdir, timeout=timeout)

    def run_dynamic(
        self,
        *,
        base_url: str,
        auth_headers: Optional[dict] = None,
        timeout: int = 1800,
        scan_mode: Optional[str] = None,
        instruction: Optional[str] = None,
        instruction_file: Optional[str] = None,
        non_interactive: bool = True,
        run_name: Optional[str] = None,
        workdir: Optional[Path] = None,
    ) -> ExternalScanResult:
        if not base_url:
            raise ValueError("base_url is required for dynamic scan")

        command = self._build_command(
            base_url,
            scan_mode=scan_mode,
            instruction=instruction,
            instruction_file=instruction_file,
            non_interactive=non_interactive,
            run_name=run_name,
        )
        return self.run(command=command, workdir=workdir, timeout=timeout)
