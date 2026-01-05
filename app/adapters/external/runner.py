"""External scanner runner utilities."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import signal
import subprocess
from time import perf_counter
from contextlib import nullcontext
from typing import Optional, Sequence


@dataclass
class ExternalScanResult:
    exit_code: int
    report_path: Optional[Path] = None
    log_path: Optional[Path] = None
    stdout_path: Optional[Path] = None
    stderr_path: Optional[Path] = None
    summary: Optional[str] = None
    duration_ms: Optional[int] = None


class ExternalRunner:
    def run(
        self,
        command: Sequence[str],
        workdir: Optional[Path] = None,
        timeout: int = 1800,
    ) -> ExternalScanResult:
        if not command:
            raise ValueError("Command must not be empty")

        resolved_workdir = Path(workdir) if workdir else None
        if resolved_workdir:
            resolved_workdir.mkdir(parents=True, exist_ok=True)

        stdout_path = resolved_workdir / "stdout.log" if resolved_workdir else None
        stderr_path = resolved_workdir / "stderr.log" if resolved_workdir else None
        start = perf_counter()

        def _open(path: Optional[Path]):
            if path is None:
                return nullcontext(subprocess.DEVNULL)
            return path.open("w", encoding="utf-8")

        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
            preexec_fn = None
        else:
            creationflags = 0
            preexec_fn = os.setsid

        with _open(stdout_path) as stdout_handle, _open(stderr_path) as stderr_handle:
            process = subprocess.Popen(
                list(command),
                stdout=stdout_handle,
                stderr=stderr_handle,
                cwd=str(resolved_workdir) if resolved_workdir else None,
                text=True,
                preexec_fn=preexec_fn,
                creationflags=creationflags,
            )
            try:
                exit_code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                _terminate_process(process)
                exit_code = -1

        duration_ms = int((perf_counter() - start) * 1000)
        summary = f"exit_code={exit_code} duration_ms={duration_ms}"

        return ExternalScanResult(
            exit_code=exit_code,
            log_path=stdout_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            summary=summary,
            duration_ms=duration_ms,
        )


def _terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except Exception:
        process.kill()
