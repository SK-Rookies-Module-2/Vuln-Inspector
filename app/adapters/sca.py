"""이 파일은 .py SCA 어댑터로 외부 도구 실행을 래핑합니다."""

from __future__ import annotations

from dataclasses import dataclass
import subprocess
from typing import List, Optional

from app.core.errors import AdapterError


@dataclass
class ToolResult:
    exit_code: int
    stdout: str
    stderr: str


class ScaRunner:
    def __init__(self, timeout: int = 30) -> None:
        self.timeout = timeout

    def run(self, command: List[str], cwd: Optional[str] = None) -> ToolResult:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
                cwd=cwd,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdapterError("SCA command timeout") from exc
        except OSError as exc:
            raise AdapterError(f"SCA execution failed: {exc}") from exc

        return ToolResult(result.returncode, result.stdout, result.stderr)
