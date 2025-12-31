"""이 파일은 .py SSH 어댑터로 원격 명령 실행을 제공합니다."""

from __future__ import annotations

from dataclasses import dataclass
import subprocess
from typing import List, Optional

from app.core.errors import AdapterError


@dataclass
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str


class SshClient:
    def __init__(
        self,
        host: str,
        user: Optional[str] = None,
        key_path: Optional[str] = None,
        port: int = 22,
        timeout: int = 10,
        strict_host_key: bool = False,
    ) -> None:
        self.host = host
        self.user = user
        self.key_path = key_path
        self.port = port
        self.timeout = timeout
        self.strict_host_key = strict_host_key

    def run(self, command: str) -> CommandResult:
        ssh_command = self._build_command(command)
        try:
            result = subprocess.run(
                ssh_command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdapterError("SSH command timeout") from exc
        except OSError as exc:
            raise AdapterError(f"SSH execution failed: {exc}") from exc

        return CommandResult(result.returncode, result.stdout, result.stderr)

    def _build_command(self, command: str) -> List[str]:
        target = f"{self.user}@{self.host}" if self.user else self.host
        ssh_command = ["ssh", "-p", str(self.port)]
        if self.key_path:
            ssh_command.extend(["-i", self.key_path])
        if not self.strict_host_key:
            ssh_command.extend(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"])
        ssh_command.append(target)
        ssh_command.append(command)
        return ssh_command
