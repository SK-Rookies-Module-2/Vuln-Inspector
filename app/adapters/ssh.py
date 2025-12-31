"""이 파일은 .py SSH 어댑터로 원격 명령 실행을 제공합니다."""

from __future__ import annotations

from dataclasses import dataclass
import shutil
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
        password: Optional[str] = None,
        port: int = 22,
        timeout: int = 10,
        strict_host_key: bool = False,
        proxy_jump: Optional[str] = None,
        sudo: bool = False,
        sudo_user: Optional[str] = None,
    ) -> None:
        self.host = host
        self.user = user
        self.key_path = key_path
        self.password = password
        self.port = port
        self.timeout = timeout
        self.strict_host_key = strict_host_key
        self.proxy_jump = proxy_jump
        self.sudo = sudo
        self.sudo_user = sudo_user

    def run(self, command: str) -> CommandResult:
        ssh_command = self._build_command(self._wrap_sudo(command))
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
        if not self.host:
            raise AdapterError("SSH host is required")
        target = f"{self.user}@{self.host}" if self.user else self.host
        ssh_command: List[str] = ["ssh", "-p", str(self.port)]
        ssh_command.extend(["-o", f"ConnectTimeout={self.timeout}"])
        if self.proxy_jump:
            ssh_command.extend(["-J", self.proxy_jump])
        if self.key_path:
            ssh_command.extend(["-i", self.key_path])
        if not self.strict_host_key:
            ssh_command.extend(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"])
        ssh_command.append(target)
        ssh_command.append(command)
        return self._with_sshpass(ssh_command)

    def _with_sshpass(self, ssh_command: List[str]) -> List[str]:
        if not self.password:
            return ssh_command
        if not shutil.which("sshpass"):
            raise AdapterError("sshpass is required for password authentication")
        return ["sshpass", "-p", self.password, *ssh_command]

    def _wrap_sudo(self, command: str) -> str:
        if not self.sudo:
            return command
        user_flag = f"-u {self.sudo_user}" if self.sudo_user else ""
        return f"sudo -n {user_flag} -- {command}".strip()
