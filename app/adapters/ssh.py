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
        proxy_command: Optional[str] = None,
        identities_only: bool = False,
        sudo: bool = False,
        sudo_user: Optional[str] = None,
    ) -> None:
        # 접속 대상 호스트/IP
        self.host = host
        # 로그인 사용자명(없으면 현재 사용자로 시도)
        self.user = user
        # SSH 개인키 경로(키 기반 인증)
        self.key_path = key_path
        # 비밀번호(sshpass 필요)
        self.password = password
        # SSH 포트
        self.port = port
        # 연결/명령 타임아웃(초)
        self.timeout = timeout
        # 호스트 키 검증 여부(운영환경에서는 True 권장)
        self.strict_host_key = strict_host_key
        # 점프 호스트(-J user@host:port 형식)
        self.proxy_jump = proxy_jump
        # ProxyCommand 문자열(우선순위가 proxy_jump보다 높다)
        self.proxy_command = proxy_command
        # 지정한 키만 사용하도록 제한할지 여부
        self.identities_only = identities_only
        # sudo 사용 여부(비밀번호 없이 실행되는 경우에만 가능)
        self.sudo = sudo
        # sudo 대상 사용자(옵션)
        self.sudo_user = sudo_user

    def run(self, command: str) -> CommandResult:
        # sudo 옵션이 있으면 먼저 감싼 뒤 SSH 명령을 구성한다.
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
            # 타임아웃은 별도 오류로 표준화한다.
            raise AdapterError("SSH command timeout") from exc
        except OSError as exc:
            # ssh 실행 실패(바이너리 없음/권한 문제 등)
            raise AdapterError(f"SSH execution failed: {exc}") from exc

        # 원격 명령의 종료코드/표준출력/표준에러를 반환한다.
        return CommandResult(result.returncode, result.stdout, result.stderr)

    def _build_command(self, command: str) -> List[str]:
        # 호스트가 없으면 SSH 자체를 구성할 수 없다.
        if not self.host:
            raise AdapterError("SSH host is required")
        # user@host 또는 host 형태로 대상 문자열을 만든다.
        target = f"{self.user}@{self.host}" if self.user else self.host
        ssh_command: List[str] = ["ssh", "-p", str(self.port)]
        # 연결 타임아웃 설정(SSH 레벨)
        ssh_command.extend(["-o", f"ConnectTimeout={self.timeout}"])
        # 점프 호스트가 있으면 프록시 점프 옵션을 붙인다.
        if self.proxy_command:
            ssh_command.extend(["-o", f"ProxyCommand={self.proxy_command}"])
        elif self.proxy_jump:
            ssh_command.extend(["-J", self.proxy_jump])
        # 키 경로가 있으면 키 기반 인증을 사용한다.
        if self.key_path:
            ssh_command.extend(["-i", self.key_path])
        if self.identities_only:
            ssh_command.extend(["-o", "IdentitiesOnly=yes"])
        # 운영 편의를 위해 기본은 호스트 키 검증을 끈다.
        if not self.strict_host_key:
            ssh_command.extend(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"])
        # 대상과 실행할 원격 명령을 마지막에 추가한다.
        ssh_command.append(target)
        ssh_command.append(command)
        return self._with_sshpass(ssh_command)

    def _with_sshpass(self, ssh_command: List[str]) -> List[str]:
        # 비밀번호가 없으면 일반 SSH 명령만 사용한다.
        if not self.password:
            return ssh_command
        # 비밀번호 인증은 sshpass가 필요하다.
        if not shutil.which("sshpass"):
            raise AdapterError("sshpass is required for password authentication")
        # sshpass -p <password> ssh ... 형태로 래핑한다.
        return ["sshpass", "-p", self.password, *ssh_command]

    def _wrap_sudo(self, command: str) -> str:
        # sudo 사용하지 않으면 원본 명령을 그대로 반환한다.
        if not self.sudo:
            return command
        # sudo -n은 비밀번호 입력 없이 실행(비밀번호 요구 시 실패)
        user_flag = f"-u {self.sudo_user}" if self.sudo_user else ""
        return f"sudo -n {user_flag} -- {command}".strip()
