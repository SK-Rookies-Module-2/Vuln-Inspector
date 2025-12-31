"""이 파일은 .py 원격 점검 플러그인 모듈로 SSH 설정의 root 로그인 허용 여부를 검사합니다."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from app.adapters.ssh import SshClient
from app.core.errors import PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.types import Finding

WEAK_VALUES = {"yes", "without-password", "prohibit-password", "forced-commands-only"}


def _parse_permit_root_login(lines: List[str]) -> Optional[str]:
    # sshd_config 라인 목록에서 PermitRootLogin 값을 추출한다.
    for raw_line in lines:
        line = raw_line.strip()
        # 공백/주석 라인은 무시한다.
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("permitrootlogin"):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1].lower()
    return None


def _read_local_config(config_path: Path) -> Optional[List[str]]:
    # 로컬 파일 경로가 있으면 파일 내용을 읽어 라인 리스트로 반환한다.
    if not config_path.exists():
        return None
    return config_path.read_text().splitlines()


def _read_remote_config(target: dict, config_path: Path, config: dict) -> Optional[List[str]]:
    # Target에서 접속 정보를 추출한다.
    connection = target.get("connection_info", {}) or {}
    credentials = target.get("credentials", {}) or {}
    host = connection.get("host") or connection.get("ip")
    user = credentials.get("username")
    key_path = credentials.get("key_path")
    password = credentials.get("password")
    port = int(connection.get("port", 22))
    proxy_jump = connection.get("proxy_jump")

    # 필수 정보가 없으면 원격 접근을 시도하지 않는다.
    if not host or not user:
        return None
    if not key_path and not password:
        return None

    # SSH 클라이언트를 구성한다(키 또는 비밀번호 인증).
    client = SshClient(
        host=host,
        user=user,
        key_path=key_path,
        password=password,
        port=port,
        proxy_jump=proxy_jump,
        sudo=bool(config.get("use_sudo", False)),
        sudo_user=config.get("sudo_user"),
    )
    # 원격 서버에서 sshd_config를 읽는다.
    result = client.run(f"cat {config_path}")
    if result.exit_code != 0:
        raise PluginConfigError(f"SSH command failed: {result.stderr.strip()}")
    return result.stdout.splitlines()


class RootLoginCheck(BasePlugin):
    def check(self) -> List[Finding]:
        # 설정에서 sshd_config 경로를 읽고 기본값을 적용한다.
        config_path = Path(self.context.config.get("sshd_config_path", "/etc/ssh/sshd_config"))
        # 먼저 로컬 파일을 읽고, 없으면 원격 SSH로 읽는다.
        lines = _read_local_config(config_path)
        remote_used = False
        if lines is None:
            lines = _read_remote_config(self.context.target, config_path, self.context.config)
            remote_used = lines is not None
        if lines is None:
            # 로컬/원격 모두 실패하면 설정 오류로 처리한다.
            raise PluginConfigError("Missing SSH config path or remote credentials")

        # PermitRootLogin 값만 추출한다.
        value = _parse_permit_root_login(lines)
        if value in WEAK_VALUES:
            # 증적에 경로/모드/호스트를 남긴다.
            evidence = {
                "config_path": str(config_path),
                "permit_root_login": value,
                "mode": "ssh" if remote_used else "local",
            }
            if remote_used:
                evidence["host"] = self.context.target.get("connection_info", {}).get("host")
            self.add_finding(
                vuln_id="KISA-U-01",
                title="SSH root 원격 로그인 허용",
                severity="High",
                evidence=evidence,
                tags=["KISA:U-01"],
                description="SSH 설정에서 root 원격 로그인이 허용되어 있습니다.",
                solution="PermitRootLogin 값을 no로 설정하고 SSH를 재시작하세요.",
            )
        return self.results
