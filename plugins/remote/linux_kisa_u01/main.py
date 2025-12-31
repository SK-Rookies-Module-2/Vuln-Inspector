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
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("permitrootlogin"):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1].lower()
    return None


def _read_local_config(config_path: Path) -> Optional[List[str]]:
    if not config_path.exists():
        return None
    return config_path.read_text().splitlines()


def _read_remote_config(target: dict, config_path: Path, config: dict) -> Optional[List[str]]:
    connection = target.get("connection_info", {}) or {}
    credentials = target.get("credentials", {}) or {}
    host = connection.get("host") or connection.get("ip")
    user = credentials.get("username")
    key_path = credentials.get("key_path")
    password = credentials.get("password")
    port = int(connection.get("port", 22))
    proxy_jump = connection.get("proxy_jump")

    if not host or not user:
        return None
    if not key_path and not password:
        return None

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
    result = client.run(f"cat {config_path}")
    if result.exit_code != 0:
        raise PluginConfigError(f"SSH command failed: {result.stderr.strip()}")
    return result.stdout.splitlines()


class RootLoginCheck(BasePlugin):
    def check(self) -> List[Finding]:
        config_path = Path(self.context.config.get("sshd_config_path", "/etc/ssh/sshd_config"))
        lines = _read_local_config(config_path)
        remote_used = False
        if lines is None:
            lines = _read_remote_config(self.context.target, config_path, self.context.config)
            remote_used = lines is not None
        if lines is None:
            raise PluginConfigError("Missing SSH config path or remote credentials")

        value = _parse_permit_root_login(lines)
        if value in WEAK_VALUES:
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
