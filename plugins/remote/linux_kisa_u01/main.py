"""이 파일은 .py 원격 점검 플러그인 모듈로 SSH 설정의 root 로그인 허용 여부를 검사합니다."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from app.core.plugin_base import BasePlugin
from app.core.types import Finding

WEAK_VALUES = {"yes", "without-password", "prohibit-password", "forced-commands-only"}


def _parse_permit_root_login(config_path: Path) -> Optional[str]:
    if not config_path.exists():
        return None

    for raw_line in config_path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("permitrootlogin"):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1].lower()
    return None


class RootLoginCheck(BasePlugin):
    def check(self) -> List[Finding]:
        config_path = Path(self.context.config.get("sshd_config_path", "/etc/ssh/sshd_config"))
        value = _parse_permit_root_login(config_path)
        if value in WEAK_VALUES:
            self.add_finding(
                vuln_id="KISA-U-01",
                title="SSH root 원격 로그인 허용",
                severity="High",
                evidence={
                    "config_path": str(config_path),
                    "permit_root_login": value,
                },
                tags=["KISA:U-01"],
                description="SSH 설정에서 root 원격 로그인이 허용되어 있습니다.",
                solution="PermitRootLogin 값을 no로 설정하고 SSH를 재시작하세요.",
            )
        return self.results
