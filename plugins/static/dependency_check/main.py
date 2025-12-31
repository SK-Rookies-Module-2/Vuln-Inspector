"""이 파일은 .py 정적 분석 플러그인 모듈로 의존성 고정 여부를 점검합니다."""

from __future__ import annotations

from pathlib import Path
import re
from typing import List, Optional

from app.core.plugin_base import BasePlugin
from app.core.types import Finding

VERSION_OPERATORS = ("==", ">=", "<=", "~=", "!=", ">", "<")
OPERATOR_PATTERN = re.compile(r"(==|>=|<=|~=|!=|>|<)")


def _strip_inline_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


def _parse_requirement(line: str) -> Optional[dict]:
    cleaned = _strip_inline_comment(line)
    if not cleaned or cleaned.startswith(("-r", "--", "-e")):
        return None

    match = OPERATOR_PATTERN.search(cleaned)
    if not match:
        return {"name": cleaned, "spec": None, "operator": None}

    operator = match.group(1)
    name = cleaned.split(operator, 1)[0].strip()
    spec = cleaned.split(operator, 1)[1].strip()
    return {"name": name, "spec": spec, "operator": operator}


class DependencyCheck(BasePlugin):
    def check(self) -> List[Finding]:
        manifest_path = self.context.config.get("manifest_path", "requirements.txt")
        path = Path(manifest_path)
        if not path.exists():
            return self.results

        lines = path.read_text().splitlines()
        for line in lines:
            req = _parse_requirement(line)
            if not req:
                continue

            operator = req["operator"]
            if operator != "==":
                self.add_finding(
                    vuln_id="KISA-STATIC-UNPINNED",
                    title="의존성 버전 미고정",
                    severity="Medium",
                    evidence={
                        "dependency": req["name"],
                        "operator": operator,
                        "spec": req["spec"],
                        "line": line.strip(),
                        "manifest": str(path),
                    },
                    tags=["OWASP:2025:A03"],
                    description="버전이 고정되지 않으면 공급망 리스크가 증가합니다.",
                    solution="의존성을 정확한 버전으로 고정하세요.",
                )

        return self.results
