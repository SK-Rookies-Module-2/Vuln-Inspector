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
    # requirements.txt 한 줄에서 주석(#)을 제거하고 의미 있는 내용만 남긴다.
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


def _parse_requirement(line: str) -> Optional[dict]:
    # 한 줄을 분석해 패키지명/연산자/버전을 분리한다.
    cleaned = _strip_inline_comment(line)
    # 빈 줄, include(-r), 옵션(--), editable(-e)은 무시한다.
    if not cleaned or cleaned.startswith(("-r", "--", "-e")):
        return None

    # 연산자(==, >= 등) 위치를 찾는다.
    match = OPERATOR_PATTERN.search(cleaned)
    if not match:
        # 연산자가 없으면 버전 미고정으로 간주한다.
        return {"name": cleaned, "spec": None, "operator": None}

    # 연산자 기준으로 패키지명/버전을 분리한다.
    operator = match.group(1)
    name = cleaned.split(operator, 1)[0].strip()
    spec = cleaned.split(operator, 1)[1].strip()
    return {"name": name, "spec": spec, "operator": operator}


class DependencyCheck(BasePlugin):
    def check(self) -> List[Finding]:
        # 설정에서 매니페스트 경로를 읽고 기본값을 적용한다.
        manifest_path = self.context.config.get("manifest_path", "requirements.txt")
        path = Path(manifest_path)
        # 파일이 없으면 결과 없이 종료한다.
        if not path.exists():
            return self.results

        # 매니페스트를 줄 단위로 파싱한다.
        lines = path.read_text().splitlines()
        for line in lines:
            req = _parse_requirement(line)
            # 파싱 불가/무시 대상이면 건너뛴다.
            if not req:
                continue

            operator = req["operator"]
            # 정확한 고정(==)이 아닐 경우 정책 위반으로 기록한다.
            if operator != "==":
                self.add_finding(
                    vuln_id="POLICY-UNPINNED-DEPENDENCY",
                    title="의존성 버전 미고정(정책 점검)",
                    severity="Info",
                    evidence={
                        "dependency": req["name"],
                        "operator": operator,
                        "spec": req["spec"],
                        "line": line.strip(),
                        "manifest": str(path),
                    },
                    tags=["OWASP:2025:A03"],
                    description="버전 고정 정책 위반 항목입니다.",
                    solution="의존성을 정확한 버전(==)으로 고정하세요.",
                )

        return self.results
