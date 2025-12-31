"""이 파일은 .py 정적 분석 플러그인 모듈로 의존성 고정 여부를 점검합니다."""

from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess
from typing import List, Optional

from app.core.errors import PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.storage import ensure_artifacts_dir
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


def _clone_repo(repo_url: str, dest_dir: Path, ref: Optional[str]) -> Path:
    # git 명령이 없으면 클론을 수행할 수 없다.
    if not shutil.which("git"):
        raise PluginConfigError("git binary not found for repository clone")
    if dest_dir.exists():
        return dest_dir

    clone_command = ["git", "clone", "--depth", "1"]
    if ref:
        clone_command.extend(["--branch", ref])
    clone_command.extend([repo_url, str(dest_dir)])
    result = subprocess.run(clone_command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise PluginConfigError(f"git clone failed: {result.stderr.strip()}")

    if ref:
        checkout = subprocess.run(
            ["git", "-C", str(dest_dir), "checkout", ref],
            capture_output=True,
            text=True,
            check=False,
        )
        if checkout.returncode != 0:
            raise PluginConfigError(f"git checkout failed: {checkout.stderr.strip()}")
    return dest_dir


def _resolve_manifest_path(context, manifest_path: str) -> Optional[Path]:
    # 절대 경로면 해당 파일을 우선 사용한다.
    path = Path(manifest_path)
    if path.is_absolute() and path.exists():
        return path

    # Target에 로컬 경로가 있으면 상대 경로로 결합한다.
    target_info = context.target.get("connection_info", {}) or {}
    target_path = target_info.get("path") or context.target.get("path")
    if target_path:
        candidate = Path(target_path) / manifest_path
        if candidate.exists():
            return candidate

    # Git URL이 있으면 artifacts로 클론하여 검사한다.
    repo_url = context.config.get("repo_url") or target_info.get("url")
    if repo_url:
        job_id = context.job_id if context.job_id is not None else 0
        artifacts_dir = ensure_artifacts_dir(job_id)
        repo_dir = artifacts_dir / "repo"
        repo_ref = context.config.get("repo_ref")
        _clone_repo(repo_url, repo_dir, repo_ref)
        candidate = repo_dir / manifest_path
        if candidate.exists():
            return candidate

    return None


class DependencyCheck(BasePlugin):
    def check(self) -> List[Finding]:
        # 설정에서 매니페스트 경로를 읽고 기본값을 적용한다.
        manifest_path = self.context.config.get("manifest_path", "requirements.txt")
        path = _resolve_manifest_path(self.context, manifest_path)
        # 경로를 찾지 못하면 결과 없이 종료한다.
        if path is None:
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
