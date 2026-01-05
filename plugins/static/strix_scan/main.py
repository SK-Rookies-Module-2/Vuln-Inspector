"""External Strix static scan plugin."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from app.adapters.external.strix import StrixRunner
from app.core.errors import PluginConfigError
from app.core.plugin_base import BasePlugin
from app.core.storage import ensure_artifacts_dir
from app.core.types import Finding
from app.services.report_parsers.strix import parse_strix_report


class StrixStaticScan(BasePlugin):
    def check(self) -> List[Finding]:
        config = self.context.config or {}
        target = self.context.target or {}
        connection = target.get("connection_info", {}) or {}

        repo_url = config.get("repo_url") or connection.get("url")
        repo_path = config.get("repo_path") or connection.get("path")
        repo_ref = config.get("repo_ref")
        if not repo_url and not repo_path:
            raise PluginConfigError("repo_url or repo_path is required for Strix static scan")

        job_id = self.context.job_id or 0
        run_name = config.get("run_name") or f"job-{job_id}-strix-static"
        workdir = self._prepare_workdir(job_id, run_name)

        runner = StrixRunner()
        result = runner.run_static(
            repo_url=repo_url,
            repo_ref=repo_ref,
            repo_path=Path(repo_path) if repo_path else None,
            timeout=int(config.get("timeout", 1800)),
            scan_mode=config.get("scan_mode"),
            instruction=config.get("instruction"),
            instruction_file=config.get("instruction_file"),
            non_interactive=bool(config.get("non_interactive", True)),
            run_name=run_name,
            workdir=workdir,
        )

        run_dir = workdir / "strix_runs" / run_name
        findings = self._parse_or_fallback(run_dir, result)
        self.results.extend(findings)
        return self.results

    def _prepare_workdir(self, job_id: int, run_name: str) -> Path:
        base = ensure_artifacts_dir(job_id)
        workdir = base / "strix" / run_name
        workdir.mkdir(parents=True, exist_ok=True)
        return workdir

    def _parse_or_fallback(self, run_dir: Path, result) -> List[Finding]:
        try:
            findings = parse_strix_report(run_dir)
        except Exception as exc:
            findings = []
            error_message = str(exc)
        else:
            error_message = None

        if findings:
            return findings

        evidence: Dict[str, Optional[str]] = {
            "run_dir": str(run_dir),
            "stdout_log": str(result.stdout_path) if result.stdout_path else None,
            "stderr_log": str(result.stderr_path) if result.stderr_path else None,
            "summary": result.summary,
        }
        return [
            self.add_finding(
                vuln_id="STRIX-EXEC-FAILED",
                title="Strix execution failed",
                severity="Info",
                evidence=evidence,
                tags=["STRIX"],
                description=error_message or "Strix execution failed or report missing.",
                solution="Check Strix logs and report artifacts.",
            )
        ]
