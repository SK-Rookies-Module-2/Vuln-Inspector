"""이 파일은 .py 스캔 실행 모듈로 플러그인 실행과 결과 저장을 담당합니다."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.config import PLUGINS_DIR
from app.core.config_validation import apply_config_schema
from app.core.plugin_loader import PluginLoader, PluginMeta
from app.core.taxonomy import TaxonomyIndex
from app.core.types import Finding as CoreFinding
from app.core.types import PluginContext
from app.db import models


class ScanExecutor:
    def __init__(
        self,
        session: Session,
        plugins_dir: Optional[Path] = None,
        taxonomy: Optional[TaxonomyIndex] = None,
    ) -> None:
        self.session = session
        self.taxonomy = taxonomy or TaxonomyIndex.from_default()
        self.loader = PluginLoader(plugins_dir or PLUGINS_DIR, self.taxonomy)
        self._meta_index = {meta.plugin_id: meta for meta in self.loader.discover()}

    def run_job(self, job: models.ScanJob, target: models.Target) -> List[models.Finding]:
        self._set_job_running(job)
        stored_findings: List[models.Finding] = []

        try:
            scan_config = job.scan_config or {}
            for plugin_id in job.scan_scope or []:
                meta = self._get_meta(plugin_id)
                plugin_config = apply_config_schema(meta.config_schema, scan_config.get(plugin_id, {}))
                scan_config[plugin_id] = plugin_config
                job.scan_config = scan_config
                self.session.commit()
                context = self._build_context(job, target, plugin_config)
                plugin = self.loader.load_plugin(meta, context)
                results = plugin.check()
                stored_findings.extend(self._store_findings(job, results))

            job.status = "COMPLETED"
            job.end_time = datetime.utcnow()
            job.summary = self._summarize(stored_findings)
            job.error_message = None
            self.session.commit()
            return stored_findings
        except Exception as exc:
            job.status = "FAILED"
            job.end_time = datetime.utcnow()
            job.error_message = str(exc)
            self.session.commit()
            raise

    def _set_job_running(self, job: models.ScanJob) -> None:
        job.status = "RUNNING"
        job.start_time = datetime.utcnow()
        self.session.commit()

    def _get_meta(self, plugin_id: str) -> PluginMeta:
        meta = self._meta_index.get(plugin_id)
        if meta is None:
            raise KeyError(f"Plugin not found: {plugin_id}")
        return meta

    def _build_context(
        self,
        job: models.ScanJob,
        target: models.Target,
        plugin_config: Dict,
    ) -> PluginContext:
        target_payload = {
            "id": target.id,
            "name": target.name,
            "type": target.target_type,
            "connection_info": target.connection_info or {},
            "credentials": target.credentials or {},
            "description": target.description,
        }
        return PluginContext(target=target_payload, config=plugin_config, job_id=job.id)

    def _store_findings(
        self,
        job: models.ScanJob,
        results: List[CoreFinding],
    ) -> List[models.Finding]:
        stored: List[models.Finding] = []
        for result in results:
            record = models.Finding(
                job_id=job.id,
                vuln_id=result.vuln_id,
                title=result.title,
                severity=result.severity,
                tags=result.tags,
                description=result.description,
                solution=result.solution,
                evidence=result.evidence,
                raw_data=result.raw_data,
            )
            self.session.add(record)
            stored.append(record)
        self.session.commit()
        return stored

    def _summarize(self, findings: List[models.Finding]) -> Dict[str, int]:
        summary: Dict[str, int] = {}
        for finding in findings:
            summary[finding.severity] = summary.get(finding.severity, 0) + 1
        return summary
