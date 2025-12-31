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
        # API에서 전달된 Job을 실행하기 위한 실행기이며 DB 세션을 사용한다.
        self.session = session
        # 태그 확장(예: KISA → OWASP)을 위한 분류 인덱스를 준비한다.
        self.taxonomy = taxonomy or TaxonomyIndex.from_default()
        # 플러그인 메타데이터 로더를 초기화한다.
        self.loader = PluginLoader(plugins_dir or PLUGINS_DIR, self.taxonomy)
        # 플러그인 ID로 빠르게 찾기 위한 인덱스를 만든다.
        self._meta_index = {meta.plugin_id: meta for meta in self.loader.discover()}

    def run_job(self, job: models.ScanJob, target: models.Target) -> List[models.Finding]:
        # Job을 RUNNING으로 전환하고 실행 시각을 기록한다.
        self._set_job_running(job)
        stored_findings: List[models.Finding] = []

        try:
            # scan_config는 plugin_id -> 설정 딕셔너리 구조다.
            scan_config = job.scan_config or {}
            for plugin_id in job.scan_scope or []:
                # 1) 플러그인 메타 조회
                meta = self._get_meta(plugin_id)
                # 2) config_schema로 설정 검증/기본값 주입
                plugin_config = apply_config_schema(meta.config_schema, scan_config.get(plugin_id, {}))
                # 3) 검증된 설정을 job에 저장(추적/감사 목적)
                scan_config[plugin_id] = plugin_config
                job.scan_config = scan_config
                self.session.commit()
                # 4) Target + config를 PluginContext로 전달
                context = self._build_context(job, target, plugin_config)
                # 5) 플러그인 로드 및 실행
                plugin = self.loader.load_plugin(meta, context)
                results = plugin.check()
                # 6) 결과를 DB에 저장
                stored_findings.extend(self._store_findings(job, results))

            # 정상 종료 시 상태/요약 업데이트
            job.status = "COMPLETED"
            job.end_time = datetime.utcnow()
            job.summary = self._summarize(stored_findings)
            job.error_message = None
            self.session.commit()
            return stored_findings
        except Exception as exc:
            # 오류 발생 시 실패 상태로 저장하고 예외를 전파한다.
            job.status = "FAILED"
            job.end_time = datetime.utcnow()
            job.error_message = str(exc)
            self.session.commit()
            raise

    def _set_job_running(self, job: models.ScanJob) -> None:
        # 실행 시작 상태로 전환한다.
        job.status = "RUNNING"
        job.start_time = datetime.utcnow()
        self.session.commit()

    def _get_meta(self, plugin_id: str) -> PluginMeta:
        # 플러그인 ID로 메타데이터를 조회한다.
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
        # Target 정보를 플러그인에서 사용할 수 있는 형태로 구성한다.
        target_payload = {
            "id": target.id,
            "name": target.name,
            "type": target.target_type,
            "connection_info": target.connection_info or {},
            "credentials": target.credentials or {},
            "description": target.description,
        }
        # PluginContext에 target/config/job_id를 담아 전달한다.
        return PluginContext(target=target_payload, config=plugin_config, job_id=job.id)

    def _store_findings(
        self,
        job: models.ScanJob,
        results: List[CoreFinding],
    ) -> List[models.Finding]:
        # 플러그인 결과를 DB Finding 모델로 변환해 저장한다.
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
        # 심각도별 카운트를 만들어 Job.summary에 저장한다.
        summary: Dict[str, int] = {}
        for finding in findings:
            summary[finding.severity] = summary.get(finding.severity, 0) + 1
        return summary
