"""이 파일은 .py 리포팅 모듈로 결과 요약과 보고서 생성을 제공합니다."""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from app.core.storage import ensure_reports_dir
from app.core.types import Finding
from app.db import models

SUPPORTED_FORMATS = {"json", "csv"}


def summarize_findings(findings: List[Finding]) -> Dict[str, int]:
    # 심각도별로 카운트를 집계해 요약 정보를 만든다.
    summary: Dict[str, int] = {}
    for finding in findings:
        summary[finding.severity] = summary.get(finding.severity, 0) + 1
    return summary


def generate_report(session: Session, job_id: int, report_format: str) -> models.Report:
    # 지원 여부를 확인하고 형식을 정규화한다.
    normalized = report_format.strip().lower()
    if normalized not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported format: {report_format}")

    # Job과 Target을 조회한다.
    job = session.get(models.ScanJob, job_id)
    if job is None:
        raise KeyError("Job not found")
    target = session.get(models.Target, job.target_id)
    if target is None:
        raise KeyError("Target not found")

    findings = (
        session.query(models.Finding)
        .filter(models.Finding.job_id == job_id)
        .order_by(models.Finding.id.asc())
        .all()
    )

    # 보고서 파일을 생성할 디렉토리를 준비한다.
    generated_at = datetime.utcnow()
    report_dir = ensure_reports_dir(job_id)
    file_path = report_dir / f"report.{normalized}"

    # 형식별로 파일을 작성한다.
    if normalized == "json":
        payload = _build_json_payload(job, target, findings, generated_at)
        _write_json(file_path, payload)
    else:
        _write_csv(file_path, findings)

    # 보고서 메타데이터를 DB에 저장한다.
    report = models.Report(
        job_id=job_id,
        format=normalized.upper(),
        file_path=str(file_path),
        generated_at=generated_at,
    )
    session.add(report)
    session.commit()
    session.refresh(report)
    return report


def _build_json_payload(
    job: models.ScanJob,
    target: models.Target,
    findings: List[models.Finding],
    generated_at: datetime,
) -> Dict[str, Any]:
    # Job/Target/Findings를 하나의 JSON 페이로드로 구성한다.
    summary = job.summary or _summarize_db_findings(findings)
    return {
        "job": {
            "id": job.id,
            "status": job.status,
            "scan_scope": job.scan_scope,
            "scan_config": job.scan_config,
            "start_time": _format_dt(job.start_time),
            "end_time": _format_dt(job.end_time),
            "summary": summary,
        },
        "target": {
            "id": target.id,
            "name": target.name,
            "type": target.target_type,
            "connection_info": target.connection_info,
            "description": target.description,
        },
        "findings": [_finding_to_dict(item) for item in findings],
        "generated_at": _format_dt(generated_at),
    }


def _write_json(file_path: Path, payload: Dict[str, Any]) -> None:
    # JSON 파일로 직렬화해 저장한다.
    file_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2))


def _write_csv(file_path: Path, findings: List[models.Finding]) -> None:
    # CSV 헤더를 고정하고 Finding 데이터를 기록한다.
    rows = [_finding_to_dict(item) for item in findings]
    fieldnames = [
        "id",
        "job_id",
        "vuln_id",
        "title",
        "severity",
        "tags",
        "description",
        "solution",
        "evidence",
        "raw_data",
    ]
    with file_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _finding_to_dict(item: models.Finding) -> Dict[str, Any]:
    # ORM Finding을 직렬화 가능한 딕셔너리로 변환한다.
    return {
        "id": item.id,
        "job_id": item.job_id,
        "vuln_id": item.vuln_id,
        "title": item.title,
        "severity": item.severity,
        "tags": ",".join(item.tags or []),
        "description": item.description,
        "solution": item.solution,
        "evidence": json.dumps(item.evidence or {}, ensure_ascii=False),
        "raw_data": json.dumps(item.raw_data or {}, ensure_ascii=False),
    }


def _summarize_db_findings(findings: List[models.Finding]) -> Dict[str, int]:
    # DB Finding 리스트로 요약 정보를 만든다.
    summary: Dict[str, int] = {}
    for finding in findings:
        summary[finding.severity] = summary.get(finding.severity, 0) + 1
    return summary


def _format_dt(value: datetime | None) -> str | None:
    # datetime을 ISO 문자열로 변환한다.
    if value is None:
        return None
    return value.isoformat()
