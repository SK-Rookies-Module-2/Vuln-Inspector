"""이 파일은 .py 리포팅 모듈로 결과 요약과 보고서 생성을 제공합니다."""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from app.core.config import REPORTS_DIR
from app.core.types import Finding
from app.db import models

SUPPORTED_FORMATS = {"json", "csv"}


def summarize_findings(findings: List[Finding]) -> Dict[str, int]:
    summary: Dict[str, int] = {}
    for finding in findings:
        summary[finding.severity] = summary.get(finding.severity, 0) + 1
    return summary


def generate_report(session: Session, job_id: int, report_format: str) -> models.Report:
    normalized = report_format.strip().lower()
    if normalized not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported format: {report_format}")

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

    generated_at = datetime.utcnow()
    report_dir = _ensure_report_dir(job_id)
    file_path = report_dir / f"report.{normalized}"

    if normalized == "json":
        payload = _build_json_payload(job, target, findings, generated_at)
        _write_json(file_path, payload)
    else:
        _write_csv(file_path, findings)

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


def _ensure_report_dir(job_id: int) -> Path:
    report_dir = REPORTS_DIR / str(job_id)
    report_dir.mkdir(parents=True, exist_ok=True)
    return report_dir


def _build_json_payload(
    job: models.ScanJob,
    target: models.Target,
    findings: List[models.Finding],
    generated_at: datetime,
) -> Dict[str, Any]:
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
    file_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2))


def _write_csv(file_path: Path, findings: List[models.Finding]) -> None:
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
    summary: Dict[str, int] = {}
    for finding in findings:
        summary[finding.severity] = summary.get(finding.severity, 0) + 1
    return summary


def _format_dt(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()
