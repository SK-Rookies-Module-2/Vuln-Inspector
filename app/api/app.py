"""이 파일은 .py FastAPI 앱 모듈로 REST 엔드포인트를 제공합니다."""

from __future__ import annotations

from pathlib import Path
from typing import List

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.config import API_PREFIX
from app.core.errors import PluginConfigError
from app.db import models
from app.db.session import get_session, init_db
from app.services.scan_executor import ScanExecutor
from app.services.reporting import generate_report

from .schemas import (
    FindingResponse,
    JobCreate,
    JobResponse,
    JobStatusResponse,
    ReportCreate,
    ReportResponse,
    TargetCreate,
    TargetResponse,
)

app = FastAPI(title="vuln-inspector")


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.post(f"{API_PREFIX}/targets", response_model=TargetResponse, status_code=201)
def create_target(
    payload: TargetCreate,
    session: Session = Depends(get_session),
) -> TargetResponse:
    target = models.Target(
        name=payload.name,
        target_type=payload.target_type,
        connection_info=payload.connection_info,
        credentials=payload.credentials,
        description=payload.description,
    )
    session.add(target)
    session.commit()
    session.refresh(target)
    return TargetResponse.model_validate(target)


@app.get(f"{API_PREFIX}/targets/{{target_id}}", response_model=TargetResponse)
def get_target(
    target_id: int,
    session: Session = Depends(get_session),
) -> TargetResponse:
    target = session.get(models.Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return TargetResponse.model_validate(target)


@app.post(f"{API_PREFIX}/jobs", response_model=JobResponse, status_code=201)
def create_job(
    payload: JobCreate,
    session: Session = Depends(get_session),
) -> JobResponse:
    target = session.get(models.Target, payload.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    job = models.ScanJob(
        target_id=payload.target_id,
        status="PENDING",
        scan_scope=payload.scan_scope,
        scan_config=payload.scan_config,
    )
    session.add(job)
    session.commit()
    session.refresh(job)

    if payload.run_now:
        executor = ScanExecutor(session)
        try:
            executor.run_job(job, target)
        except PluginConfigError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except KeyError as exc:
            detail = exc.args[0] if exc.args else "Invalid plugin id"
            raise HTTPException(status_code=400, detail=detail) from exc
        session.refresh(job)

    return JobResponse.model_validate(job)


@app.post(f"{API_PREFIX}/jobs/{{job_id}}/run", response_model=JobResponse)
def run_job(
    job_id: int,
    session: Session = Depends(get_session),
) -> JobResponse:
    job = session.get(models.ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status == "RUNNING":
        raise HTTPException(status_code=409, detail="Job already running")

    target = session.get(models.Target, job.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    executor = ScanExecutor(session)
    try:
        executor.run_job(job, target)
    except PluginConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        detail = exc.args[0] if exc.args else "Invalid plugin id"
        raise HTTPException(status_code=400, detail=detail) from exc
    session.refresh(job)
    return JobResponse.model_validate(job)


@app.get(f"{API_PREFIX}/jobs/{{job_id}}/status", response_model=JobStatusResponse)
def get_job_status(
    job_id: int,
    session: Session = Depends(get_session),
) -> JobStatusResponse:
    job = session.get(models.ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    progress_map = {
        "PENDING": 0,
        "RUNNING": 50,
        "COMPLETED": 100,
        "FAILED": 100,
    }
    progress = progress_map.get(job.status, 0)
    return JobStatusResponse(
        status=job.status,
        progress=progress,
        error_message=job.error_message,
    )


@app.get(f"{API_PREFIX}/jobs/{{job_id}}/findings", response_model=List[FindingResponse])
def get_job_findings(
    job_id: int,
    session: Session = Depends(get_session),
) -> List[FindingResponse]:
    job = session.get(models.ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    records = (
        session.query(models.Finding)
        .filter(models.Finding.job_id == job_id)
        .order_by(models.Finding.id.asc())
        .all()
    )
    return [FindingResponse.model_validate(record) for record in records]


@app.post(f"{API_PREFIX}/jobs/{{job_id}}/report", response_model=ReportResponse, status_code=201)
def create_report(
    job_id: int,
    payload: ReportCreate,
    session: Session = Depends(get_session),
) -> ReportResponse:
    job = session.get(models.ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status not in {"COMPLETED", "FAILED"}:
        raise HTTPException(status_code=409, detail="Job not completed")

    try:
        report = generate_report(session, job_id, payload.format)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        detail = exc.args[0] if exc.args else "Invalid job or target"
        raise HTTPException(status_code=400, detail=detail) from exc

    return ReportResponse.model_validate(report)


@app.get(f"{API_PREFIX}/reports/{{report_id}}", response_model=ReportResponse)
def get_report(
    report_id: int,
    session: Session = Depends(get_session),
) -> ReportResponse:
    report = session.get(models.Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return ReportResponse.model_validate(report)


@app.get(f"{API_PREFIX}/reports/{{report_id}}/file")
def download_report_file(
    report_id: int,
    session: Session = Depends(get_session),
) -> FileResponse:
    report = session.get(models.Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    file_path = Path(report.file_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")
    return FileResponse(path=str(file_path), filename=file_path.name)
