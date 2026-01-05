"""이 파일은 .py FastAPI 앱 모듈로 REST 엔드포인트를 제공합니다."""

from __future__ import annotations

from pathlib import Path
from typing import List

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Response
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.config import API_PREFIX, PLUGINS_DIR
from app.core.plugin_loader import PluginLoader
from app.db import models
from app.db.session import get_session, init_db
from app.services.scan_executor import run_job_background
from app.services.reporting import generate_report

from .schemas import (
    FindingResponse,
    JobCreate,
    JobResponse,
    JobStatusResponse,
    PluginMetaResponse,
    ReportCreate,
    ReportResponse,
    TargetCreate,
    TargetResponse,
)

app = FastAPI(title="vuln-inspector")


@app.on_event("startup")
def _startup() -> None:
    # API 서버 시작 시점에 DB 초기화(테이블 생성 등)를 보장한다.
    init_db()


@app.post(f"{API_PREFIX}/targets", response_model=TargetResponse, status_code=201)
def create_target(
    payload: TargetCreate,
    session: Session = Depends(get_session),
) -> TargetResponse:
    # 요청 스키마를 기반으로 Target ORM 객체를 생성한다.
    target = models.Target(
        name=payload.name,
        target_type=payload.target_type,
        connection_info=payload.connection_info,
        credentials=payload.credentials,
        description=payload.description,
    )
    # DB에 저장하고 PK를 리로드한다.
    session.add(target)
    session.commit()
    session.refresh(target)
    # ORM 객체를 응답 스키마로 변환한다.
    return TargetResponse.model_validate(target)


@app.get(f"{API_PREFIX}/targets", response_model=List[TargetResponse])
def list_targets(
    session: Session = Depends(get_session),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> List[TargetResponse]:
    # 등록된 대상 목록을 페이지 단위로 조회한다.
    records = (
        session.query(models.Target)
        .order_by(models.Target.id.asc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [TargetResponse.model_validate(record) for record in records]


@app.get(f"{API_PREFIX}/plugins", response_model=List[PluginMetaResponse])
def list_plugins(
    plugin_type: str | None = Query(None, alias="type"),
) -> List[PluginMetaResponse]:
    # plugin.yml 메타데이터 목록을 반환한다.
    loader = PluginLoader(PLUGINS_DIR)
    metas = loader.discover()
    if plugin_type:
        normalized = plugin_type.strip().lower()
        metas = [meta for meta in metas if meta.plugin_type == normalized]
    metas = sorted(metas, key=lambda meta: meta.plugin_id)

    return [
        PluginMetaResponse(
            id=meta.plugin_id,
            name=meta.name,
            version=meta.version,
            type=meta.plugin_type,
            category=meta.category,
            tags=meta.tags,
            description=meta.description,
            config_schema=meta.config_schema,
            entry_point=meta.entry_point,
            class_name=meta.class_name,
        )
        for meta in metas
    ]


@app.get(f"{API_PREFIX}/targets/{{target_id}}", response_model=TargetResponse)
def get_target(
    target_id: int,
    session: Session = Depends(get_session),
) -> TargetResponse:
    # Target ID로 조회 후, 없으면 404를 반환한다.
    target = session.get(models.Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    # ORM 객체를 응답 스키마로 변환한다.
    return TargetResponse.model_validate(target)


@app.delete(f"{API_PREFIX}/targets/{{target_id}}", status_code=204)
def delete_target(
    target_id: int,
    session: Session = Depends(get_session),
) -> Response:
    # Target과 연관된 Job/결과를 정리한 뒤 삭제한다.
    target = session.get(models.Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    jobs = session.query(models.ScanJob).filter(models.ScanJob.target_id == target_id).all()
    for job in jobs:
        session.query(models.Finding).filter(models.Finding.job_id == job.id).delete(synchronize_session=False)
        session.query(models.Report).filter(models.Report.job_id == job.id).delete(synchronize_session=False)
        session.delete(job)

    session.delete(target)
    session.commit()
    return Response(status_code=204)


@app.post(f"{API_PREFIX}/jobs", response_model=JobResponse, status_code=201)
def create_job(
    payload: JobCreate,
    session: Session = Depends(get_session),
    background_tasks: BackgroundTasks = None,
) -> JobResponse:
    # Job이 참조하는 Target이 존재하는지 확인한다.
    target = session.get(models.Target, payload.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    # 스캔 범위와 설정을 포함한 Job 레코드를 생성한다.
    job = models.ScanJob(
        target_id=payload.target_id,
        status="PENDING",
        scan_scope=payload.scan_scope,
        scan_config=payload.scan_config,
    )
    session.add(job)
    session.commit()
    session.refresh(job)

    if payload.run_now and background_tasks is not None:
        # 즉시 실행 옵션이면 백그라운드에서 스캔을 수행한다.
        background_tasks.add_task(run_job_background, job.id)

    # Job 생성/실행 결과를 응답으로 반환한다.
    return JobResponse.model_validate(job)


@app.get(f"{API_PREFIX}/jobs", response_model=List[JobResponse])
def list_jobs(
    session: Session = Depends(get_session),
    target_id: int | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> List[JobResponse]:
    # Job 목록을 필터링/페이지네이션으로 조회한다.
    query = session.query(models.ScanJob)
    if target_id is not None:
        query = query.filter(models.ScanJob.target_id == target_id)
    if status:
        query = query.filter(models.ScanJob.status == status)
    records = (
        query.order_by(models.ScanJob.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [JobResponse.model_validate(record) for record in records]


@app.post(f"{API_PREFIX}/jobs/{{job_id}}/run", response_model=JobResponse)
def run_job(
    job_id: int,
    session: Session = Depends(get_session),
    background_tasks: BackgroundTasks = None,
) -> JobResponse:
    # Job 존재 여부와 상태를 확인한다.
    job = session.get(models.ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status == "RUNNING":
        raise HTTPException(status_code=409, detail="Job already running")

    # Job이 참조하는 Target을 조회한다.
    target = session.get(models.Target, job.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    # 실행을 백그라운드로 넘기기 전 상태를 초기화한다.
    job.status = "PENDING"
    job.start_time = None
    job.end_time = None
    job.summary = {}
    job.error_message = None
    session.commit()

    if background_tasks is not None:
        # 플러그인 실행기로 Job을 백그라운드에서 수행한다.
        background_tasks.add_task(run_job_background, job.id)
    return JobResponse.model_validate(job)


@app.delete(f"{API_PREFIX}/jobs/{{job_id}}", status_code=204)
def delete_job(
    job_id: int,
    session: Session = Depends(get_session),
) -> Response:
    # Job과 연관된 Finding/Report를 정리한 뒤 삭제한다.
    job = session.get(models.ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    session.query(models.Finding).filter(models.Finding.job_id == job_id).delete(synchronize_session=False)
    session.query(models.Report).filter(models.Report.job_id == job_id).delete(synchronize_session=False)
    session.delete(job)
    session.commit()
    return Response(status_code=204)


@app.get(f"{API_PREFIX}/jobs/{{job_id}}/status", response_model=JobStatusResponse)
def get_job_status(
    job_id: int,
    session: Session = Depends(get_session),
) -> JobStatusResponse:
    # Job 조회 후 없으면 404를 반환한다.
    job = session.get(models.ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    # 상태값을 간단한 퍼센트로 매핑한다.
    progress_map = {
        "PENDING": 0,
        "RUNNING": 50,
        "COMPLETED": 100,
        "FAILED": 100,
    }
    progress = progress_map.get(job.status, 0)
    # 상태/진행률/에러 메시지를 응답한다.
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
    # Job 존재 여부 확인 후, Finding을 정렬해 조회한다.
    job = session.get(models.ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    records = (
        session.query(models.Finding)
        .filter(models.Finding.job_id == job_id)
        .order_by(models.Finding.id.asc())
        .all()
    )
    # ORM 리스트를 응답 스키마 리스트로 변환한다.
    return [FindingResponse.model_validate(record) for record in records]


@app.delete(f"{API_PREFIX}/findings/{{finding_id}}", status_code=204)
def delete_finding(
    finding_id: int,
    session: Session = Depends(get_session),
) -> Response:
    # 단일 Finding을 삭제한다.
    finding = session.get(models.Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    session.delete(finding)
    session.commit()
    return Response(status_code=204)


@app.get(f"{API_PREFIX}/findings", response_model=List[FindingResponse])
def list_findings(
    session: Session = Depends(get_session),
    job_id: int | None = Query(None),
    target_id: int | None = Query(None),
    severity: str | None = Query(None),
    tag: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> List[FindingResponse]:
    # Finding 목록을 필터링/페이지네이션으로 조회한다.
    query = session.query(models.Finding)
    if job_id is not None:
        query = query.filter(models.Finding.job_id == job_id)
    if target_id is not None:
        query = query.join(models.ScanJob).filter(models.ScanJob.target_id == target_id)
    if severity:
        query = query.filter(models.Finding.severity == severity)

    records = (
        query.order_by(models.Finding.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    if tag:
        # JSON 컬럼 호환성을 위해 태그 필터는 파이썬 레벨에서 처리한다.
        records = [record for record in records if tag in (record.tags or [])]

    return [FindingResponse.model_validate(record) for record in records]


@app.post(f"{API_PREFIX}/jobs/{{job_id}}/report", response_model=ReportResponse, status_code=201)
def create_report(
    job_id: int,
    payload: ReportCreate,
    session: Session = Depends(get_session),
) -> ReportResponse:
    # 보고서 생성 전 Job 상태를 확인한다.
    job = session.get(models.ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status not in {"COMPLETED", "FAILED"}:
        raise HTTPException(status_code=409, detail="Job not completed")

    # 보고서를 생성하고 DB에 저장한다.
    try:
        report = generate_report(session, job_id, payload.format)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        detail = exc.args[0] if exc.args else "Invalid job or target"
        raise HTTPException(status_code=400, detail=detail) from exc

    # 생성된 보고서 메타데이터를 반환한다.
    return ReportResponse.model_validate(report)


@app.get(f"{API_PREFIX}/reports", response_model=List[ReportResponse])
def list_reports(
    session: Session = Depends(get_session),
    job_id: int | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> List[ReportResponse]:
    # Report 목록을 필터링/페이지네이션으로 조회한다.
    query = session.query(models.Report)
    if job_id is not None:
        query = query.filter(models.Report.job_id == job_id)
    records = (
        query.order_by(models.Report.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [ReportResponse.model_validate(record) for record in records]


@app.get(f"{API_PREFIX}/reports/{{report_id}}", response_model=ReportResponse)
def get_report(
    report_id: int,
    session: Session = Depends(get_session),
) -> ReportResponse:
    # 보고서 메타데이터를 조회한다.
    report = session.get(models.Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return ReportResponse.model_validate(report)


@app.delete(f"{API_PREFIX}/reports/{{report_id}}", status_code=204)
def delete_report(
    report_id: int,
    session: Session = Depends(get_session),
) -> Response:
    # Report 메타데이터를 삭제한다.
    report = session.get(models.Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    session.delete(report)
    session.commit()
    return Response(status_code=204)


@app.get(f"{API_PREFIX}/reports/{{report_id}}/file")
def download_report_file(
    report_id: int,
    session: Session = Depends(get_session),
) -> FileResponse:
    # 보고서 파일 경로를 조회한 뒤, 존재 여부를 확인한다.
    report = session.get(models.Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    file_path = Path(report.file_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")
    # 실제 파일 다운로드 응답을 반환한다.
    return FileResponse(path=str(file_path), filename=file_path.name)
