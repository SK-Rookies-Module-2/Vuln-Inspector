"""이 파일은 .py DB 모델 정의 모듈로 Target/ScanJob/Finding/Report를 제공합니다."""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from .base import Base


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    target_type = Column(String, nullable=False)
    connection_info = Column(JSON, nullable=True)
    credentials = Column(JSON, nullable=True)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan_jobs = relationship("ScanJob", back_populates="target")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    status = Column(String, default="PENDING")
    scan_scope = Column(JSON, nullable=False)
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    summary = Column(JSON, default={})

    target = relationship("Target", back_populates="scan_jobs")
    findings = relationship("Finding", back_populates="job")
    report = relationship("Report", back_populates="job", uselist=False)


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id"))
    vuln_id = Column(String, index=True)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    tags = Column(JSON)
    description = Column(Text)
    solution = Column(Text)
    evidence = Column(JSON)
    raw_data = Column(JSON, nullable=True)

    job = relationship("ScanJob", back_populates="findings")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id"))
    format = Column(String)
    file_path = Column(String)
    generated_at = Column(DateTime, default=datetime.utcnow)

    job = relationship("ScanJob", back_populates="report")
