"""이 파일은 .py API 스키마 모듈로 요청/응답 모델을 정의합니다."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class TargetCreate(BaseModel):
    name: str
    target_type: str = Field(..., alias="type")
    connection_info: Dict = Field(default_factory=dict)
    credentials: Dict = Field(default_factory=dict)
    description: Optional[str] = None

    model_config = ConfigDict(populate_by_name=True)


class TargetResponse(BaseModel):
    id: int
    name: str
    target_type: str = Field(..., alias="type")
    connection_info: Dict
    credentials: Dict
    description: Optional[str] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class JobCreate(BaseModel):
    target_id: int
    scan_scope: List[str]
    scan_config: Dict[str, Dict] = Field(default_factory=dict)
    run_now: bool = True


class JobResponse(BaseModel):
    id: int
    target_id: int
    status: str
    scan_scope: List[str]
    scan_config: Dict[str, Dict]
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    summary: Dict[str, int] = Field(default_factory=dict)
    error_message: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class JobStatusResponse(BaseModel):
    status: str
    progress: int
    error_message: Optional[str] = None


class FindingResponse(BaseModel):
    id: int
    job_id: int
    vuln_id: Optional[str] = None
    title: str
    severity: str
    tags: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    solution: Optional[str] = None
    evidence: Dict = Field(default_factory=dict)
    raw_data: Optional[Dict] = None

    model_config = ConfigDict(from_attributes=True)
