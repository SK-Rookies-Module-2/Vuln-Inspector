"""이 파일은 .py API 스키마 모듈로 요청/응답 모델을 정의합니다."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class TargetType(str, Enum):
    SERVER = "SERVER"
    WEB_URL = "WEB_URL"
    GIT_REPO = "GIT_REPO"


class TargetCreate(BaseModel):
    name: str
    target_type: TargetType = Field(..., alias="type")
    connection_info: Dict = Field(default_factory=dict)
    credentials: Dict = Field(default_factory=dict)
    description: Optional[str] = None

    model_config = ConfigDict(populate_by_name=True)

    @model_validator(mode="after")
    def validate_connection_info(self) -> "TargetCreate":
        info = self.connection_info or {}
        if self.target_type == TargetType.SERVER:
            if not (info.get("host") or info.get("ip")):
                raise ValueError("connection_info.host or connection_info.ip is required for SERVER")
        elif self.target_type == TargetType.WEB_URL:
            if not info.get("url"):
                raise ValueError("connection_info.url is required for WEB_URL")
        elif self.target_type == TargetType.GIT_REPO:
            if not (info.get("url") or info.get("path")):
                raise ValueError("connection_info.url or connection_info.path is required for GIT_REPO")
        return self


class TargetResponse(BaseModel):
    id: int
    name: str
    target_type: TargetType = Field(..., alias="type")
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


class ReportCreate(BaseModel):
    format: str = "json"


class ReportResponse(BaseModel):
    id: int
    job_id: int
    format: str
    file_path: str
    generated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
