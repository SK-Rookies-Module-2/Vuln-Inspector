"""이 파일은 .py API 스키마 모듈로 요청/응답 모델을 정의합니다."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class TargetType(str, Enum):
    # Target 유형은 플러그인의 실행 경로와 필요 입력을 구분하는 기준이 된다.
    SERVER = "SERVER"
    WEB_URL = "WEB_URL"
    GIT_REPO = "GIT_REPO"


class TargetCreate(BaseModel):
    # Target 등록 요청 스키마로 연결 정보/인증 정보를 함께 받는다.
    name: str
    # API 요청에서는 "type" 필드를 사용하고 내부에서는 target_type으로 매핑한다.
    target_type: TargetType = Field(..., alias="type")
    connection_info: Dict = Field(default_factory=dict)
    credentials: Dict = Field(default_factory=dict)
    description: Optional[str] = None

    # alias 필드를 허용하여 입력/출력 키를 정리한다.
    model_config = ConfigDict(populate_by_name=True)

    @model_validator(mode="after")
    def validate_connection_info(self) -> "TargetCreate":
        # 유형별 필수 연결 정보가 있는지 검증한다.
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
    # Target 응답 스키마로 DB 레코드를 그대로 전달한다.
    id: int
    name: str
    target_type: TargetType = Field(..., alias="type")
    connection_info: Dict
    credentials: Dict
    description: Optional[str] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class JobCreate(BaseModel):
    # Job 생성 요청 스키마로 스캔 범위와 플러그인 설정을 전달한다.
    target_id: int
    # scan_scope는 실행할 plugin_id 목록이다.
    scan_scope: List[str]
    # scan_config는 plugin_id -> 설정 객체 구조로 전달한다.
    scan_config: Dict[str, Dict] = Field(default_factory=dict)
    # run_now가 True면 즉시 실행하고 False면 대기 상태로 만든다.
    run_now: bool = True


class JobResponse(BaseModel):
    # Job 상태 조회/생성 응답 스키마이다.
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
    # Job의 진행률과 에러 메시지를 제공한다.
    status: str
    progress: int
    error_message: Optional[str] = None


class FindingResponse(BaseModel):
    # 스캔 결과(Finding) 응답 스키마이다.
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
    # 보고서 생성 요청 스키마로 형식을 지정한다.
    format: str = "json"


class ReportResponse(BaseModel):
    # 보고서 메타데이터 응답 스키마이다.
    id: int
    job_id: int
    format: str
    file_path: str
    generated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
