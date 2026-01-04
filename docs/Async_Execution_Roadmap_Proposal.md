# Async Execution Roadmap Proposal

## 목적
- Strix 통합으로 실행 시간이 길어질 가능성이 높으므로 단계적 비동기화 로드맵을 제안한다.
- 기존 API 계약을 최대한 유지하며 확장한다.

## 단계별 로드맵
### Phase 0 (현재)
- 동기 실행(run_now=True)
- Dashboard는 즉시 결과를 수신
- 작은 규모 테스트에 적합

### Phase 1 (내부 비동기)
- FastAPI BackgroundTasks 또는 내부 워커 스레드로 분리
- run_now=True는 Job 생성 후 즉시 실행을 시작하되 API 응답은 빠르게 반환
- 기존 /jobs/{id}/status 폴링으로 진행률 표시

### Phase 2 (외부 워커)
- 간단한 큐(예: Redis + RQ/Celery) 도입
- API는 Job 상태만 관리
- 워커가 ScanExecutor를 실행

### Phase 3 (대규모 확장)
- 실행 이력, 재시도 정책, 타임아웃 정책 도입
- 리포트 생성 단계 분리(보고서 생성 큐)

## 상태 관리 확장 제안
- ScanJob.status: PENDING/RUNNING/COMPLETED/FAILED 유지
- progress 계산: 플러그인 단위 진행률(예: 0~100 분할)
- error_message에 외부 도구 오류 기록

## 호환성 유지 원칙
- 기존 엔드포인트(/api/v1/jobs, /jobs/{id}/status) 유지
- Dashboard는 폴링 기반 유지
- 결과 저장 구조(Finding/Report)는 변경하지 않음

## 위험 및 대응
- 장시간 실행 시 타임아웃 위험
  - 외부 도구 실행 타임아웃 설정
- 프로세스 장애 시 Job 상태 고착
  - 워커 재시도 및 상태 복구 로직 필요

## 구현 힌트(선택)
- job runner를 독립 모듈로 분리
- ScanExecutor 실행 전후로 상태 갱신
- 보고서 저장은 현재 storage 구조 유지

