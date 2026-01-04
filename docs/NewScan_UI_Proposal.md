# New Scan UI/UX Proposal

## 목적
- URL/GitHub 입력만으로 진단을 실행하고 결과를 확인하는 흐름을 단일 페이지에서 제공한다.
- 현재 API/DB 모델( Target/ScanJob/Finding/Report )을 변경하지 않고도 동작하도록 설계한다.
- Dashboard가 "테스트용"을 벗어나 실사용 가능한 UX를 제공하도록 구조를 단순화한다.

## 범위
- Streamlit 대시보드 화면/정보구조 설계 제안.
- API 호출은 기존 엔드포인트를 그대로 사용한다.

## 핵심 사용자 흐름 (One-Page Wizard)
1) Target 선택 또는 즉시 생성
2) 진단 범위 선택(Blackbox/Whitebox)
3) 실행 및 상태 모니터링
4) 결과 요약 + Findings + 보고서 보기

## 화면 구조 (단일 페이지 구성)
### A. 상단: 환경/실행 컨텍스트
- API_BASE_URL 표시 및 연결 상태 체크
- "New Scan" 버튼(새 스캔 초기화)

### B. Step 1: Target 입력
- Target Source 토글: URL / GitHub / Existing Target
- URL 입력
  - base_url
  - auth_headers (옵션, JSON 입력)
- GitHub 입력
  - repo_url
  - repo_ref (branch/tag, optional)
  - path (optional)
- Existing Target 선택
  - 기존 Target 목록 selectbox

### C. Step 2: Scope/Profile
- 진단 범위 토글: Blackbox / Whitebox
- 프로파일 선택
  - Quick (기본)
  - Deep (상세)
- Advanced 옵션 (expander)
  - plugin_id별 scan_config JSON
  - timeout, max_results, verify_ssl 등

### D. Step 3: Execution
- "Run" 버튼
- 실행 상태 카드
  - Job ID, status, progress
  - 마지막 상태 갱신 시간
- 실행 중에는 폴링(3~5초)

### E. 결과 섹션
- 요약 카드: Critical/High/Medium/Low/Info
- Findings 테이블 (severity, tags, title, evidence 요약)
- Raw Report 링크(외부 도구 리포트 파일 다운로드)

## 레이아웃 스케치 (ASCII)
```
[ API 상태/환경 ]
[ Step1 Target 입력 ]
[ Step2 Scope/Profile ]
[ Run 버튼 + 상태 카드 ]
[ Summary ]
[ Findings Table ]
[ Raw Report ]
```

## 기존 페이지 구조와의 관계
- 기존 페이지는 유지 가능하나 "New Scan" 중심으로 재배치
  - Overview: 최근 Job/Findings 요약
  - New Scan: 본 설계 적용
  - Runs: Job 목록 및 상세
  - Reports: 보고서 목록
  - Targets: 대상 관리

## API 호출 매핑
- Target 생성: POST /api/v1/targets
- Job 생성/즉시 실행: POST /api/v1/jobs (run_now=True)
- Job 상태 폴링: GET /api/v1/jobs/{id}/status
- 결과 조회: GET /api/v1/jobs/{id}/findings
- 보고서 생성: POST /api/v1/jobs/{id}/report

## 상태/세션 관리 (Streamlit)
- st.session_state로 target_id, scan_scope, last_job_id 유지
- st.cache_data(ttl=3~5)로 status/findings 캐싱
- 완료 시 자동 결과 섹션 강조(리렌더)

## 실패/에러 처리
- API 오류는 사용자 메시지와 원인 요약 제공
- 외부 도구 보고서만 존재하는 경우
  - Findings에 "Raw Report Only" 항목 1건 표시
  - Raw Report 링크를 강조

## 구현 파일(예시)
- dashboard/pages/New_Scan.py
- dashboard/lib/api_client.py (기존 사용)
- dashboard/lib/schemas.py (JSON 입력 파싱)
