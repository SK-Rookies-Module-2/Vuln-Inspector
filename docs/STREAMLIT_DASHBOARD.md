# Streamlit 진단 대시보드 설계안

## 목적과 범위
API 중심의 진단 흐름을 **웹 대시보드에서 쉽게 실행/관찰/보고서 생성**할 수 있도록 Streamlit UI를 설계합니다. 대시보드는 API 호출만 사용하며 서버 내부 로직을 직접 실행하지 않습니다.

## 전제 사항
- API 베이스 URL은 환경변수로 관리합니다. 예: `API_BASE_URL=http://127.0.0.1:8000`
- 사용 가능한 핵심 API
  - `POST /api/v1/targets` 대상 등록
  - `POST /api/v1/jobs` 스캔 요청(run_now=True 기본)
  - `POST /api/v1/jobs/{id}/run` 지연 실행
  - `GET /api/v1/jobs/{id}/status` 상태/진행률
  - `GET /api/v1/jobs/{id}/findings` 결과 조회
  - `POST /api/v1/jobs/{id}/report` 보고서 생성
  - `GET /api/v1/reports/{id}/file` 보고서 다운로드

## 페이지 구성(멀티 페이지 기준)
1. **Overview (요약 대시보드)**
   - 최근 Job 목록, 상태 요약(성공/실패/진행 중), 최근 Findings 수
2. **Remote (원격 진단)**
   - SERVER 대상 선택/등록
   - Remote 플러그인 다중 선택
   - 공통 설정 일괄 입력 + 플러그인별 오버라이드(선택)
3. **Manage (통합 관리)**
   - Targets/Jobs/Findings CRUD를 탭으로 통합
   - 각 탭 하단에 목록 테이블 제공

## 데이터 흐름(모듈/함수 기준)
- 대상 등록
  - Streamlit 폼 → `POST /api/v1/targets`
- 스캔 실행
  - Streamlit 폼 → `POST /api/v1/jobs` (run_now=True)
  - 또는 `POST /api/v1/jobs/{id}/run`로 수동 실행
- 진행률 모니터링
  - `GET /api/v1/jobs/{id}/status` 폴링(기본 3~5초)
- 결과 조회
  - `GET /api/v1/jobs/{id}/findings`
- 보고서 생성/다운로드
  - `POST /api/v1/jobs/{id}/report`
  - 반환된 `report_id`로 `GET /api/v1/reports/{id}/file`

## UI 컴포넌트 설계
- **스캔 설정 폼**
  - 대상 선택: `st.selectbox` (target_id)
  - 채널 선택: `st.multiselect` (scan_scope)
  - 플러그인별 config 입력: JSON 편집기(`st.text_area` + JSON validate)
- **상태 카드**
  - 진행률: `st.progress`
  - 상태 배지: `st.info` / `st.success` / `st.error`
- **결과 테이블**
  - Findings: `st.dataframe` (severity 정렬, tag 필터)
  - 선택 행 상세: `st.expander` + evidence/raw_data JSON 표시

## 상태 관리/캐싱 전략
- `st.session_state`로 선택된 `target_id`, `job_id`, `scan_scope` 유지
- `st.cache_data(ttl=3)`로 Job 상태/Findings 캐시
- 상태 변동 시 `st.experimental_rerun()`으로 화면 갱신

## 예시 요청 페이로드
```json
{
  "target_id": 1,
  "scan_scope": ["remote_linux_kisa_u01", "dynamic_idor_scan"],
  "scan_config": {
    "remote_linux_kisa_u01": { "ssh_port": 22, "use_sudo": true },
    "dynamic_idor_scan": { "require_auth": false, "timeout": 5 }
  },
  "run_now": true
}
```

## 폴더 구조 제안
```
dashboard/
  app.py
  pages/
    01_Overview.py
    02_Remote.py
    03_Manage.py
  lib/
    api_client.py
    schemas.py
```

## 운영 포인트
- API 오류는 사용자에게 즉시 표시하고, 원문 에러 메시지를 로그에 남깁니다.
- 대시보드는 **진단 실행 제어** 중심으로 유지하며, 상세 보고서는 API 기반으로만 생성합니다.
