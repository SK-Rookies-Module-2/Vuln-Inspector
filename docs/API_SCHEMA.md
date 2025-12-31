<!-- API_SCHEMA.md: REST API 스키마 상세 문서 -->
# API 스키마 상세  
http://127.0.0.1:8000/docs

## 공통 사항
- Base URL: `http://127.0.0.1:8000`
- Prefix: `/api/v1`
- Content-Type: `application/json`
- 인증: 없음(내부/개발용)
- 기본 DB: PostgreSQL (`.env`의 `DB_*` 또는 `DATABASE_URL`)
- 스캔 실행 방식: 동기 실행(`run_now: true`일 때 요청이 완료될 때까지 대기)

### 오류 응답 형식
FastAPI 기본 오류 응답을 사용합니다.
```json
{"detail": "에러 메시지"}
```

---

## 1) 대상(Target) API

### POST /api/v1/targets
**요청 본문**
```json
{
  "name": "demo-web",
  "type": "WEB_URL",
  "connection_info": {"url": "http://127.0.0.1"},
  "credentials": {},
  "description": "optional"
}
```

**요청 필드**
- `name` (string, required)
- `type` (enum: `SERVER` | `WEB_URL` | `GIT_REPO`, required)
- `connection_info` (object, required)
- `credentials` (object, optional)
- `description` (string, optional)

**타입별 connection_info 규칙**
- `SERVER`: `host` 또는 `ip` 필수, `port` 선택
- `WEB_URL`: `url` 필수
- `GIT_REPO`: `url` 또는 `path` 필수

**credentials 권장 키**
- `username` (string)
- `key_path` (string)
- `password` (string)

**응답 코드**
- 201: 생성 성공
- 422: 필드 검증 실패

**응답**
```json
{
  "id": 1,
  "name": "demo-web",
  "type": "WEB_URL",
  "connection_info": {"url": "http://127.0.0.1"},
  "credentials": {},
  "description": "optional",
  "created_at": "2024-01-01T00:00:00"
}
```

### GET /api/v1/targets/{target_id}
**응답**: Target 단건 반환

**응답 코드**
- 200: 정상 반환
- 404: 대상 없음

---

## 2) Job API

### scan_scope / scan_config 규칙
- `scan_scope`: 실행할 플러그인 ID 목록
- `scan_config`: **플러그인 ID → 설정 객체** 매핑
- `scan_scope`에 있는 플러그인만 실행됨
- `scan_config`가 없으면 `config_schema` 기본값이 적용됨
- `scan_config`에 있으나 `scan_scope`에 없는 항목은 무시됨
- `config_schema`에 정의되지 않은 키는 검증되지 않음(플러그인 내부에서 사용 가능)

### POST /api/v1/jobs
**요청 본문**
```json
{
  "target_id": 1,
  "scan_scope": ["static_dependency_check", "remote_linux_kisa_u01"],
  "scan_config": {
    "static_dependency_check": {"manifest_path": "requirements.txt"},
    "remote_linux_kisa_u01": {"sshd_config_path": "/etc/ssh/sshd_config", "use_sudo": false}
  },
  "run_now": true
}
```

**요청 필드**
- `target_id` (int, required)
- `scan_scope` (array[string], required)
- `scan_config` (object, optional)
- `run_now` (boolean, optional, default: true)

**run_now**
- `true`: 생성 후 즉시 실행(동기)
- `false`: Job만 생성하고 실행은 `/jobs/{id}/run`으로 별도 호출

**응답**
```json
{
  "id": 1,
  "target_id": 1,
  "status": "COMPLETED",
  "scan_scope": ["static_dependency_check", "remote_linux_kisa_u01"],
  "scan_config": {"...": "..."},
  "start_time": "2024-01-01T00:00:00",
  "end_time": "2024-01-01T00:00:05",
  "summary": {"High": 1, "Info": 2},
  "error_message": null
}
```

**summary**
- 심각도별 카운트 맵(`Critical/High/Medium/Low/Info`)

**응답 코드**
- 201: 생성 성공
- 400: 플러그인 ID 오류 또는 설정 검증 실패
- 404: 대상 없음
- 422: 필드 검증 실패

### POST /api/v1/jobs/{job_id}/run
- 기존 Job을 다시 실행
- 응답은 `JobResponse`

**응답 코드**
- 200: 실행 성공
- 400: 플러그인 ID 오류 또는 설정 검증 실패
- 404: Job 또는 Target 없음
- 409: 이미 실행 중

### GET /api/v1/jobs/{job_id}/status
**응답**
```json
{
  "status": "COMPLETED",
  "progress": 100,
  "error_message": null
}
```

**응답 코드**
- 200: 정상 반환
- 404: Job 없음

### GET /api/v1/jobs/{job_id}/findings
**응답**: Finding 배열 반환

**응답 코드**
- 200: 정상 반환
- 404: Job 없음

---

## 3) Finding 스키마
**severity 값 예시**: `Critical | High | Medium | Low | Info`  
**tags 확장**: KISA 태그가 있으면 OWASP 태그가 자동으로 추가될 수 있습니다.
```json
{
  "id": 1,
  "job_id": 1,
  "vuln_id": "OWASP-A01-UNAUTH",
  "title": "인증 필요 엔드포인트에 대한 무인증 접근",
  "severity": "Medium",
  "tags": ["OWASP:2025:A01"],
  "description": "...",
  "solution": "...",
  "evidence": {"url": "...", "status": 200},
  "raw_data": null
}
```

---

## 4) Report API

### POST /api/v1/jobs/{job_id}/report
**요청 본문**
```json
{"format": "json"}
```

**지원 포맷**
- `json`
- `csv`

**응답**
```json
{
  "id": 1,
  "job_id": 1,
  "format": "JSON",
  "file_path": "storage/reports/1/report.json",
  "generated_at": "2024-01-01T00:00:05"
}
```

**응답 코드**
- 201: 생성 성공
- 400: 지원하지 않는 포맷
- 404: Job 없음
- 409: Job이 완료되지 않음

### GET /api/v1/reports/{report_id}
- 보고서 메타 반환

**응답 코드**
- 200: 정상 반환
- 404: Report 없음

### GET /api/v1/reports/{report_id}/file
- 실제 파일 다운로드

**응답 코드**
- 200: 파일 반환
- 404: Report 또는 파일 없음

---

## 5) Demo 플러그인별 scan_config 스키마

### static_dependency_check
**필드**
- `manifest_path` (string, default: `requirements.txt`)
- `repo_url` (string, optional)
- `repo_ref` (string, optional)
```json
{"manifest_path": "requirements.txt"}
```

### remote_linux_kisa_u01
**필드**
- `sshd_config_path` (string, default: `fixtures/sshd_config_demo`)
- `use_sudo` (boolean, default: false)
- `sudo_user` (string, optional)
```json
{
  "sshd_config_path": "/etc/ssh/sshd_config",
  "use_sudo": false,
  "sudo_user": ""
}
```

### dynamic_idor_scanner
**필드**
- `base_url` (string, optional)
- `endpoint_path` (string, default: `/api/users/1`)
- `headers` (object, default: `{}`)
- `auth_headers` (object, default: `{}`)
- `require_auth` (boolean, default: false)
- `timeout` (integer, default: 5, min: 1)
- `verify_ssl` (boolean, default: true)
```json
{
  "base_url": "http://127.0.0.1:8000",
  "endpoint_path": "/api/users/2",
  "headers": {},
  "auth_headers": {"Authorization": "Bearer TOKEN"},
  "require_auth": true,
  "timeout": 5,
  "verify_ssl": true
}
```
