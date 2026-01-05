<!-- API_SCHEMA.md: REST API 스키마 상세 문서 -->
# API 스키마 상세  
http://127.0.0.1:8000/docs

## 공통 사항
- Base URL: `http://127.0.0.1:8000`
- Prefix: `/api/v1`
- Content-Type: `application/json`
- 인증: 없음(내부/개발용)
- 기본 DB: PostgreSQL (`.env`의 `DB_*` 또는 `DATABASE_URL`)
- 스캔 실행 방식: 백그라운드 실행(`run_now: true`일 때 Job 생성 후 즉시 반환)

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

### GET /api/v1/targets
**쿼리 파라미터**
- `limit` (int, default: 100, max: 1000)
- `offset` (int, default: 0)

**응답 코드**
- 200: 정상 반환

### DELETE /api/v1/targets/{target_id}
**응답 코드**
- 204: 삭제 완료
- 404: 대상 없음

### POST /api/v1/targets/{target_id}/validate-ssh
**설명**: SERVER 대상의 SSH 연결을 사전 점검합니다.

**쿼리 파라미터**
- `timeout` (int, default: 10, min: 1, max: 60)

**응답**
```json
{
  "target_id": 1,
  "success": true,
  "message": "SSH connection ok",
  "duration_ms": 120,
  "stdout": "__vuln_inspector_ok__",
  "stderr": null,
  "host": "127.0.0.1",
  "port": 22,
  "user": "root"
}
```

**응답 코드**
- 200: 정상 반환
- 400: 대상 유형/파라미터 오류
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
  "scan_scope": ["static_strix_scan", "remote_kisa_u01"],
  "scan_config": {
    "static_strix_scan": {"repo_url": "https://example.com/repo.git"},
    "remote_kisa_u01": {"os_type": "linux", "protocols": ["ssh"], "use_sudo": false}
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
- `true`: 생성 후 즉시 백그라운드 실행
- `false`: Job만 생성하고 실행은 `/jobs/{id}/run`으로 별도 호출

**응답**
```json
{
  "id": 1,
  "target_id": 1,
  "status": "COMPLETED",
  "scan_scope": ["static_strix_scan", "remote_kisa_u01"],
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
- 404: 대상 없음
- 422: 필드 검증 실패

**실행 오류 처리**
- 플러그인 ID/설정 오류는 백그라운드 실행 중 발생할 수 있으며,
  `Job.error_message`와 `status=FAILED`로 기록됩니다.

### POST /api/v1/jobs/{job_id}/run
- 기존 Job을 다시 실행
- 응답은 `JobResponse`

**응답 코드**
- 200: 실행 성공
- 404: Job 또는 Target 없음
- 409: 이미 실행 중

### GET /api/v1/jobs
**쿼리 파라미터**
- `target_id` (int, optional)
- `status` (string, optional)
- `limit` (int, default: 100, max: 1000)
- `offset` (int, default: 0)

**응답 코드**
- 200: 정상 반환

### DELETE /api/v1/jobs/{job_id}
**응답 코드**
- 204: 삭제 완료
- 404: Job 없음

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

### GET /api/v1/findings
**쿼리 파라미터**
- `job_id` (int, optional)
- `target_id` (int, optional)
- `severity` (string, optional)
- `tag` (string, optional)
- `limit` (int, default: 100, max: 1000)
- `offset` (int, default: 0)

**응답 코드**
- 200: 정상 반환

### DELETE /api/v1/findings/{finding_id}
**응답 코드**
- 204: 삭제 완료
- 404: Finding 없음

---

## 3) Plugin API

### GET /api/v1/plugins
**쿼리 파라미터**
- `type` (string, optional: `static` | `remote` | `dynamic`)

**응답 코드**
- 200: 정상 반환

**응답 예시**
```json
[
  {
    "id": "static_strix_scan",
    "name": "Strix External Static Scan",
    "version": "0.1.0",
    "type": "static",
    "category": "external",
    "tags": ["STRIX"],
    "description": "External static scan placeholder for Strix integration.",
    "config_schema": {"properties": {"repo_url": {"type": "string"}}},
    "entry_point": "main.py",
    "class_name": "StrixStaticScan"
  }
]
```

---

## 4) Finding 스키마
**severity 값 예시**: `Critical | High | Medium | Low | Info`  
**tags 처리**: 플러그인이 전달한 태그를 그대로 반환합니다.
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

## 5) Report API

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

### GET /api/v1/reports
**쿼리 파라미터**
- `job_id` (int, optional)
- `limit` (int, default: 100, max: 1000)
- `offset` (int, default: 0)

**응답 코드**
- 200: 정상 반환

### DELETE /api/v1/reports/{report_id}
**응답 코드**
- 204: 삭제 완료
- 404: Report 없음

---

## 6) Demo 플러그인별 scan_config 스키마

### static_strix_scan
**필드**
- `repo_url` (string, optional)
- `repo_ref` (string, optional)
- `repo_path` (string, optional)
- `scan_mode` (string, optional: `quick` | `standard` | `deep`)
- `instruction` (string, optional)
- `instruction_file` (string, optional)
- `non_interactive` (boolean, default: true)
- `run_name` (string, optional)
- `timeout` (integer, default: 1800)
```json
{"repo_url": "https://example.com/repo.git"}
```

### remote_kisa_u01
**필드**
- `os_type` (string, required: `linux` | `solaris` | `aix` | `hpux`)
- `protocols` (array, default: `["ssh", "telnet"]`)
- `sshd_config_path` (string, optional)
- `telnet_config_path` (string, optional)
- `use_sudo` (boolean, default: false)
- `sudo_user` (string, optional)
- `allow_local_fallback` (boolean, default: false)
```json
{
  "os_type": "linux",
  "protocols": ["ssh"],
  "use_sudo": false
}
```

### dynamic_strix_scan
**필드**
- `base_url` (string, optional)
- `auth_headers` (object, default: `{}`)
- `scan_mode` (string, optional: `quick` | `standard` | `deep`)
- `instruction` (string, optional)
- `instruction_file` (string, optional)
- `non_interactive` (boolean, default: true)
- `run_name` (string, optional)
- `timeout` (integer, default: 1800, min: 1)
```json
{
  "base_url": "https://example.com",
  "auth_headers": {"Authorization": "Bearer TOKEN"}
}
```
