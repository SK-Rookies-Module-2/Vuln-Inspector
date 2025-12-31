<!-- API_SCHEMA.md: REST API 스키마 상세 문서 -->
# API 스키마 상세

## 공통 사항
- Base URL: `http://127.0.0.1:8000`
- Prefix: `/api/v1`
- Content-Type: `application/json`

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

---

## 2) Job API

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

### POST /api/v1/jobs/{job_id}/run
- 기존 Job을 다시 실행
- 응답은 `JobResponse`

### GET /api/v1/jobs/{job_id}/status
**응답**
```json
{
  "status": "COMPLETED",
  "progress": 100,
  "error_message": null
}
```

### GET /api/v1/jobs/{job_id}/findings
**응답**: Finding 배열 반환

---

## 3) Finding 스키마
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

### GET /api/v1/reports/{report_id}
- 보고서 메타 반환

### GET /api/v1/reports/{report_id}/file
- 실제 파일 다운로드

---

## 5) 플러그인별 scan_config 스키마

### static_dependency_check
```json
{"manifest_path": "requirements.txt"}
```

### remote_linux_kisa_u01
```json
{
  "sshd_config_path": "/etc/ssh/sshd_config",
  "use_sudo": false,
  "sudo_user": ""
}
```

### dynamic_idor_scanner
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
