<!-- TESTING_EXTERNAL.md: 외부 대상(SSH/Git/HTTP) 테스트 가이드 -->
# 외부 대상 테스트 가이드

이 문서는 현재 3개 플러그인을 **외부 SSH 서버 / 외부 Git 저장소 / 외부 HTTP URL** 대상으로 테스트하는 방법을 설명합니다.

## 공통 준비 사항
- API 실행: `uv run uvicorn app.api.app:app --reload`
- 네트워크 접근: 실행 환경에서 외부 네트워크 접근 가능해야 합니다.
- DB 연결: `.env` 설정 후 API 실행

## 1) Static 플러그인: 외부 Git 저장소 검사
**대상 플러그인**: `static_dependency_check`  
**검사 대상 파일**: 기본 `requirements.txt`

### 조건
- 실행 환경에 `git`이 설치되어 있어야 합니다.
- private repo는 현재 인증이 없어 실패합니다.

### 대상 등록
```bash
curl -X POST http://127.0.0.1:8000/api/v1/targets \
  -H "Content-Type: application/json" \
  -d '{"name":"demo-repo","type":"GIT_REPO","connection_info":{"url":"https://github.com/psf/requests.git"}}'
```

### 스캔 실행
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{"target_id":1,"scan_scope":["static_dependency_check"],"scan_config":{"static_dependency_check":{"manifest_path":"requirements.txt"}}}'
```

### 옵션: 특정 브랜치/태그
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{"target_id":1,"scan_scope":["static_dependency_check"],"scan_config":{"static_dependency_check":{"repo_ref":"v2.31.0","manifest_path":"requirements.txt"}}}'
```

---

## 2) Remote 플러그인: 외부 SSH 서버 검사
**대상 플러그인**: `remote_linux_kisa_u01`  
**검사 대상 파일**: `/etc/ssh/sshd_config`

### 조건
- 원격 SSH 접속 가능해야 합니다.
- 비밀번호 인증은 `sshpass` 설치 필요.
- `sshd_config`가 root 권한이면 `use_sudo` + NOPASSWD 설정이 필요합니다.
- 현재 로직은 **로컬 파일이 존재하면 로컬을 우선**합니다. 외부 서버 테스트를 위해서는:
  - 로컬에 해당 경로가 없도록 환경을 구성하거나
  - 로컬에 없는 경로로 지정 후 원격에서만 존재하도록 설정해야 합니다.

### 대상 등록(비밀번호 방식)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/targets \
  -H "Content-Type: application/json" \
  -d '{"name":"demo-server","type":"SERVER","connection_info":{"host":"192.168.40.129","port":22},"credentials":{"username":"user","password":"pass"}}'
```

### 대상 등록(키 방식)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/targets \
  -H "Content-Type: application/json" \
  -d '{"name":"demo-server","type":"SERVER","connection_info":{"host":"192.168.40.129","port":22},"credentials":{"username":"user","key_path":"/path/to/key"}}'
```

### 스캔 실행
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{"target_id":2,"scan_scope":["remote_linux_kisa_u01"],"scan_config":{"remote_linux_kisa_u01":{"sshd_config_path":"/etc/ssh/sshd_config","use_sudo":false}}}'
```

---

## 3) Dynamic 플러그인: 외부 HTTP URL 검사
**대상 플러그인**: `dynamic_idor_scanner`  
**검사 방식**: 무인증 접근 여부 확인

### 조건
- 외부 HTTP 접근 가능해야 합니다.
- 인증이 필요한 경우 `auth_headers`를 설정합니다.
- 자체 서명 인증서는 `verify_ssl=false` 사용

### 대상 등록
```bash
curl -X POST http://127.0.0.1:8000/api/v1/targets \
  -H "Content-Type: application/json" \
  -d '{"name":"demo-web","type":"WEB_URL","connection_info":{"url":"https://example.com"}}'
```

### 스캔 실행(무인증 접근 확인)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{"target_id":3,"scan_scope":["dynamic_idor_scanner"],"scan_config":{"dynamic_idor_scanner":{"endpoint_path":"/api/users/2","require_auth":true,"verify_ssl":true}}}'
```

### 스캔 실행(인증 헤더 포함)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{"target_id":3,"scan_scope":["dynamic_idor_scanner"],"scan_config":{"dynamic_idor_scanner":{"endpoint_path":"/api/users/2","require_auth":true,"auth_headers":{"Authorization":"Bearer TOKEN"}}}}'
```

---

## 결과 확인 및 보고서
```bash
# 결과 조회
curl http://127.0.0.1:8000/api/v1/jobs/1/findings

# 보고서 생성
curl -X POST http://127.0.0.1:8000/api/v1/jobs/1/report \
  -H "Content-Type: application/json" \
  -d '{"format":"json"}'

# 보고서 다운로드
curl -O http://127.0.0.1:8000/api/v1/reports/1/file
```
