<!-- PLUGIN_WORKFLOW.md: 플러그인 추가/테스트/API 호출 과정을 코드 단위로 설명 -->
# 플러그인 추가/테스트/API 호출 가이드(코드 단위)

## 공통 실행 흐름(함수 단위)
1. API 요청 → `app/api/app.py:create_job()` 또는 `run_job()`
2. 스캔 실행 → `app/services/scan_executor.py:ScanExecutor.run_job()`
3. 설정 검증 → `app/core/config_validation.py:apply_config_schema()`
4. 플러그인 로딩 → `app/core/plugin_loader.py:PluginLoader.load_plugin()`
5. 플러그인 실행 → `plugins/**/main.py:*.check()`
6. 결과 저장 → `ScanExecutor._store_findings()`
7. 태그 확장 → `app/core/taxonomy.py:TaxonomyIndex.expand_tags()`

## 플러그인 공통 구조
- 메타데이터: `plugins/<채널>/<플러그인명>/plugin.yml`
- 실행 코드: `plugins/<채널>/<플러그인명>/main.py`
- 필수 클래스/함수:
  - `class <PluginName>(BasePlugin)`
  - `def check(self) -> List[Finding]`

### 플러그인 추가 절차(코드 단위)
1. 디렉터리 생성
   - `plugins/<channel>/<plugin_name>/`
2. `plugin.yml` 작성
   - `id`, `name`, `version`, `type`, `entry_point`, `class_name` 필수
   - 필요 시 `config_schema` 추가
3. `main.py` 구현
   - `BasePlugin` 상속
   - `check()`에서 진단 수행 후 `add_finding()` 호출
4. 매핑 추가(선택)
   - KISA/OWASP 매핑이 필요하면 `app/data/mappings/kisa_owasp.yml` 갱신
5. 테스트 추가
   - `tests/`에 유닛 테스트 혹은 데모 스크립트 추가

---

## 플러그인별 상세

### 1) Static: dependency_check
**파일**
- `plugins/static/dependency_check/plugin.yml`
- `plugins/static/dependency_check/main.py`

**핵심 함수**
- `DependencyCheck.check()`
  - `manifest_path` 읽기
  - `==` 미사용 버전 지정 발견 시 `add_finding()` 호출

**config_schema 예시**
```yaml
config_schema:
  properties:
    manifest_path:
      type: string
      default: "requirements.txt"
    repo_url:
      type: string
    repo_ref:
      type: string
```

**API 호출 예시**
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{"target_id":1,"scan_scope":["static_dependency_check"],"scan_config":{"static_dependency_check":{"manifest_path":"requirements.txt"}}}'
```

**테스트 방법**
- 데모 실행: `python3 scripts/run_static_demo.py`
- 유닛 테스트: `UV_CACHE_DIR=.uv-cache uv run pytest -q`

---

### 2) Remote: linux_kisa_u01
**파일**
- `plugins/remote/linux_kisa_u01/plugin.yml`
- `plugins/remote/linux_kisa_u01/main.py`

**핵심 함수**
- `RootLoginCheck.check()`
  - 로컬 파일(`sshd_config_path`) 읽기 또는 SSH로 원격 `cat /etc/ssh/sshd_config`
  - `PermitRootLogin` 값 파싱 → 취약 시 `add_finding()`
- SSH 경로
  - `app/adapters/ssh.py:SshClient.run()`

**config_schema 예시**
```yaml
config_schema:
  properties:
    sshd_config_path:
      type: string
      default: "fixtures/sshd_config_demo"
    use_sudo:
      type: boolean
      default: false
    sudo_user:
      type: string
```

**API 호출 예시(원격 SSH)**
```bash
# 대상 등록
curl -X POST http://127.0.0.1:8000/api/v1/targets \
  -H "Content-Type: application/json" \
  -d '{"name":"demo-server","type":"SERVER","connection_info":{"host":"192.168.40.129","port":22},"credentials":{"username":"user","password":"pass"}}'

# 스캔 실행
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{"target_id":1,"scan_scope":["remote_linux_kisa_u01"],"scan_config":{"remote_linux_kisa_u01":{"sshd_config_path":"/etc/ssh/sshd_config","use_sudo":false}}}'
```

**테스트 방법**
- 로컬 데모: `python3 scripts/run_remote_demo.py`
- 원격 테스트: 위 API 호출 후 결과 조회
- 참고: 비밀번호 인증은 `sshpass` 필요

---

### 3) Dynamic: idor_scanner
**파일**
- `plugins/dynamic/idor_scanner/plugin.yml`
- `plugins/dynamic/idor_scanner/main.py`

**핵심 함수**
- `IdorScanner.check()`
  - 대상 URL 결정(`base_url` or `target.connection_info.url`)
  - 무인증 요청 수행 (`HttpClient.get()`)
  - `require_auth=True`이고 무인증 200이면 `add_finding()`
- HTTP 경로
  - `app/adapters/http.py:HttpClient.request()`

**config_schema 예시**
```yaml
config_schema:
  properties:
    base_url:
      type: string
    endpoint_path:
      type: string
      default: "/api/users/1"
    headers:
      type: object
      default: {}
    auth_headers:
      type: object
      default: {}
    require_auth:
      type: boolean
      default: false
    timeout:
      type: integer
      default: 5
      min: 1
    verify_ssl:
      type: boolean
      default: true
```

**API 호출 예시**
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{"target_id":1,"scan_scope":["dynamic_idor_scanner"],"scan_config":{"dynamic_idor_scanner":{"endpoint_path":"/api/users/2","require_auth":true}}}'
```

**테스트 방법**
- 데모 실행: `python3 scripts/run_dynamic_demo.py`
  - 로컬 HTTP 서버를 임시 생성하여 동작 확인

---

## 결과 확인 및 보고서 생성
- 결과 조회: `GET /api/v1/jobs/{id}/findings`
- 보고서 생성: `POST /api/v1/jobs/{id}/report`
- 다운로드: `GET /api/v1/reports/{id}/file`

```bash
curl http://127.0.0.1:8000/api/v1/jobs/1/findings
curl -X POST http://127.0.0.1:8000/api/v1/jobs/1/report \
  -H "Content-Type: application/json" \
  -d '{"format":"json"}'
curl -O http://127.0.0.1:8000/api/v1/reports/1/file
```

## 빠른 테스트 체크리스트
- 플러그인 로딩: `tests/test_plugin_loader.py`
- 설정 스키마 검증: `tests/test_config_validation.py`
- 태그 확장: `tests/test_taxonomy.py`
- 데모 실행: `scripts/run_*_demo.py`
