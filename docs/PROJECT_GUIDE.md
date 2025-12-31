<!-- PROJECT_GUIDE.md: 전체 동작 흐름 및 파일 관계를 설명하는 운영/개발 가이드 -->
# 프로젝트 전체 가이드

## 목적과 범위
이 문서는 프로젝트를 처음 보는 사람이 **이 문서만으로** 실행/테스트/확장이 가능하도록 전체 동작 흐름과 파일 간 연관 관계를 설명합니다. 단기 목표는 “스캔 결과 보고서 생성”까지의 MVP이며, 성능/인증/비동기 처리는 우선순위가 낮습니다.

## 전체 동작 프로세스(요약)
1. **대상 등록**: `POST /api/v1/targets` → `Target` 저장.
2. **스캔 요청**: `POST /api/v1/jobs` → `ScanJob` 저장 후 동기 실행.
3. **플러그인 실행**: `ScanExecutor`가 `plugin.yml`을 읽어 플러그인을 로드하고 `check()` 실행.
4. **결과 저장**: `Finding`을 DB에 저장, KISA 태그는 OWASP 태그로 확장.
5. **결과 조회**: `GET /api/v1/jobs/{id}/findings`로 결과 확인.
6. **보고서 생성/다운로드**: `POST /api/v1/jobs/{id}/report` → `storage/reports/{job_id}/report.(json|csv)` 생성, `/reports/{id}/file`로 다운로드.

## 실행 방법(uv 기준)
```bash
uv venv
uv pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env
uv run uvicorn app.api.app:app --reload
```

## PostgreSQL 실행(로컬)
```bash
docker-compose up -d
```

## 구조 확정 및 운용 변경 범위
현재 구조는 **플러그인 추가와 DB 연결 변경만으로 운용 가능한 상태**로 고정했습니다.  
운용 시 필수로 변경되는 범위는 아래 두 가지입니다.
- 플러그인 추가/수정: `plugins/` 및 필요 시 `app/data/mappings/`
- DB 연결 변경: `.env`의 `DB_*` 또는 `DATABASE_URL` 설정

## API 기본 사용 흐름
```bash
# 1) 대상 등록
curl -X POST http://127.0.0.1:8000/api/v1/targets \
  -H "Content-Type: application/json" \
  -d '{"name":"demo-web","type":"WEB_URL","connection_info":{"url":"http://127.0.0.1"}}'

# 2) 스캔 요청
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{"target_id":1,"scan_scope":["static_dependency_check"],"scan_config":{"static_dependency_check":{"manifest_path":"requirements.txt"}}}'

# 3) 결과 조회
curl http://127.0.0.1:8000/api/v1/jobs/1/findings

# 4) 보고서 생성
curl -X POST http://127.0.0.1:8000/api/v1/jobs/1/report \
  -H "Content-Type: application/json" \
  -d '{"format":"json"}'

# 5) 보고서 다운로드
curl -O http://127.0.0.1:8000/api/v1/reports/1/file
```

## 대상/자격증명 스키마
- SERVER: `connection_info.host`(또는 `ip`) 필수, `port` 선택
- WEB_URL: `connection_info.url` 필수
- GIT_REPO: `connection_info.url` 또는 `path` 필수
- 원격 점검 시: `credentials.username`과 `key_path` 또는 `password` 필요

## 모듈 간 상호작용
- `app/api/app.py` → `app/services/scan_executor.py`, `app/services/reporting.py` 호출
- `scan_executor.py` → `app/core/plugin_loader.py`로 플러그인 로딩
- `plugin_loader.py` → `plugin.yml` 메타데이터 로드, `BasePlugin` 인스턴스 생성
- `BasePlugin.add_finding()` → `TaxonomyIndex`로 태그 확장
- `reporting.py` → 결과를 JSON/CSV로 저장

## 기능 추가/변경 방법
### 새 플러그인 추가
1. `plugins/<채널>/<플러그인명>/` 생성
2. `plugin.yml`에 `id`, `entry_point`, `class_name`, `config_schema` 정의
3. `main.py`에서 `BasePlugin` 상속 후 `check()` 구현
4. 필요 시 `app/data/mappings/kisa_owasp.yml`에 태그 매핑 추가
5. 테스트 추가 후 `uv run pytest`

### 기존 플러그인 수정
- `plugin.yml`의 `config_schema` 변경 시 **입력 검증**이 즉시 적용됨
- 어댑터 사용: HTTP는 `app/adapters/http.py`, SSH는 `app/adapters/ssh.py` 활용

### 보고서 형식 추가
- `app/services/reporting.py`에 형식 추가
- `SUPPORTED_FORMATS` 확장 및 생성 로직 구현

## 디렉터리/파일 맵(전수)
> 각 파일은 “무엇을 담당하는지”와 “어떤 모듈과 연결되는지”를 명시합니다.

### 루트
- `AGENTS.md`: 협업/운영 가이드
- `Guide.md`: 설계서(아키텍처 원본)
- `README.md`: 사용법 요약
- `pyproject.toml`: 프로젝트 메타데이터
- `requirements.txt`: 런타임 의존성
- `requirements-dev.txt`: 개발/테스트 의존성
- `uv.lock`: uv 의존성 잠금 파일
- `docker-compose.yml`: 로컬 DB/캐시 구성
- `run.py`: 오케스트레이터 실행 진입점(기본)
- `main.py`: 간단 샘플 실행

### app/
- `app/__init__.py`: 패키지 초기화
- `app/api/app.py`: FastAPI 엔드포인트(전체 API 흐름의 시작점)
- `app/api/schemas.py`: API 요청/응답 스키마
- `app/api/router.py`: 라우팅 확장용 자리
- `app/core/config.py`: 경로/DB 설정
- `app/core/storage.py`: 보고서/아티팩트/증적 경로 생성
- `app/core/errors.py`: 공통 에러 타입
- `app/core/config_validation.py`: 플러그인 설정 스키마 검증
- `app/core/plugin_loader.py`: `plugin.yml` 로딩/플러그인 로딩
- `app/core/plugin_base.py`: 플러그인 베이스 클래스
- `app/core/taxonomy.py`: KISA→OWASP 태그 확장
- `app/core/types.py`: 공통 타입
- `app/core/logging.py`: 로깅 설정
- `app/core/__init__.py`: 코어 심볼 노출
- `app/db/base.py`: SQLAlchemy Base
- `app/db/models.py`: DB 모델(Target/ScanJob/Finding/Report)
- `app/db/session.py`: DB 세션/초기화
- `app/db/__init__.py`: DB 심볼 노출
- `app/services/orchestrator.py`: 플러그인 목록 조회(기본)
- `app/services/scan_executor.py`: 플러그인 실행 → 결과 저장
- `app/services/reporting.py`: 보고서 생성
- `app/services/__init__.py`: 서비스 노출
- `app/adapters/base.py`: 어댑터 인터페이스
- `app/adapters/registry.py`: 어댑터 레지스트리(선택)
- `app/adapters/http.py`: HTTP 어댑터(헤더/타임아웃/SSL)
- `app/adapters/ssh.py`: SSH 어댑터(키/패스워드/프록시/ sudo)
- `app/adapters/sca.py`: SCA 도구 실행 래퍼
- `app/adapters/__init__.py`: 어댑터 노출
- `app/data/mappings/kisa_owasp.yml`: KISA→OWASP 매핑 데이터
- `app/data/mappings/README.md`: 매핑 규칙 설명
- `app/data/taxonomies/README.md`: 분류 데이터 안내

### plugins/
- `plugins/README.md`: 플러그인 구조/설정 스키마 설명
- `plugins/static/dependency_check/main.py`: 정적 의존성 고정 여부 점검
- `plugins/static/dependency_check/plugin.yml`: 정적 플러그인 메타/스키마
- `plugins/remote/linux_kisa_u01/main.py`: SSH 기반 U-01 점검
- `plugins/remote/linux_kisa_u01/plugin.yml`: 원격 플러그인 메타/스키마
- `plugins/dynamic/idor_scanner/main.py`: HTTP 기반 IDOR 점검
- `plugins/dynamic/idor_scanner/plugin.yml`: 동적 플러그인 메타/스키마

### scripts/
- `scripts/run_static_demo.py`: 정적 플러그인 데모 실행
- `scripts/run_remote_demo.py`: 원격 플러그인 데모 실행
- `scripts/run_dynamic_demo.py`: 동적 플러그인 데모 실행

### fixtures/
- `fixtures/sshd_config_demo`: 원격 플러그인 테스트용 SSH 설정 파일

### tests/
- `tests/conftest.py`: 테스트 경로 초기화
- `tests/test_taxonomy.py`: 태그 확장 테스트
- `tests/test_plugin_loader.py`: 플러그인 탐색 테스트
- `tests/test_config_validation.py`: 설정 스키마 검증 테스트

### storage/
- `storage/vuln_inspector.db`: SQLite DB 파일(생성물)
- `storage/reports/1/report.json`: 보고서 예시(생성물)

### referenceSource/
- `referenceSource/exploit_checker/*`: 참고용 스캐너 코드 및 스크립트
- `referenceSource/vulnerability-check/*`: OS별 점검 스크립트 참고 자료
- `referenceSource/centos_vuln_check_script/*`: CentOS 점검 스크립트 참고 자료

## 테스트 방법
```bash
UV_CACHE_DIR=.uv-cache uv run pytest -q
```

## 변경 시 주의사항
- 플러그인 설정 변경 시 `config_schema`에 기본값/타입을 반드시 추가하세요.
- 원격 플러그인에서 비밀번호 인증을 사용할 경우 `sshpass` 설치가 필요합니다.
- 보고서는 생성된 파일을 DB에 기록하므로, 경로 변경 시 `app/services/reporting.py`와 `app/core/storage.py`를 같이 수정해야 합니다.
