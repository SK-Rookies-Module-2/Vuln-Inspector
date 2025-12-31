<!-- README.md: 저장소 개요, 구조, 사용법을 요약하는 문서 -->
# vuln-inspector

## 개요
이 저장소는 중앙 오케스트레이터가 정적(Static), 원격(Remote), 동적(Dynamic) 채널 플러그인을 로드해 취약점을 진단하는 구조를 목표로 합니다. KISA U-코드와 OWASP 2025 카테고리를 매핑해 태그를 확장하는 체계를 기본으로 제공합니다.

## 프로젝트 구조
- `app/`: 코어 로직, 서비스, DB 모델, 매핑 데이터
- `plugins/`: 채널별 플러그인(Static/Remote/Dynamic)
- `scripts/`: 채널별 데모 실행 스크립트
- `fixtures/`: 데모 점검용 설정/입력 파일
- `tests/`: 기본 유닛 테스트
- `storage/`: 스캔 아티팩트/증적 저장소

## 구조 확정 및 운용 변경 범위
현재 구조는 **플러그인 추가와 DB 연결 변경만으로 운용 가능한 상태**로 고정했습니다.  
운용 시 필수로 변경되는 범위는 아래 두 가지입니다.
- 플러그인 추가/수정: `plugins/` 및 필요 시 `app/data/mappings/`
- DB 연결 변경: `DATABASE_URL` 환경 변수 설정

## 모듈 상호작용 흐름
1. `Orchestrator`가 `PluginLoader`로 `plugins/**/plugin.yml`을 탐색합니다.
2. 선택된 플러그인은 `BasePlugin`을 상속한 클래스에서 `check()`를 실행합니다.
3. 플러그인은 `add_finding()`으로 결과를 생성하고, `TaxonomyIndex`가 KISA→OWASP 태그를 확장합니다.
4. 결과는 `services/reporting.py` 등에서 요약하거나 리포트로 확장할 수 있습니다.

## 핵심 모듈
- `app/core/`: 플러그인 로딩, 태그 매핑, 공통 타입
- `app/services/`: 오케스트레이터와 리포팅 로직
- `app/db/`: SQLAlchemy 모델/세션
- `app/data/mappings/`: KISA ↔ OWASP 매핑 데이터

## 빠른 실행
```bash
# uv로 의존성 설치(가상환경 포함)
uv venv
uv pip install -r requirements.txt -r requirements-dev.txt

# 데모 실행(채널별)
uv run python scripts/run_static_demo.py
uv run python scripts/run_remote_demo.py
uv run python scripts/run_dynamic_demo.py
```

## 채널별 기본 진단 동작
- Static: `requirements.txt`를 읽어 버전이 고정되지 않은 의존성을 탐지합니다.
- Remote: `fixtures/sshd_config_demo`를 읽어 `PermitRootLogin` 설정을 점검합니다.
- Dynamic: 로컬 HTTP 서버를 임시로 띄우고 `/api/users/2` 접근 허용 여부를 확인합니다.

## 결과 출력
각 데모 스크립트는 Findings 개수와 증적(evidence)을 콘솔에 출력합니다.

## API 실행
```bash
uv run uvicorn app.api.app:app --reload
```
- 기본 DB는 `storage/vuln_inspector.db`(SQLite)이며, `DATABASE_URL`로 변경할 수 있습니다.
- 현재 스캔 요청은 동기 실행입니다(요청이 완료될 때까지 응답 대기).

## API 사용 예시
```bash
# 대상 등록
curl -X POST http://127.0.0.1:8000/api/v1/targets \
  -H "Content-Type: application/json" \
  -d '{"name":"demo-web","type":"WEB_URL","connection_info":{"url":"http://127.0.0.1"}}'

# 원격 대상 예시(SSH)
curl -X POST http://127.0.0.1:8000/api/v1/targets \
  -H "Content-Type: application/json" \
  -d '{"name":"demo-server","type":"SERVER","connection_info":{"host":"127.0.0.1","port":22},"credentials":{"username":"root","key_path":"/path/to/key","password":""}}'

# 스캔 요청(즉시 실행)
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{"target_id":1,"scan_scope":["static_dependency_check","remote_linux_kisa_u01"],"scan_config":{"static_dependency_check":{"manifest_path":"requirements.txt"},"remote_linux_kisa_u01":{"sshd_config_path":"fixtures/sshd_config_demo"}}}'

# 상태 조회
curl http://127.0.0.1:8000/api/v1/jobs/1/status

# 결과 조회
curl http://127.0.0.1:8000/api/v1/jobs/1/findings

# 보고서 생성(JSON/CSV)
curl -X POST http://127.0.0.1:8000/api/v1/jobs/1/report \
  -H "Content-Type: application/json" \
  -d '{"format":"json"}'

# 보고서 생성(CSV)
curl -X POST http://127.0.0.1:8000/api/v1/jobs/1/report \
  -H "Content-Type: application/json" \
  -d '{"format":"csv"}'

# 보고서 메타 조회
curl http://127.0.0.1:8000/api/v1/reports/1

# 보고서 생성 후 id 추출(예: jq 사용)
curl -X POST http://127.0.0.1:8000/api/v1/jobs/1/report \
  -H "Content-Type: application/json" \
  -d '{"format":"json"}' | jq -r '.id'

# 보고서 파일 다운로드
curl -O http://127.0.0.1:8000/api/v1/reports/1/file
```

## 대상/자격증명 스키마
- SERVER: `connection_info.host`(또는 `ip`) 필수, `port` 선택
- WEB_URL: `connection_info.url` 필수
- GIT_REPO: `connection_info.url` 또는 `path` 필수
- 원격 점검 사용 시 `credentials.username`과 `key_path` 또는 `password`가 필요합니다.

## 매핑 데이터
- KISA → OWASP 매핑: `app/data/mappings/kisa_owasp.yml`
- 플러그인 태그에 `KISA:U-01`처럼 KISA 코드를 포함하면, 매핑을 통해 `OWASP:2025:A07` 같은 태그가 자동 확장됩니다.

## 플러그인 개발 가이드
- 플러그인은 `plugins/<채널>/<플러그인명>/` 구조로 추가합니다.
- `plugin.yml`에 `id`, `entry_point`, `class_name`을 정의합니다.
- 실행 클래스는 `BasePlugin`을 상속하고 `check()`에서 `add_finding()`으로 결과를 반환합니다.
- `config_schema`로 플러그인별 설정 검증/기본값 주입을 지원합니다.

## 테스트
```bash
uv run pytest
```

## 확장 방향
아래는 선택 확장 항목이며, 현재 운용에는 필수가 아닙니다.
- Static: 외부 SCA 도구(OSV, Safety 등) 어댑터 연동
- Remote: SSH/WinRM 기반 점검 스크립트와 결과 파싱 확장
- Dynamic: HTTP 기반 휴리스틱/레시피 엔진 고도화
- DB: 마이그레이션 도구(Alembic) 도입
