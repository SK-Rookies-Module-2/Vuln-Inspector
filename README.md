<!-- README.md: 저장소 개요, 구조, 사용법을 요약하는 문서 -->
# vuln-inspector

## 개요
이 저장소는 중앙 오케스트레이터가 정적(Static), 원격(Remote), 동적(Dynamic) 채널 플러그인을 로드해 취약점을 진단하는 구조를 목표로 합니다. KISA/OWASP 태그는 플러그인이 전달한 값을 그대로 저장합니다.

## 프로젝트 구조
```
.
├── app/            # API/서비스/DB/어댑터 등 코어 로직
├── dashboard/      # Streamlit 대시보드
├── plugins/        # 채널별 플러그인(Static/Remote/Dynamic)
├── scripts/        # 데모 실행/유틸 스크립트
├── docs/           # 상세 문서
├── tests/          # 테스트 코드
├── fixtures/       # 데모용 설정/입력 파일
├── storage/        # 스캔 아티팩트/보고서 저장(생성물)
├── docker-compose.yml
├── Dockerfile
├── README.md
└── requirements.txt
```

## 구조 확정 및 운용 변경 범위
현재 구조는 **플러그인 추가와 DB 연결 변경만으로 운용 가능한 상태**로 고정했습니다.  
운용 시 필수로 변경되는 범위는 아래 두 가지입니다.
- 플러그인 추가/수정: `plugins/`
- DB 연결 변경: `DATABASE_URL` 환경 변수 설정


## Docker Compose 실행(서버/VM 공용)
Docker만 설치되어 있으면 **API + 대시보드 + DB를 한 번에** 실행할 수 있습니다.

### 1) .env 준비
```bash
bash scripts/bootstrap_env.sh
```

### 2) 빌드 및 실행
```bash
docker-compose up -d --build
```

### 3) 접속
- API: `http://<서버IP>:8000`
- 대시보드: `http://<서버IP>:8501`

### 4) 로그 확인/중지
```bash
docker-compose logs -f api
docker-compose logs -f dashboard
docker-compose down
```

### 참고
- 컨테이너 내부에서는 DB 호스트가 `db`로 자동 설정됩니다.
- `.env`에 `DATABASE_URL`을 직접 지정했다면 `db` 호스트로 맞춰야 합니다.
- 방화벽에서 `8000`, `8501` 포트를 허용해야 외부 접속이 가능합니다.

## 로컬 개발 실행(WSL + PostgreSQL)
Docker 대신 **로컬 PostgreSQL**을 사용해 개발/테스트할 수 있습니다.  
아래 순서대로 실행하면 **사전 환경이 없는 상태**에서도 API 서버와 대시보드를 함께 실행할 수 있습니다.

### 1) 필수 도구 설치
- 필수: `git`, `python3`, `pip`
- 권장: `docker`, `docker-compose` (PostgreSQL 사용 시)

```bash
# Ubuntu/Debian 예시
sudo apt update
sudo apt install -y git python3 python3-pip
```

### 2) 레포 클론 및 이동
```bash
git clone <REPO_URL>
cd vuln-inspector
```

### 3) uv 설치
```bash
python3 -m pip install --user uv
export PATH="$HOME/.local/bin:$PATH"
```

### 4) 의존성 설치
```bash
uv venv
uv pip install -r requirements.txt -r requirements-dev.txt
```

### 5) PostgreSQL 설치(WSL)
```bash
sudo apt update
sudo apt install -y postgresql postgresql-contrib
```

### 6) 계정/DB 생성 스크립트
아래 스크립트를 실행하면 `vuln` 계정과 `vuln_inspector` DB가 생성됩니다.
```bash
sudo -u postgres psql <<'SQL'
CREATE USER vuln WITH PASSWORD 'vuln';
CREATE DATABASE vuln_inspector OWNER vuln;
GRANT ALL PRIVILEGES ON DATABASE vuln_inspector TO vuln;
SQL
```

### 7) 환경 설정
```bash
bash scripts/bootstrap_env.sh
```
필요하면 `.env`에서 `DB_*` 값을 수정하거나 `DATABASE_URL`을 직접 지정하세요.

### 8) API 서버 실행
```bash
uv run uvicorn app.api.app:app --reload
```

### 9) 대시보드 실행(별도 터미널)
```bash
export API_BASE_URL="http://127.0.0.1:8000"
uv run streamlit run dashboard/app.py
```

## PostgreSQL 실행(로컬, Docker)
*Docker로 PostgreSQL만 실행하는 경우*   
```bash
docker-compose up -d db
```

## 채널별 기본 진단 동작
- Static: 로컬 `requirements.txt` 또는 GIT_REPO를 클론한 경로에서 버전 미고정을 탐지합니다.
- Remote: `fixtures/sshd_config_demo`를 읽어 `PermitRootLogin` 설정을 점검합니다.
- Dynamic: 로컬 HTTP 서버를 임시로 띄우고 `/api/users/2` 접근 허용 여부를 확인합니다.

## 결과 출력
각 데모 스크립트는 Findings 개수와 증적(evidence)을 콘솔에 출력합니다.

## API 실행
```bash
uv run uvicorn app.api.app:app --reload
```
- 기본 DB는 PostgreSQL이며, `.env`의 `DB_*` 또는 `DATABASE_URL`로 변경할 수 있습니다.
- 현재 스캔 요청은 동기 실행입니다(요청이 완료될 때까지 응답 대기).

## 대상/자격증명 스키마
- SERVER: `connection_info.host`(또는 `ip`) 필수, `port` 선택
- WEB_URL: `connection_info.url` 필수
- GIT_REPO: `connection_info.url` 또는 `path` 필수
- 원격 점검 사용 시 `credentials.username`과 `key_path` 또는 `password`가 필요합니다.

## 태그 사용
- 플러그인은 KISA/OWASP 태그를 그대로 기록합니다.
- 태그 규칙은 `plugins/README.md`를 따릅니다.
- KISA/OWASP 태그는 혼용 사용 가능하며 자동 변환은 하지 않습니다.

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
