<!-- AGENTS.md: 저장소 협업 가이드를 제공하는 문서 -->
# Repository Guidelines

## 프로젝트 구조 및 모듈 구성
현재 저장소는 가이드 구조를 기준으로 스켈레톤이 구성되어 있습니다. 주요 경로는 `app/`(코어, DB 모델, 서비스, 매핑 데이터), `plugins/<static|remote|dynamic>/`(진단 플러그인), `storage/`(아티팩트·증적), `tests/`(테스트), `run.py`(엔트리포인트), `docker-compose.yml`(로컬 의존 서비스)입니다.

## 빌드, 테스트, 개발 명령
현재는 스켈레톤 단계이며 아래 명령은 기본 템플릿으로 제공됩니다.
- `pip install -r requirements.txt`: 런타임 의존성 설치.
- `pip install -r requirements-dev.txt`: 개발/테스트 의존성 설치.
- `python run.py`: 오케스트레이터 진입점(플러그인 탐색 로그 출력).
- `python scripts/run_static_demo.py`: 정적 채널 데모 플러그인 실행.
- `python scripts/run_remote_demo.py`: 원격 채널 데모 플러그인 실행.
- `python scripts/run_dynamic_demo.py`: 동적 채널 데모 플러그인 실행.
- `docker-compose up`: 로컬 DB·캐시 서비스 실행.
- `pytest`: 테스트 실행.

## 코딩 스타일 및 네이밍 규칙
Python 4-space 들여쓰기와 PEP 8을 기본으로 합니다. 함수·모듈은 `snake_case`, 클래스는 `CapWords`를 사용합니다. 플러그인은 `plugins/<채널>/<플러그인명>/` 구조로 두고 `main.py`와 `plugin.yml`을 포함하세요. 메타데이터 ID는 `remote_linux_kisa_u01`처럼 명확하고 안정적인 규칙을 유지합니다.

## 테스트 가이드라인
테스트 프레임워크는 `pytest`를 사용합니다. `tests/` 아래에 `test_*.py` 형태로 작성하며, 플러그인 로더·태그 매핑은 유닛 테스트로, 외부 도구 연동은 통합 테스트로 분리합니다.

## 커밋 및 PR 가이드라인
이 저장소에는 커밋 히스토리가 없으므로 메시지 규칙은 일관되게 통일하세요. 예: `Add plugin loader` 또는 `feat: add plugin loader`. PR에는 변경 요약, 실행한 테스트, 설정 변경 여부(예: 환경 변수 추가)를 포함하고, 관련 이슈가 있으면 링크합니다.

## 보안 및 구성 팁
자격 증명은 커밋하지 말고 환경 변수나 암호화된 설정에 저장하세요. `storage/` 하위 아티팩트와 증적은 민감 정보일 수 있으므로 로그·공유 범위를 최소화합니다.
