<!-- plugins/README.md: 플러그인 구조 안내 문서 -->
# 플러그인 디렉터리 안내

플러그인은 채널별로 분리하여 추가합니다.
- `plugins/static/`: 정적 분석
- `plugins/remote/`: 원격 설정 분석
- `plugins/dynamic/`: 런타임 검증

## 플러그인 구성
각 플러그인은 아래 파일을 포함해야 합니다.
- `plugin.yml`: 메타데이터(식별자, 태그, 실행 정보)
- `main.py`: 실행 클래스(예: `class_name`)

## 설정 스키마
`plugin.yml`에 `config_schema`를 정의하면 입력 설정을 검증하고 기본값을 주입할 수 있습니다.

## 태그 규칙
- KISA U-코드: `KISA:U-01`
- OWASP 2025: `OWASP:2025:A01`
- 매핑 확장은 `app/data/mappings/kisa_owasp.yml`에 추가합니다.
