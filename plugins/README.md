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
원격 플러그인의 경우 `target.connection_info`(host/port)와 `target.credentials`(username/key_path)를 사용해 SSH로 접근할 수 있습니다.

### 정적(Static) 관련 권장 필드
- `manifest_path`: 매니페스트 상대 경로(기본 `requirements.txt`)
- `repo_url`/`repo_ref`: Git 저장소 URL과 브랜치/태그(선택)

### 원격(SSH) 관련 권장 필드
- `connection_info.host` 또는 `ip`, `port`
- `connection_info.proxy_jump`: 점프 호스트(`user@host:port` 형식)
- `credentials.username`, `credentials.key_path` 또는 `credentials.password`
- 플러그인 설정: `use_sudo`/`sudo_user` 등
 - `password` 인증을 쓸 경우 `sshpass`가 필요합니다.

### 동적(HTTP) 관련 권장 필드
- `connection_info.url` 또는 플러그인 설정의 `base_url`
- 플러그인 설정: `headers`, `auth_headers`, `require_auth`, `timeout`, `verify_ssl`

## 태그 규칙
- KISA U-코드: `KISA:U-01`
- OWASP 2025: `OWASP:2025:A01`
- 매핑 확장은 `app/data/mappings/kisa_owasp.yml`에 추가합니다.
