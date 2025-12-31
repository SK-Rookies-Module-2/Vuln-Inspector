<!-- CONTRIBUTING.md: 기여자용 구조/확장/테스트 가이드 -->
# 기여 가이드

이 문서는 프로젝트 구조를 모르는 기여자가 **플러그인 추가/수정/테스트**를 바로 수행할 수 있도록 필요한 파일과 절차를 정리합니다.

## 먼저 읽을 문서
- `README.md`: 실행/사용법 요약
- `docs/PROJECT_GUIDE.md`: 전체 동작 흐름/파일 맵
- `docs/PLUGIN_WORKFLOW.md`: 플러그인 추가/테스트/API 호출 흐름(코드 단위)
- `docs/API_SCHEMA.md`: API 스키마 상세

## 프로젝트 핵심 구조
- `app/api/`: API 엔드포인트 및 스키마
- `app/services/`: 스캔 실행 및 리포팅
- `app/core/`: 플러그인 로더/설정 검증/태그 매핑/경로 관리
- `app/db/`: DB 모델 및 세션
- `plugins/`: 채널별 플러그인
- `tests/`: 유닛 테스트
- `scripts/`: 데모 실행 스크립트

## 플러그인 추가 방법(설명 + 예시)
플러그인은 **`plugin.yml`(메타/설정 스키마)**와 **`main.py`(실행 로직)** 두 파일이 핵심입니다.  
`plugin.yml`은 로더가 읽는 “실행 계약서”이고, `main.py`는 실제 진단 로직을 담습니다.  
아래는 **새 정적 플러그인** `static_license_check`를 추가하는 과정을 **설명 → 예시** 순서로 보여줍니다.

### 1) 디렉터리 생성
플러그인은 채널별 하위 폴더에 둡니다. 채널은 `static|remote|dynamic` 중 하나이며, 폴더명은 플러그인 기능을 설명하는 소문자 스네이크 케이스를 권장합니다.
```
plugins/static/license_check/
```

### 2) plugin.yml 작성
`plugin.yml`은 플러그인 로더가 읽는 메타데이터입니다. `id`는 API에서 `scan_scope`로 호출할 때 사용되는 키이며 **고유해야 합니다**.  
`config_schema`는 API로 받은 설정값을 검증하고 기본값을 주입하는 규칙입니다.
`plugins/static/license_check/plugin.yml`
```yaml
id: "static_license_check"
name: "License Policy Check"
version: "0.1.0"
type: "static"
category: "policy"
tags:
  - "OWASP:2025:A03"
description: "Check for disallowed licenses in dependency metadata."
config_schema:
  properties:
    manifest_path:
      type: string
      default: "requirements.txt"
    blocked_licenses:
      type: array
      default: ["GPL-3.0"]
entry_point: "main.py"
class_name: "LicenseCheck"
```

### 3) main.py 구현
`main.py`는 `BasePlugin`을 상속해 `check()`를 구현합니다.  
실제 진단 로직을 수행한 뒤, 발견 사항은 `add_finding()`으로 기록합니다.
`plugins/static/license_check/main.py`
```python
from typing import List

from app.core.plugin_base import BasePlugin
from app.core.types import Finding


class LicenseCheck(BasePlugin):
    def check(self) -> List[Finding]:
        manifest_path = self.context.config.get("manifest_path")
        blocked = set(self.context.config.get("blocked_licenses", []))

        # 실제 구현에서는 manifest를 파싱해 라이선스 목록을 수집해야 합니다.
        detected = "GPL-3.0"
        if detected in blocked:
            self.add_finding(
                vuln_id="POLICY-BLOCKED-LICENSE",
                title="차단된 라이선스 사용",
                severity="Info",
                evidence={"manifest": manifest_path, "license": detected},
                tags=["OWASP:2025:A03"],
                description="정책상 허용되지 않는 라이선스가 포함되어 있습니다.",
                solution="해당 라이선스를 제거하거나 대체하세요.",
            )
        return self.results
```

### 4) 매핑 추가(필요 시)
KISA → OWASP 태그 확장이 필요하면 매핑 파일을 갱신합니다.  
OWASP 태그만 사용하는 경우 이 단계는 생략 가능합니다.
`app/data/mappings/kisa_owasp.yml`에 필요한 매핑을 추가합니다.

### 5) API에서 실행(예시)
플러그인 ID를 `scan_scope`에 넣고, 같은 키의 설정을 `scan_config`에 넣습니다.  
`scan_config`는 없으면 `config_schema`의 기본값이 자동 적용됩니다.
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{"target_id":1,"scan_scope":["static_license_check"],"scan_config":{"static_license_check":{"manifest_path":"requirements.txt","blocked_licenses":["GPL-3.0","AGPL-3.0"]}}}'
```

### 6) 테스트 추가(선택)
유닛 테스트(계약/로직) 또는 데모 스크립트(실행 경로)를 추가합니다.
- `tests/`에 유닛 테스트 추가
- `scripts/`에 데모 스크립트 추가

## 원격 플러그인 예시(설명 + 예시)
원격 플러그인은 **SSH 접근 정보**를 `Target`에 넣고, 플러그인 설정은 `scan_config`로 전달합니다.  
설정 파일을 로컬에서 읽지 못하면 SSH로 원격 파일을 읽는 방식입니다.

### 1) 디렉터리 생성
```
plugins/remote/linux_kisa_u02/
```

### 2) plugin.yml 작성
`plugins/remote/linux_kisa_u02/plugin.yml`
```yaml
id: "remote_linux_kisa_u02"
name: "Password Policy Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-02"
description: "Check password policy configuration."
config_schema:
  properties:
    config_path:
      type: string
      default: "/etc/login.defs"
    use_sudo:
      type: boolean
      default: false
entry_point: "main.py"
class_name: "PasswordPolicyCheck"
```

### 3) main.py 구현(요약)
```python
from typing import List

from app.adapters.ssh import SshClient
from app.core.plugin_base import BasePlugin
from app.core.types import Finding


class PasswordPolicyCheck(BasePlugin):
    def check(self) -> List[Finding]:
        config_path = self.context.config.get("config_path")
        connection = self.context.target.get("connection_info", {})
        credentials = self.context.target.get("credentials", {})
        client = SshClient(
            host=connection.get("host"),
            user=credentials.get("username"),
            password=credentials.get("password"),
            port=int(connection.get("port", 22)),
        )
        result = client.run(f"cat {config_path}")
        if "PASS_MAX_DAYS" in result.stdout:
            self.add_finding(
                vuln_id="KISA-U-02",
                title="비밀번호 정책 점검",
                severity="Medium",
                evidence={"config_path": config_path},
                tags=["KISA:U-02"],
                description="비밀번호 정책 항목을 확인했습니다.",
                solution="정책 기준에 맞게 설정하세요.",
            )
        return self.results
```

### 4) API 호출 예시
```bash
curl -X POST http://127.0.0.1:8000/api/v1/targets \
  -H "Content-Type: application/json" \
  -d '{"name":"demo-server","type":"SERVER","connection_info":{"host":"192.168.40.129","port":22},"credentials":{"username":"user","password":"pass"}}'

curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{"target_id":1,"scan_scope":["remote_linux_kisa_u02"],"scan_config":{"remote_linux_kisa_u02":{"config_path":"/etc/login.defs","use_sudo":false}}}'
```

## 동적 플러그인 예시(설명 + 예시)
동적 플러그인은 **HTTP 엔드포인트**를 대상으로 요청을 보내 응답을 분석합니다.  
`require_auth`를 사용하는 경우 무인증 접근 가능 여부를 탐지합니다.

### 1) 디렉터리 생성
```
plugins/dynamic/auth_bypass_check/
```

### 2) plugin.yml 작성
`plugins/dynamic/auth_bypass_check/plugin.yml`
```yaml
id: "dynamic_auth_bypass_check"
name: "Auth Bypass Check"
version: "0.1.0"
type: "dynamic"
category: "application"
tags:
  - "OWASP:2025:A01"
description: "Check unauthenticated access to protected endpoints."
config_schema:
  properties:
    base_url:
      type: string
    endpoint_path:
      type: string
      default: "/api/admin"
    require_auth:
      type: boolean
      default: true
    headers:
      type: object
      default: {}
    auth_headers:
      type: object
      default: {}
entry_point: "main.py"
class_name: "AuthBypassCheck"
```

### 3) main.py 구현(요약)
```python
from typing import List

from app.adapters.http import HttpClient
from app.core.plugin_base import BasePlugin
from app.core.types import Finding


class AuthBypassCheck(BasePlugin):
    def check(self) -> List[Finding]:
        base_url = self.context.config.get("base_url")
        endpoint = self.context.config.get("endpoint_path", "/api/admin")
        require_auth = bool(self.context.config.get("require_auth", True))
        headers = self.context.config.get("headers", {})
        auth_headers = self.context.config.get("auth_headers", {})

        client = HttpClient(timeout=5)
        unauth = client.get(f"{base_url.rstrip('/')}{endpoint}", headers=headers)
        if require_auth and unauth.status == 200:
            self.add_finding(
                vuln_id="OWASP-A01-UNAUTH",
                title="인증 우회 가능성",
                severity="Medium",
                evidence={"status": unauth.status, "endpoint": endpoint},
                tags=["OWASP:2025:A01"],
                description="인증 필요 엔드포인트에 대한 접근이 가능합니다.",
                solution="인증/인가 로직을 적용하세요.",
            )
        return self.results
```

### 4) API 호출 예시
```bash
curl -X POST http://127.0.0.1:8000/api/v1/targets \
  -H "Content-Type: application/json" \
  -d '{"name":"demo-web","type":"WEB_URL","connection_info":{"url":"http://127.0.0.1:8080"}}'

curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{"target_id":2,"scan_scope":["dynamic_auth_bypass_check"],"scan_config":{"dynamic_auth_bypass_check":{"endpoint_path":"/api/admin","require_auth":true}}}'
```

## 설정 전달 방식
- API 요청의 `scan_config`에 **plugin_id → 설정 객체**로 전달
- `config_schema`로 타입/기본값이 검증/주입됨

## 테스트 방법
- 유닛 테스트: `UV_CACHE_DIR=.uv-cache uv run pytest -q`
- 채널 데모: `python3 scripts/run_static_demo.py` 등

## 변경 시 체크리스트
- `plugin.yml`에 스키마/기본값이 정의되었는가?
- `add_finding()` 결과에 `tags`가 포함되는가?
- 필요한 경우 `README.md` 또는 `docs/*`에 사용법이 반영되었는가?
- 테스트를 통과했는가?

## 문의/리뷰 포인트
- 플러그인 ID는 고유한가?
- 설정 검증 오류 시 API가 400을 반환하는가?
- 결과(Findings)가 DB에 저장되는가?
- 보고서 생성/다운로드 경로가 정상인가?
