U-49: DNS 보안 버전 패치
• 중요도: 상
• 점검 목적: DNS 서비스(BIND)의 버전을 최신으로 유지.
• 보안 위협: 구버전 BIND는 원격 DoS, Cache Poisoning 등 심각한 취약점이 존재함.
점검 대상 및 판단 기준
• 양호: DNS 서비스를 사용하지 않거나, 최신 버전(패치 적용)을 사용하는 경우.
• 취약: 취약한 버전의 DNS 서비스를 사용하는 경우.
상세 점검 로직 (Scripting Guide)
• 명령어: named -v
• 판단: 출력된 버전이 최신 보안 패치 버전인지 벤더사 공지와 비교.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 명령 실행)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u49/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u49"
name: "DNS Service Version Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-49"
description: "Check BIND(named) version information."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    named_command:
      type: string
      default: "named -v"
    min_named_version:
      type: string
    report_unknown:
      type: boolean
      default: true
    max_results:
      type: integer
      default: 50
    use_sudo:
      type: boolean
      default: false
    sudo_user:
      type: string
    allow_local_fallback:
      type: boolean
      default: false
entry_point: "main.py"
class_name: "DnsServiceVersionCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `named_command` 기본값 제공.  
• `min_named_version`이 있으면 버전 비교 수행.  
• `report_unknown=true`이면 기준값이 없는 경우 Info로 보고.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 명령 실행 허용.
3) 명령 실행  
• `named -v` 실행 결과에서 버전 문자열 파싱.  
• 명령이 없으면 서비스 미사용으로 간주.  
• 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 판정  
• 버전이 기준값 미만이면 취약.  
• 기준값이 없거나 파싱 실패 시 `report_unknown=true`면 Info로 보고.  
• 서비스 미사용이면 결과 없음(양호).
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-49"`, `severity="High"`  
  - `tags=["KISA:U-49"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `host`  
• 기준 미설정 시 `Info` Finding 기록(선택).

### 파서 설계(요약)
• `named -v` 출력에서 버전 문자열을 파싱.  
• 버전 비교는 숫자 토큰 기반 비교.

### 테스트 계획
• 유닛:  
  - named 버전 파서 테스트.  
  - 버전 비교 로직 테스트.  
  - 명령 미존재/오류 처리 테스트.
• 통합(선택): `fixtures/` 샘플 출력으로 로컬 폴백 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-49 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u49"],
    "scan_config": {
      "remote_kisa_u49": {
        "os_type": "linux",
        "min_named_version": "9.18.0",
        "use_sudo": true
      }
    }
  }'
```

#### 3) 결과 확인
```bash
curl http://127.0.0.1:8000/api/v1/jobs/1/findings
```

#### 참고 (ProxyCommand 사용 시)
• KISA-U01 가이드의 Target 등록 4-1 방식(`proxy_command`)을 사용했다면, 동일 Target을 그대로 재사용하면 됩니다.
