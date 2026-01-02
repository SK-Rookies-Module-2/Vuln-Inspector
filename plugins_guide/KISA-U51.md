U-51: DNS 서비스의 취약한 동적 업데이트 설정 금지
• 중요도: 중
• 점검 목적: DNS 서비스의 동적 업데이트를 비활성화하여 신뢰할 수 없는 원본으로부터의 업데이트를 차단함.
• 보안 위협: 동적 업데이트가 활성화된 경우, 악의적인 사용자가 DNS 레코드를 임의로 변조할 위험이 있음.
상세 점검 로직 (Scripting Guide)
• 파일: /etc/named.conf 또는 /etc/bind/named.conf.options
• 로직:
    ◦ allow-update 구문 확인.
    ◦ { any; }로 설정되어 있거나 적절한 IP 제한이 없으면 취약.
    ◦ { none; } 또는 승인된 IP가 설정되어야 함.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 DNS 설정 파일 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u51/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u51"
name: "DNS Dynamic Update Restriction Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-51"
description: "Check allow-update directives in named configuration."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    named_conf_paths:
      type: array
      default:
        - "/etc/named.conf"
        - "/etc/bind/named.conf.options"
    max_results:
      type: integer
      default: 200
    use_sudo:
      type: boolean
      default: false
    sudo_user:
      type: string
    allow_local_fallback:
      type: boolean
      default: false
entry_point: "main.py"
class_name: "DnsDynamicUpdateCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `named_conf_paths` 기본값 적용.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 확인 허용.
3) 설정 파일 점검  
• `allow-update` 구문을 수집해 `{ any; }` 또는 비어있는 설정 여부 확인.  
• `allow-update` 구문이 전혀 없으면 미설정으로 취약 처리.  
• `allow-update { none; }` 또는 특정 IP/key 제한이 존재하면 양호.
4) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-51"`, `severity="Medium"`  
  - `tags=["KISA:U-51"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `missing_files`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• 주석(#, //, /* */) 제거 후 `allow-update` 구문을 추출.  
• `{ any; }` 포함 시 취약.  
• `{ none; }` 포함 시 양호.  
• `allow-update` 미설정 시 취약.

### 테스트 계획
• 유닛:  
  - allow-update 파서(있음/없음/any/none) 테스트.  
  - 명령 실패/파일 미존재 처리 테스트.  
• 통합(선택): 로컬 폴백으로 샘플 named.conf 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-51 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u51"],
    "scan_config": {
      "remote_kisa_u51": {
        "os_type": "linux",
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
