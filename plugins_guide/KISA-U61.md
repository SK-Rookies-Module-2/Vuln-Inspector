U-61: SNMP Access Control 설정
• 중요도: 상
• 점검 목적: SNMP 서비스에 접근할 수 있는 IP(Manager)를 제한.
• 보안 위협: 접근 통제가 없으면 임의의 사용자가 SNMP 쿼리를 통해 정보를 수집할 수 있음.
상세 점검 로직 (Scripting Guide)
• 파일: /etc/snmp/snmpd.conf
• 로직:
    ◦ com2sec, rocommunity 등의 설정에 특정 IP/Network 제한이 있는지 확인.
    ◦ default 또는 0.0.0.0 허용 시 취약.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일 내용 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u61/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u61"
name: "SNMP Access Control Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-61"
description: "Check SNMP access control restrictions in snmpd.conf."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    snmpd_conf_path:
      type: string
      default: "/etc/snmp/snmpd.conf"
    directives:
      type: array
      default:
        - "com2sec"
        - "com2sec6"
        - "rocommunity"
        - "rwcommunity"
        - "rocommunity6"
        - "rwcommunity6"
    insecure_sources:
      type: array
      default:
        - "default"
        - "0.0.0.0"
        - "0.0.0.0/0"
        - "::"
        - "::/0"
        - "any"
    require_source:
      type: boolean
      default: true
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
class_name: "SnmpAccessControlCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `snmpd_conf_path` 기본값 제공.  
• `directives`에 대상 지시자(com2sec/rocommunity 등) 목록 정의.  
• `insecure_sources`에 default/0.0.0.0 등의 취약 소스 정의.  
• `require_source=true`이면 소스가 없는 설정도 취약 처리.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 확인 허용.
3) 파일 확인  
• `snmpd.conf`를 읽고 주석(#) 제거 후 지시자 라인을 파싱.  
• com2sec는 3번째 토큰(source), rocommunity는 3번째 토큰(source) 확인.
4) 판정  
• source가 없거나, `insecure_sources`에 해당하면 취약.  
• 모든 설정이 제한된 소스인 경우 양호.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-61"`, `severity="High"`  
  - `tags=["KISA:U-61"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `policy`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• 주석(#) 제거 후 공백 분리 파싱.  
• com2sec/com2sec6는 source 필드, rocommunity/rwcommunity는 source 필드 확인.  
• default/0.0.0.0/0 등의 소스는 취약 처리.

### 테스트 계획
• 유닛:  
  - source 누락/취약 소스 판정 테스트.  
  - 지시자별 source 파싱 테스트.  
  - 파일 미존재/오류 처리 테스트.
• 통합(선택): `fixtures/` 샘플 설정 파일로 로컬 폴백 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-61 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u61"],
    "scan_config": {
      "remote_kisa_u61": {
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
