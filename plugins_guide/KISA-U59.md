U-59: 안전한 SNMP 버전 사용
• 중요도: 상
• 점검 목적: SNMP 사용 시 평문 전송인 v1, v2 대신 암호화된 v3 사용 권고.
• 보안 위협: v1, v2c는 커뮤니티 스트링(비밀번호)을 평문 전송하므로 스니핑 위험이 있음.
상세 점검 로직 (Scripting Guide)
• 점검: SNMP 설정 파일(/etc/snmp/snmpd.conf) 또는 프로세스 옵션 확인.
• 판단: SNMP v1, v2c를 사용 중이면 취약.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 SNMP 설정/프로세스 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u59/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u59"
name: "SNMP Version Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-59"
description: "Check SNMP v1/v2c usage in snmpd configuration."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    snmp_conf_paths:
      type: array
      default:
        - "/etc/snmp/snmpd.conf"
    community_keywords:
      type: array
      default:
        - "rocommunity"
        - "rwcommunity"
        - "rocommunity6"
        - "rwcommunity6"
        - "com2sec"
        - "com2sec6"
    check_process:
      type: boolean
      default: true
    process_command:
      type: string
      default: "ps -ef"
    process_pattern:
      type: string
      default: "snmpd"
    process_version_pattern:
      type: string
      default: "v1|v2c"
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
class_name: "SnmpVersionCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. 설정 경로/프로세스 옵션 기본값 적용.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 확인 허용.
3) SNMP 설정 파일 점검  
• `snmpd.conf`에서 `rocommunity`, `rwcommunity`, `com2sec` 등 v1/v2c 지시어 확인.  
• `group` 라인에 `v1`/`v2c` 포함 시 취약으로 기록.
4) 프로세스 옵션 점검(선택)  
• `ps -ef` 출력에서 SNMP 데몬 라인을 찾고 `v1|v2c` 옵션이 있으면 취약.  
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-59"`, `severity="High"`  
  - `tags=["KISA:U-59"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `missing_files`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• 주석(#) 제거 후 라인 단위로 검사.  
• 커뮤니티 지시어(community_keywords) 존재 시 v1/v2c 사용으로 판정.  
• `group` 라인에 `v1`/`v2c` 토큰이 있으면 취약.

### 테스트 계획
• 유닛:  
  - community/group 라인 매칭 테스트.  
  - 프로세스 옵션 매칭 테스트.  
  - 파일 미존재/명령 실패 처리 테스트.  
• 통합(선택): 로컬 폴백으로 샘플 snmpd.conf 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-59 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u59"],
    "scan_config": {
      "remote_kisa_u59": {
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
