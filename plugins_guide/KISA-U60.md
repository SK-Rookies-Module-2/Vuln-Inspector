U-60: SNMP Community String 복잡성 설정
• 중요도: 중
• 점검 목적: SNMP v1/v2c 사용 시 기본 커뮤니티 스트링(public, private) 사용 금지 및 복잡성 요구.
• 보안 위협: 기본값 사용 시 공격자가 손쉽게 시스템 정보를 획득하거나 설정을 변경할 수 있음.
상세 점검 로직 (Scripting Guide)
• 파일: /etc/snmp/snmpd.conf
• 로직:
    ◦ rocommunity, rwcommunity 설정값 확인.
    ◦ public, private 문자열이 포함되어 있으면 취약.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일 내용 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u60/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u60"
name: "SNMP Community String Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-60"
description: "Check SNMP community strings for default values."
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
    insecure_tokens:
      type: array
      default:
        - "public"
        - "private"
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
class_name: "SnmpCommunityCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `snmpd_conf_path=/etc/snmp/snmpd.conf`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `snmpd_conf_path` 기본값 제공.  
• `insecure_tokens` 기본값(public/private) 적용.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 확인 허용.
3) 파일 내용 점검  
• `rocommunity`/`rwcommunity` 라인에서 커뮤니티 스트링 추출.  
• 커뮤니티 스트링에 `public` 또는 `private` 포함 시 취약.  
• 파일 미존재면 SNMP 미사용으로 판단하여 양호 처리(결과 없음).  
• 읽기 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-60"`, `severity="Medium"`  
  - `tags=["KISA:U-60"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `partial_errors`

### 파서 설계(요약)
• `rocommunity`/`rwcommunity` 라인에서 두 번째 토큰을 커뮤니티 값으로 사용.  
• 토큰 비교는 소문자 기준, 포함 여부로 판정.

### 테스트 계획
• 유닛:  
  - snmpd.conf 라인 파서 및 커뮤니티 문자열 판정 테스트.  
  - 파일 미존재 처리 및 오류 처리 테스트.
• 통합(선택): `fixtures/` 샘플 snmpd.conf로 로컬 폴백 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-60 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u60"],
    "scan_config": {
      "remote_kisa_u60": {
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
