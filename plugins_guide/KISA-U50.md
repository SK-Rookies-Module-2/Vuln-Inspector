U-50: DNS Zone Transfer 설정
• 중요도: 상
• 점검 목적: 비인가자에게 DNS Zone 정보(전체 도메인 목록, IP 등) 전송 차단.
• 보안 위협: Zone Transfer가 허용되면 공격자가 네트워크 구조를 파악하여 공격 표면을 넓힐 수 있음.
점검 대상 및 판단 기준
• 양호: Zone Transfer가 허가된 사용자(Secondary DNS)에게만 허용된 경우.
• 취약: 임의의 사용자에게 Zone Transfer가 허용된 경우.
상세 점검 로직 (Scripting Guide)
• 파일: /etc/named.conf 또는 /etc/bind/named.conf.options
• 로직:
    ◦ allow-transfer 구문 확인.
    ◦ { any; } 로 설정되어 있거나 설정이 아예 없으면(기본값 allow) 취약.
    ◦ { none; } 이거나 특정 IP(x.x.x.x)만 명시되어야 함.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 DNS 설정 파일 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u50/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u50"
name: "DNS Zone Transfer Restriction Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-50"
description: "Check DNS allow-transfer settings for zone transfer."
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
    allow_missing_config:
      type: boolean
      default: false
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
class_name: "DnsZoneTransferCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. 설정 파일 경로 목록 기본값 적용.  
• `allow_missing_config=false`이면 대상 파일이 모두 없을 때 점검 불가로 처리.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 확인 허용.
3) 설정 파일 읽기  
• `named_conf_paths` 중 존재하는 파일을 읽어 `allow-transfer` 구문을 찾음.  
• 파일이 없으면 `missing_files`에 기록하고 진행.
4) 판정  
• `allow-transfer`가 `any` 또는 미설정이면 취약.  
• `allow-transfer`가 `none` 또는 특정 IP만 명시된 경우 양호.  
• 최소 1개 파일에서 취약 판정 시 전체 취약으로 기록.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-50"`, `severity="High"`  
  - `tags=["KISA:U-50"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `checked_files`, `missing_files`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• `allow-transfer` 블록 `{ ... }` 내부 토큰을 추출.  
• `any` 포함 또는 구문 누락 시 취약.  
• `none` 또는 IP/ACL만 포함된 경우 양호로 판단.

### 테스트 계획
• 유닛:  
  - allow-transfer 블록 파서 테스트(Any/None/IP/미설정).  
  - 파일 미존재 처리 및 결과 집계 테스트.
• 통합(선택): 로컬 폴백으로 샘플 named.conf 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-50 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u50"],
    "scan_config": {
      "remote_kisa_u50": {
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
