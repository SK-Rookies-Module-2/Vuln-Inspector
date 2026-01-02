U-28: 접속 IP 및 포트 제한
• 중요도: 상
• 점검 목적: 허용된 IP에서만 서비스에 접속할 수 있도록 접근 제어 설정(TCP Wrapper, IPFilter 등).
• 보안 위협: 접근 제어가 없을 경우 불법적인 접속 및 침해사고 발생 가능.
점검 대상 및 판단 기준
• 양호: hosts.deny에 ALL:ALL 설정 후 hosts.allow에 필요 IP만 허용했거나, 방화벽(IPtables 등)을 사용 중인 경우.
• 취약: 접속 제한 설정이 없는 경우.
상세 점검 로직 (Scripting Guide)
• TCP Wrapper 점검:
    ◦ 파일: /etc/hosts.deny
    ◦ 내용: ALL:ALL (또는 모든 서비스 거부 설정) 확인.
    ◦ 파일: /etc/hosts.allow
    ◦ 내용: 정상 IP 등록 여부 확인.
• IPtables/FirewallD 점검:
    ◦ 명령어: iptables -L 또는 firewall-cmd --list-all
    ◦ 정책(Policy)이 DROP/REJECT 이거나 특정 규칙이 적용되어 있는지 확인.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일/명령 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u28/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u28"
name: "Access IP/Port Restriction Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-28"
description: "Check TCP Wrapper and firewall access controls."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    hosts_deny_path:
      type: string
      default: "/etc/hosts.deny"
    hosts_allow_path:
      type: string
      default: "/etc/hosts.allow"
    required_deny_patterns:
      type: array
      default:
        - "ALL:ALL"
    require_allow_entries:
      type: boolean
      default: true
    allowed_owners:
      type: array
      default:
        - "root"
    max_mode:
      type: integer
      default: 600
    allow_group_write:
      type: boolean
      default: false
    allow_other_write:
      type: boolean
      default: false
    check_iptables:
      type: boolean
      default: true
    iptables_command:
      type: string
      default: "iptables -L -n"
    check_firewalld:
      type: boolean
      default: true
    firewalld_command:
      type: string
      default: "firewall-cmd --list-all"
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
class_name: "AccessRestrictionCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `hosts_deny_path`, `hosts_allow_path` 기본값 제공.  
• `required_deny_patterns`로 hosts.deny 필수 패턴 정의.  
• `allowed_owners`, `max_mode`, group/other 쓰기 허용 여부로 권한 정책 설정.  
• `check_iptables`/`check_firewalld`로 방화벽 점검 여부 선택.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 확인 허용.
3) TCP Wrapper 점검  
• `hosts.deny`/`hosts.allow`의 소유자/권한(600) 확인.  
• `hosts.deny`에서 `ALL:ALL` 패턴 존재 확인.  
• `hosts.allow`에서 허용 라인 존재 여부 확인(기본 true).
4) 방화벽 점검  
• `iptables -L -n`에서 DROP/REJECT 정책 또는 규칙 존재 확인.  
• `firewall-cmd --list-all`에서 서비스/포트/룰 설정 존재 확인.
5) 판정  
• TCP Wrapper 또는 방화벽 중 하나라도 정상 구성되면 양호.  
• 모두 미구성이면 취약.
6) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-28"`, `severity="High"`  
  - `tags=["KISA:U-28"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `checked_files`, `missing_files`, `policy`, `firewall`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• hosts 파일은 주석(#) 제거 후 라인 단위로 확인.  
• `ALL:ALL`은 공백을 제거한 문자열 기준으로 비교.  
• iptables 출력에서 `policy DROP/REJECT` 또는 `DROP/REJECT` 룰 존재 확인.  
• firewalld 출력에서 `services/ports/rich rules` 등 설정값 존재 확인.

### 테스트 계획
• 유닛:  
  - hosts.deny 패턴 매칭 및 hosts.allow 라인 판정 테스트.  
  - 권한/소유자 판정 및 오류 처리 테스트.  
  - iptables/firewalld 출력 파서 테스트.
• 통합(선택): `fixtures/` 샘플 출력으로 로컬 폴백 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-28 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u28"],
    "scan_config": {
      "remote_kisa_u28": {
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
