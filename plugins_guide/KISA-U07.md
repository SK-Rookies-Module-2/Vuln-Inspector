U-07: 불필요한 계정 제거
• 중요도: 하
• 점검 목적: 퇴직, 휴직 등 사용하지 않는 계정을 제거하여 관리되지 않는 계정 악용 방지.
• 보안 위협: 미사용 계정은 공격자의 주요 타겟이 될 수 있음.
점검 대상 및 판단 기준
• 양호: 불필요한 계정이 존재하지 않는 경우.
• 취약: 불필요한 계정(로그인 가능한 미사용 계정)이 존재하는 경우.
상세 점검 로직 (Scripting Guide)
1) 공통
• 파일: /etc/passwd, /etc/shadow
• 로직:
    ◦ 시스템 기본 계정(lp, uucp, nuucp 등) 중 로그인이 가능한 쉘(/bin/bash, /bin/sh)이 할당된 경우 확인.
    ◦ 최근 로그인 기록(last 명령어 등)이 오래된 계정 식별.
    ◦ 로그인이 필요 없는 계정은 쉘이 /bin/false 또는 /sbin/nologin이어야 함.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일/명령 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u07/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u07"
name: "Unused Account Cleanup Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-07"
description: "Detect unnecessary or inactive user accounts."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    passwd_path:
      type: string
    shadow_path:
      type: string
    system_accounts:
      type: array
      default:
        - "lp"
        - "uucp"
        - "nuucp"
        - "daemon"
        - "bin"
        - "sys"
        - "adm"
        - "operator"
        - "mail"
        - "news"
        - "games"
    non_login_shells:
      type: array
      default:
        - "/bin/false"
        - "/sbin/nologin"
        - "/usr/sbin/nologin"
        - "/bin/nologin"
    login_shells:
      type: array
    inactive_days:
      type: integer
      default: 90
    check_system_accounts:
      type: boolean
      default: true
    check_inactive_accounts:
      type: boolean
      default: true
    lastlog_command:
      type: string
      default: "lastlog"
    use_sudo:
      type: boolean
      default: false
    sudo_user:
      type: string
    allow_local_fallback:
      type: boolean
      default: false
entry_point: "main.py"
class_name: "UnusedAccountCleanupCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `passwd_path=/etc/passwd`, `shadow_path=/etc/shadow`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. 경로 오버라이드는 있으면 사용, 없으면 기본값 적용.  
• `system_accounts`, `non_login_shells`, `inactive_days`는 기본값 제공.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 읽기 허용.
3) 파일 읽기  
• 기본은 SSH로 `cat <path>` 수행. 실패 시 `Info`로 "점검 불가" Finding 기록.  
• `/etc/shadow`는 권한이 필요할 수 있어 `use_sudo` 지원.
4) 파싱/정규화  
• `/etc/passwd`에서 계정명/UID/쉘을 파싱.  
• `/etc/shadow`에서 잠금 여부(`!`, `*`, `!!`)를 파악해 로그인 가능 여부 계산.  
• 로그인 가능 조건: 잠금 아님 + 쉘이 `non_login_shells`에 없음.  
• `login_shells`가 지정되면 해당 목록에 포함될 때만 로그인 가능으로 간주.
5) 시스템 계정 점검  
• `check_system_accounts=true`일 때 `system_accounts` 목록 중 로그인 가능한 계정을 취약으로 기록.
6) 미사용 계정 점검  
• `check_inactive_accounts=true`일 때 `lastlog_command` 실행으로 마지막 로그인 시각 확인.  
• `inactive_days`를 초과했거나 "Never logged in"인 로그인 가능 계정을 취약으로 기록.  
• `lastlog` 실행 실패 시 해당 항목은 `Info`로 "점검 불가" 기록.
7) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-07"`, `severity="Low"`  
  - `title`에 OS 포함(예: "Linux 불필요 계정 존재")  
  - `tags=["KISA:U-07"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `line`, `mode(remote/local)`, `host`, `source(system|inactive)`

### 파서 설계(요약)
• `/etc/passwd`: `:` 기준 분리 후 계정명/UID/쉘 추출.  
• `/etc/shadow`: 두 번째 필드가 `!`, `*`, `!!`로 시작하면 잠금으로 판단.  
• `lastlog` 출력: 계정별 마지막 로그인 문자열을 파싱해 날짜를 계산(UTC 기준 비교).  
• `Never logged in` 문자열은 미사용으로 처리.

### 테스트 계획
• 유닛:  
  - passwd/shadow 파서와 로그인 가능 판단 테스트.  
  - lastlog 출력 파서(정상/미로그인/포맷 변형) 테스트.  
• 통합(선택): `fixtures/`에 샘플 passwd/shadow/lastlog 출력 파일을 두고 `allow_local_fallback=true` 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-07 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u07"],
    "scan_config": {
      "remote_kisa_u07": {
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
