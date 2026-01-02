U-11: 사용자 shell 점검
• 중요도: 하
• 점검 목적: 로그인이 필요 없는 시스템 계정(daemon, bin, sys 등)에 쉘(/bin/false, /sbin/nologin)을 부여하여 로그인을 차단함.
• 보안 위협: 불필요한 계정에 로그인이 가능한 쉘이 부여되면 공격자가 이를 통해 시스템에 접근하거나 명령어를 실행할 수 있음.
점검 대상 및 판단 기준
• 대상: SOLARIS, LINUX, AIX, HP-UX
• 양호: 로그인이 필요 없는 계정에 /bin/false 또는 /sbin/nologin 쉘이 부여된 경우.
• 취약: 로그인이 필요 없는 계정에 /bin/sh, /bin/bash 등의 쉘이 부여된 경우.
OS별 상세 점검 로직 (Scripting Guide)
1) 공통 (Linux, AIX, HP-UX, Solaris)
• 파일: /etc/passwd
• 점검 로직:
    1. passwd 파일에서 시스템 기본 계정(daemon, bin, sys, adm, listen, nobody, nobody4, noaccess, diag, operator, games, gopher 등) 리스트를 정의.
    2. 해당 계정들의 쉘 설정 필드(마지막 필드) 확인.
    3. 쉘이 /bin/false 또는 /sbin/nologin이 아니면 취약.
    ◦ 주의: 로그인이 필요한 업무용 계정은 제외해야 함.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 /etc/passwd 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u11/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u11"
name: "System Account Shell Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-11"
description: "Ensure non-login system accounts use nologin shells."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    passwd_path:
      type: string
    system_accounts:
      type: array
      default:
        - "daemon"
        - "bin"
        - "sys"
        - "adm"
        - "listen"
        - "nobody"
        - "nobody4"
        - "noaccess"
        - "diag"
        - "operator"
        - "games"
        - "gopher"
    non_login_shells:
      type: array
      default:
        - "/bin/false"
        - "/sbin/nologin"
        - "/usr/sbin/nologin"
        - "/bin/nologin"
    exclude_accounts:
      type: array
    use_sudo:
      type: boolean
      default: false
    sudo_user:
      type: string
    allow_local_fallback:
      type: boolean
      default: false
entry_point: "main.py"
class_name: "SystemAccountShellCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `passwd_path=/etc/passwd`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `passwd_path` 오버라이드는 있으면 사용, 없으면 기본값 적용.  
• `system_accounts`/`non_login_shells`/`exclude_accounts`는 배열로 검증.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 읽기 허용.
3) 파일 읽기  
• 기본은 SSH로 `cat <path>` 수행. 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 파싱/판정  
• `/etc/passwd`에서 계정명과 쉘(마지막 필드)을 파싱.  
• `system_accounts`에 포함되고 `exclude_accounts`에 없는 계정만 대상.  
• 쉘이 `non_login_shells`에 없으면 취약.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-11"`, `severity="Low"`  
  - `title`에 OS 포함(예: "Linux 시스템 계정 쉘 설정 미흡")  
  - `tags=["KISA:U-11"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `line`, `mode(remote/local)`, `host`, `account`

### 파서 설계(요약)
• 공백/주석 라인 무시.  
• `:` 기준 분리 후 `len(fields) >= 7`만 처리.  
• 쉘 필드는 마지막 필드 사용.

### 테스트 계획
• 유닛:  
  - 시스템 계정/제외 계정 필터 및 쉘 판정 테스트.  
  - 필드 누락/쉘 누락 케이스.  
• 통합(선택): `fixtures/`에 샘플 `/etc/passwd`를 두고 `allow_local_fallback=true` 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-11 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u11"],
    "scan_config": {
      "remote_kisa_u11": {
        "os_type": "linux",
        "use_sudo": false
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
