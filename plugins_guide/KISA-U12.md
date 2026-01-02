U-12: 세션 종료 시간 설정
• 중요도: 하
• 점검 목적: 일정 시간 사용하지 않는 세션을 자동 종료하여, 자리를 비운 사이 발생할 수 있는 비인가자의 접근을 차단함.
• 보안 위협: 세션 타임아웃이 설정되지 않으면 유휴 시간 동안 공격자가 시스템을 제어할 위험이 있음.
점검 대상 및 판단 기준
• 양호: Session Timeout이 600초(10분) 이하로 설정된 경우.
• 취약: 설정되지 않거나 600초를 초과한 경우.
OS별 상세 점검 로직 (Scripting Guide)
1) 공통 (Linux, Solaris, AIX, HP-UX)
• 파일: /etc/profile, /etc/bashrc, ~/.profile (sh, ksh, bash) 또는 /etc/csh.login, /etc/csh.cshrc (csh)
• 점검 로직:
    ◦ TMOUT=600 (또는 그 이하 값) 및 export TMOUT 설정 확인.
    ◦ csh의 경우 set autologout=10 (분 단위) 설정 확인.
    ◦ 설정값이 없거나 600초(10분)를 초과하면 취약.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 프로필 파일 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u12/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u12"
name: "Session Timeout Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-12"
description: "Check session timeout settings (TMOUT/autologout)."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    profile_paths:
      type: array
      default:
        - "/etc/profile"
        - "/etc/bashrc"
        - "/etc/bash.bashrc"
    user_profile_paths:
      type: array
    csh_paths:
      type: array
      default:
        - "/etc/csh.login"
        - "/etc/csh.cshrc"
    max_timeout_seconds:
      type: integer
      default: 600
    require_tmout_export:
      type: boolean
      default: true
    use_sudo:
      type: boolean
      default: false
    sudo_user:
      type: string
    allow_local_fallback:
      type: boolean
      default: false
entry_point: "main.py"
class_name: "SessionTimeoutCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `profile_paths=/etc/profile,/etc/bashrc,/etc/bash.bashrc`, `csh_paths=/etc/csh.login,/etc/csh.cshrc`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `profile_paths`/`csh_paths`/`user_profile_paths`는 배열로 검증.  
• `max_timeout_seconds` 기본 600, `require_tmout_export` 기본 true.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 읽기 허용.
3) 파일 읽기  
• 기본은 SSH로 `cat <path>` 수행.  
• 존재하지 않는 파일은 제외하고, 모든 파일 읽기 실패 시 `Info`로 "점검 불가" 기록.
4) 파싱/판정  
• sh/ksh/bash: `TMOUT=<seconds>` 값 수집.  
  - 값이 없으면 취약.  
  - 값이 600 초과면 취약.  
  - `require_tmout_export=true`인 경우 `export TMOUT` 없으면 취약.  
• csh: `set autologout=<minutes>` 값 수집.  
  - csh 파일이 존재하는데 값이 없으면 취약.  
  - 값이 10분 초과면 취약.  
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-12"`, `severity="Low"`  
  - `title`에 OS 포함(예: "Linux 세션 종료 시간 미설정")  
  - `tags=["KISA:U-12"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `line`, `mode(remote/local)`, `host`, `source(tmout|autologout|mixed)`

### 파서 설계(요약)
• 공백/주석 라인 무시.  
• TMOUT: `TMOUT=600`, `export TMOUT=600`, `TMOUT=600; export TMOUT` 등 지원.  
• autologout: `set autologout=10`, `set autologout 10` 패턴 지원.

### 테스트 계획
• 유닛:  
  - TMOUT 값/export 조합 및 경계값 테스트.  
  - autologout 파서 및 분 단위 변환 테스트.  
• 통합(선택): `fixtures/`에 샘플 프로필 파일을 두고 `allow_local_fallback=true` 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-12 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u12"],
    "scan_config": {
      "remote_kisa_u12": {
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
