U-03: 계정 잠금 임계값 설정
• 중요도: 상
• 점검 목적: 무차별 대입 공격 시 계정을 잠가 접속 시도를 무력화함.
• 보안 위협: 임계값 미설정 시 지속적인 비밀번호 대입 공격에 노출됨.
점검 대상 및 판단 기준
• 양호: 계정 잠금 임계값이 10회 이하로 설정된 경우.
• 취약: 계정 잠금 임계값이 설정되지 않거나 10회를 초과한 경우.
OS별 상세 점검 로직 (Scripting Guide)
1) Linux
• 점검:
    ◦ 파일: /etc/pam.d/system-auth (Redhat) 또는 /etc/pam.d/common-auth (Debian)
    ◦ 모듈: pam_tally.so, pam_tally2.so, 또는 pam_faillock.so
    ◦ 로직: deny=10 (또는 그 이하), unlock_time 설정 여부 확인.
2) Solaris
• 5.9 이상:
    ◦ 파일: /etc/security/policy.conf
    ◦ 로직: LOCK_AFTER_RETRIES=YES 확인.
    ◦ 파일: /etc/default/login 내 RETRIES=10 이하 확인.
3) AIX
• 점검:
    ◦ 파일: /etc/security/user
    ◦ 로직: loginretries = 3 (10회 이하) 설정 확인.
4) HP-UX
• 점검:
    ◦ 파일: /tcb/files/auth/system/default (Trusted Mode) 또는 /etc/default/security (11.v3 이상)
    ◦ 로직: u_maxtries 또는 AUTH_MAXTRIES 값이 10 이하인지 확인

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u03/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u03"
name: "Account Lockout Threshold Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-03"
description: "Check account lockout threshold across OS policies."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    pam_auth_path_redhat:
      type: string
    pam_auth_path_debian:
      type: string
    policy_conf_path:
      type: string
    login_path:
      type: string
    aix_user_path:
      type: string
    hpux_trusted_path:
      type: string
    hpux_default_security_path:
      type: string
    use_sudo:
      type: boolean
      default: false
    sudo_user:
      type: string
    allow_local_fallback:
      type: boolean
      default: false
entry_point: "main.py"
class_name: "AccountLockoutThresholdCheck"
```

### OS별 기본 경로(코드 내 기본값)
• linux: `pam_auth_path_redhat=/etc/pam.d/system-auth`, `pam_auth_path_debian=/etc/pam.d/common-auth`  
• solaris: `policy_conf_path=/etc/security/policy.conf`, `login_path=/etc/default/login`  
• aix: `aix_user_path=/etc/security/user`  
• hpux: `hpux_trusted_path=/tcb/files/auth/system/default`, `hpux_default_security_path=/etc/default/security`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. OS별 경로 오버라이드는 있으면 사용, 없으면 기본값 적용.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 읽기 허용.
3) 파일 읽기  
• 기본은 SSH로 `cat <path>` 수행. 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 파싱/판정  
• Linux: pam_tally.so/pam_tally2.so/pam_faillock.so 라인에서 `deny` 값 추출.  
  - `deny`가 없거나 10 초과면 취약.  
  - `unlock_time` 값이 없으면 취약(값 존재만 확인).  
  - 모듈 라인이 전혀 없으면 취약으로 처리.  
• Solaris:  
  - `/etc/security/policy.conf`의 `LOCK_AFTER_RETRIES=YES` 여부 확인.  
  - `/etc/default/login`의 `RETRIES` 값이 10 이하인지 확인.  
  - 둘 중 하나라도 미충족이면 취약.  
• AIX: `/etc/security/user`의 `loginretries`가 10 이하인지 확인.  
  - `root` 스탠자를 우선, 없으면 `default` 사용.  
• HP-UX:  
  - Trusted Mode 파일(`/tcb/files/auth/system/default`)에서 `u_maxtries` 확인.  
  - 해당 파일이 없으면 `/etc/default/security`의 `AUTH_MAXTRIES` 확인.  
  - 값이 없거나 10 초과면 취약.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-03"`, `severity="High"`  
  - `title`에 OS 포함(예: "Linux 계정 잠금 임계값 미설정")  
  - `tags=["KISA:U-03"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `line`, `mode(remote/local)`, `host`

### 파서 설계(요약)
• 공통: 주석/공백 라인 무시.  
• PAM 라인 파서: 모듈명 포함 여부로 라인 필터 → `deny=`/`unlock_time=` 파라미터 파싱.  
• AIX 스탠자 파서: `<section>:` 구분 후 `key = value` 형태 파싱.  
• Solaris: `KEY=VALUE` 형태만 파싱(대소문자 무시).

### 테스트 계획
• 유닛: OS별 파서 입력/출력 테스트(`tests/test_kisa_u03_parsers.py`).  
• 통합(선택): `fixtures/`에 샘플 설정 파일을 두고 `allow_local_fallback=true`로 실행 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-03 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u03"],
    "scan_config": {
      "remote_kisa_u03": {
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
