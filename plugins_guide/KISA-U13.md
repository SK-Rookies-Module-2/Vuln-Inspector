U-13: 안전한 비밀번호 암호화 알고리즘 사용
• 중요도: 중
• 점검 목적: 패스워드 저장 시 취약한 해시 알고리즘(MD5 등) 대신 안전한 알고리즘(SHA-256 이상) 사용 여부 확인.
• 보안 위협: 취약한 알고리즘 사용 시 해시값이 유출되었을 때 복호화(Cracking)될 가능성이 높음.
점검 대상 및 판단 기준
• 양호: SHA-256 이상의 암호화 알고리즘을 사용하는 경우 (예: $5, $6 등).
• 취약: MD5(1),Blowfish(2a) 등 취약하거나 낮은 수준의 암호화를 사용하는 경우.
OS별 상세 점검 로직 (Scripting Guide)
1) Linux
• 파일: /etc/login.defs (Redhat 계열), /etc/pam.d/common-password (Debian 계열)
• 점검 로직:
    ◦ /etc/login.defs 내 ENCRYPT_METHOD 값이 SHA512인지 확인.
    ◦ 또는 PAM 설정에 sha512 옵션이 적용되어 있는지 확인.
2) Solaris
• 파일: /etc/security/policy.conf
• 점검 로직: CRYPT_DEFAULT=6 (SHA-512) 또는 5 (SHA-256) 설정 확인.
3) AIX
• 파일: /etc/security/login.cfg
• 점검 로직: pwd_algorithm 값이 ssha256 또는 ssha512 인지 확인.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 설정 파일 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u13/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u13"
name: "Password Hash Algorithm Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-13"
description: "Check password hash algorithm settings by OS."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    login_defs_path:
      type: string
    pam_password_path_debian:
      type: string
    pam_password_path_redhat:
      type: string
    policy_conf_path:
      type: string
    aix_login_cfg_path:
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
class_name: "PasswordHashAlgorithmCheck"
```

### OS별 기본 경로(코드 내 기본값)
• linux: `login_defs_path=/etc/login.defs`, `pam_password_path_debian=/etc/pam.d/common-password`, `pam_password_path_redhat=/etc/pam.d/system-auth`  
• solaris: `policy_conf_path=/etc/security/policy.conf`  
• aix: `aix_login_cfg_path=/etc/security/login.cfg`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. OS별 경로 오버라이드는 있으면 사용, 없으면 기본값 적용.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 읽기 허용.
3) 파일 읽기  
• 기본은 SSH로 `cat <path>` 수행. 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 파싱/판정  
• Linux:  
  - `/etc/login.defs`의 `ENCRYPT_METHOD` 값이 `SHA512` 또는 `SHA256`이면 양호.  
  - PAM 설정에서 `sha512` 또는 `sha256` 옵션이 있으면 양호.  
  - 위 둘 중 하나라도 충족하지 않으면 취약.  
• Solaris:  
  - `/etc/security/policy.conf`의 `CRYPT_DEFAULT` 값이 `6` 또는 `5`면 양호.  
  - 그 외/미설정이면 취약.  
• AIX:  
  - `/etc/security/login.cfg`의 `pwd_algorithm` 값이 `ssha512` 또는 `ssha256`면 양호.  
  - 그 외/미설정이면 취약.  
• HP-UX: 해당 가이드에 명시된 기준이 없어 `Info`로 "점검 불가" 처리.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-13"`, `severity="Medium"`  
  - `title`에 OS 포함(예: "Linux 안전한 비밀번호 암호화 미설정")  
  - `tags=["KISA:U-13"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `line`, `mode(remote/local)`, `host`, `source`

### 파서 설계(요약)
• 공백/주석 라인 무시.  
• `KEY=VALUE` 또는 `KEY VALUE` 형식 파싱.  
• PAM: `pam_unix.so` 라인에서 `sha512`/`sha256` 옵션 포함 여부 확인.

### 테스트 계획
• 유닛:  
  - Linux login.defs/PAM 파서 및 판정 조합 테스트.  
  - Solaris CRYPT_DEFAULT 파서 테스트.  
  - AIX pwd_algorithm 파서 테스트.  
• 통합(선택): `fixtures/`에 샘플 설정 파일을 두고 `allow_local_fallback=true` 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-13 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u13"],
    "scan_config": {
      "remote_kisa_u13": {
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
