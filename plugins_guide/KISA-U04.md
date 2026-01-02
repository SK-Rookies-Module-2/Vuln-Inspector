U-04: 비밀번호 파일 보호
• 중요도: 상
• 점검 목적: 사용자 계정 비밀번호를 암호화하여 별도 파일(/etc/shadow 등)에 저장하는지 확인.
• 보안 위협: /etc/passwd 파일에 비밀번호가 평문으로 저장될 경우 노출 위험이 매우 높음.
점검 대상 및 판단 기준
• 양호: 쉐도우(Shadow) 비밀번호를 사용하거나 비밀번호를 암호화하여 저장하는 경우.
• 취약: 쉐도우 비밀번호를 사용하지 않고 평문으로 저장하는 경우.
OS별 상세 점검 로직 (Scripting Guide)
1) Solaris, Linux
• 점검:
    ◦ 파일: /etc/passwd
    ◦ 로직: 두 번째 필드가 x로 표시되어 있는지 확인. (예: root:x:0:0...)
    ◦ 확인: /etc/shadow 파일 존재 여부 확인.
2) AIX
• 점검:
    ◦ 파일: /etc/security/passwd
    ◦ 로직: 비밀번호가 해당 파일에 암호화되어 저장되는지 확인.
3) HP-UX
• 점검:
    ◦ 확인: Trusted Mode로 전환되어 /tcb/files/auth 디렉터리가 존재하는지 또는 /etc/shadow 파일이 존재하는지 확인.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u04/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u04"
name: "Password File Protection Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-04"
description: "Check password file protection and shadow usage by OS."
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
    aix_security_passwd_path:
      type: string
    hpux_tcb_dir:
      type: string
    hpux_shadow_path:
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
class_name: "PasswordFileProtectionCheck"
```

### OS별 기본 경로(코드 내 기본값)
• linux/solaris: `passwd_path=/etc/passwd`, `shadow_path=/etc/shadow`  
• aix: `aix_security_passwd_path=/etc/security/passwd`  
• hpux: `hpux_tcb_dir=/tcb/files/auth`, `hpux_shadow_path=/etc/shadow`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. OS별 경로 오버라이드는 있으면 사용, 없으면 기본값 적용.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 읽기 허용.
3) 파일/디렉터리 확인  
• 기본은 SSH로 `cat <path>` 또는 `test -d <dir>` 수행. 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 파싱/판정  
• Linux/Solaris:  
  - `/etc/passwd`의 두 번째 필드가 `x`인지 확인.  
  - `/etc/shadow` 파일 존재 여부 확인.  
  - 둘 중 하나라도 미충족이면 취약.  
• AIX:  
  - `/etc/security/passwd`에서 `root` 스탠자 우선, 없으면 `default` 스탠자의 `password` 값 확인.  
  - `password` 항목이 없거나 비어있으면 취약.  
• HP-UX:  
  - `/tcb/files/auth` 디렉터리 존재 또는 `/etc/shadow` 파일 존재 여부 확인.  
  - 둘 다 없으면 취약.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-04"`, `severity="High"`  
  - `title`에 OS 포함(예: "Linux 비밀번호 파일 보호 미흡")  
  - `tags=["KISA:U-04"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `line`, `mode(remote/local)`, `host`

### 파서 설계(요약)
• 공통: 주석/공백 라인 무시.  
• /etc/passwd 파서: `:` 기준 분리 → 두 번째 필드 확인.  
• AIX 스탠자 파서: `<section>:` 구분 후 `key = value` 형태 파싱.

### 테스트 계획
• 유닛: OS별 파서 입력/출력 테스트(`tests/test_kisa_u04_parsers.py`).  
• 통합(선택): `fixtures/` 샘플 파일을 두고 `allow_local_fallback=true`로 실행 경로 검증.

### 실제 환경 테스트 절차
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-04 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u04"],
    "scan_config": {
      "remote_kisa_u04": {
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
