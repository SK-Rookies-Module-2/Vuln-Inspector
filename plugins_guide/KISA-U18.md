U-18: /etc/shadow 파일 소유자 및 권한 설정
• 중요도: 상
• 점검 목적: 패스워드 해시 파일의 유출 방지.
• 보안 위협: 해시 파일이 유출되면 오프라인 크래킹 공격(John the Ripper 등)에 노출됨.
점검 대상 및 판단 기준
• 양호: 소유자가 root이고, 권한이 400(또는 000) 이하인 경우.
• 취약: 권한이 400을 초과하거나 소유자가 root가 아닌 경우.
상세 점검 로직 (Scripting Guide)
1) Linux, Solaris
• 파일: /etc/shadow
• 로직: Owner: root, Perm: 400 (-r--------) 또는 000 확인.
2) AIX
• 파일: /etc/security/passwd
• 로직: Owner: root, Perm: 400 확인.
3) HP-UX
• 파일: /tcb/files/auth (Trusted Mode), /etc/shadow
• 로직: Owner: root, Perm: 400 확인.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일 권한 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u18/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u18"
name: "Shadow File Permission Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-18"
description: "Check shadow/password hash file ownership and permissions."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    shadow_path:
      type: string
    aix_security_passwd_path:
      type: string
    hpux_tcb_dir:
      type: string
    hpux_shadow_path:
      type: string
    required_owner:
      type: string
      default: "root"
    max_mode:
      type: integer
      default: 400
    use_sudo:
      type: boolean
      default: false
    sudo_user:
      type: string
    allow_local_fallback:
      type: boolean
      default: false
entry_point: "main.py"
class_name: "ShadowFilePermissionCheck"
```

### OS별 기본 경로(코드 내 기본값)
• linux/solaris: `shadow_path=/etc/shadow`  
• aix: `aix_security_passwd_path=/etc/security/passwd`  
• hpux: `hpux_tcb_dir=/tcb/files/auth`, `hpux_shadow_path=/etc/shadow`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. OS별 경로 오버라이드는 있으면 사용, 없으면 기본값 적용.  
• `required_owner` 기본값 root, `max_mode` 기본값 400.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 권한 확인 허용.
3) 권한 확인  
• 기본은 SSH로 `stat` 또는 `ls -ld` 실행.  
• HP-UX는 Trusted Mode 디렉터리(`/tcb/files/auth`) 존재 여부에 따라 점검 대상 선택.  
• 파싱 실패/명령 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 판정  
• 소유자 불일치 또는 권한이 `max_mode`보다 크면 취약.  
• 권한 비교는 8진수 기준(예: 0400).
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-18"`, `severity="High"`  
  - `title`에 OS 포함(예: "Linux /etc/shadow 권한 설정 미흡")  
  - `tags=["KISA:U-18"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode(remote/local)`, `host`, `owner`, `permission`

### 파서 설계(요약)
• `stat -c '%a %U'` 또는 `stat -f '%Lp %Su'` 출력 파싱.  
• 실패 시 `ls -ld` 출력에서 권한/소유자 파싱.

### 테스트 계획
• 유닛:  
  - stat/ls 출력 파서 변형 케이스 테스트.  
  - 권한 비교 경계값(400/000/640) 테스트.  
• 통합(선택): `fixtures/`에 샘플 `ls -ld` 출력 파일로 로컬 폴백 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-18 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u18"],
    "scan_config": {
      "remote_kisa_u18": {
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
