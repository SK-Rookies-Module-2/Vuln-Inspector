U-27: $HOME/.rhosts, hosts.equiv 사용 금지
• 중요도: 상
• 점검 목적: r-command 사용 시 인증 없이 접속 가능한 신뢰 호스트 설정을 제거.
• 보안 위협: + 설정이 있을 경우 모든 호스트에서 비밀번호 없이 접속 가능하여 매우 위험함.
점검 대상 및 판단 기준
• 양호: 해당 파일이 없거나, 파일 내에 + 설정이 없는 경우 (소유자 root/해당계정, 권한 600).
• 취약: 파일에 + 설정이 있거나 권한이 취약한 경우.
상세 점검 로직 (Scripting Guide)
• 대상 파일: /etc/hosts.equiv, 사용자 홈 디렉터리의 .rhosts
• 로직:
    1. 파일 존재 여부 확인.
    2. 파일 소유자(root/해당계정) 및 권한(600) 확인.
    3. 내용 점검: 파일 내에 + (단독 사용) 문자가 있는지 grep으로 확인.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일 권한/내용 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u27/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u27"
name: "Rhosts/hosts.equiv Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-27"
description: "Check rhosts and hosts.equiv usage and permissions."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    passwd_path:
      type: string
    hosts_equiv_path:
      type: string
      default: "/etc/hosts.equiv"
    rhosts_name:
      type: string
      default: ".rhosts"
    ignore_users:
      type: array
      default: []
    allowed_hosts_equiv_owners:
      type: array
      default:
        - "root"
    allow_root_owner:
      type: boolean
      default: true
    allow_user_owner:
      type: boolean
      default: true
    extra_allowed_owners:
      type: array
      default: []
    max_mode:
      type: integer
      default: 600
    allow_group_write:
      type: boolean
      default: false
    allow_other_write:
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
class_name: "RhostsHostsEquivCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `passwd_path=/etc/passwd`, `hosts_equiv_path=/etc/hosts.equiv`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `hosts_equiv_path`, `rhosts_name` 기본값 제공.  
• `allowed_hosts_equiv_owners`, `allow_root_owner/allow_user_owner`로 소유자 허용 정책 설정.  
• `max_mode` 기본 600, group/other 쓰기 허용 여부는 기본 false.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 확인 허용.
3) 파일 수집  
• `/etc/hosts.equiv` 존재 시 권한/내용 확인.  
• `/etc/passwd`에서 사용자 홈을 파싱하고 `~/.rhosts` 경로 확인.
4) 판정  
• 소유자가 root 또는 해당 계정이 아니면 취약.  
• 권한이 600 초과이거나 group/other 쓰기 권한이 있으면 취약.  
• 파일 내용에서 `+` 단독 사용(첫 토큰이 `+`)이 있으면 취약.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-27"`, `severity="High"`  
  - `tags=["KISA:U-27"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `checked_files`, `missing_files`, `policy`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• `/etc/passwd`에서 사용자/홈 필드만 사용.  
• `stat -c '%a %U'`, `stat -f '%Lp %Su'`, `ls -ld` 출력에서 권한/소유자 파싱.  
• 각 파일 내용은 주석(`#`) 제거 후 첫 토큰이 `+`인지 확인.

### 테스트 계획
• 유닛:  
  - `/etc/passwd` 파서 및 ignore_users 필터 테스트.  
  - `+` 라인 감지 및 권한 판정 테스트.  
  - 파일 미존재/부분 오류 처리 및 결과 제한(max_results) 테스트.
• 통합(선택): `fixtures/` 샘플 파일로 로컬 폴백 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-27 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u27"],
    "scan_config": {
      "remote_kisa_u27": {
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
