U-24: 사용자, 시스템 환경변수 파일 소유자 및 권한 설정
• 중요도: 상
• 점검 목적: 환경변수 파일의 변조를 통해 로그인 시 악성 명령어가 자동 실행되는 것을 방지.
• 보안 위협: 타 사용자가 환경 설정 파일을 변조하여 서비스 거부나 권한 탈취 시도 가능.
점검 대상 및 판단 기준
• 양호: 홈 디렉터리 내 환경변수 파일 소유자가 root 또는 해당 계정이고, 쓰기 권한이 타인에게 없는 경우.
• 취약: 소유자가 적절하지 않거나, 타 사용자의 쓰기 권한이 있는 경우.
상세 점검 로직 (Scripting Guide)
• 대상 파일 패턴: .profile, .bashrc, .cshrc, .kshrc, .bash_profile, .login 등.
• 로직:
    1. /etc/passwd를 파싱하여 각 사용자의 홈 디렉터리 경로 확보.
    2. 각 홈 디렉터리 내의 위 대상 파일 존재 확인.
    3. ls -l 권한 확인:
        ▪ Owner: root 또는 해당 계정이어야 함.
        ▪ Permission: Group 및 Others에 Write(w) 권한이 없어야 함.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일 권한 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u24/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u24"
name: "User Env File Permission Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-24"
description: "Check user environment file ownership and permissions."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    passwd_path:
      type: string
    env_file_names:
      type: array
      default:
        - ".profile"
        - ".bashrc"
        - ".cshrc"
        - ".kshrc"
        - ".bash_profile"
        - ".login"
    ignore_users:
      type: array
      default: []
    allow_root_owner:
      type: boolean
      default: true
    allow_user_owner:
      type: boolean
      default: true
    extra_allowed_owners:
      type: array
      default: []
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
class_name: "UserEnvFilePermissionCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `passwd_path=/etc/passwd`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `env_file_names` 기본값 제공.  
• `allow_root_owner/allow_user_owner/extra_allowed_owners`로 소유자 허용 정책 설정.  
• `allow_group_write/allow_other_write` 기본 false.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 권한 확인 허용.
3) 사용자 홈 수집  
• `/etc/passwd`를 읽어 사용자명과 홈 디렉터리 확보.  
• `ignore_users`에 포함된 계정과 홈 경로가 비정상인 항목은 제외.
4) 파일 권한 확인  
• 각 홈 디렉터리에서 `env_file_names` 대상 파일을 확인하고 존재 시 권한 확인.  
• 원격은 `stat`/`ls -ld`, 로컬은 `os.stat`으로 소유자/권한 확인.
5) 판정  
• 소유자가 `root` 또는 해당 계정(또는 `extra_allowed_owners`)이 아니면 취약.  
• Group/Other에 쓰기 권한이 있으면 취약(`allow_*` 옵션이 true면 예외).
6) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-24"`, `severity="High"`  
  - `tags=["KISA:U-24"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `checked_files`, `missing_files`, `policy`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• `/etc/passwd`에서 1/6 필드(사용자/홈 디렉터리) 사용.  
• `stat -c '%a %U'`, `stat -f '%Lp %Su'`, `ls -ld` 출력에서 권한/소유자 파싱.

### 테스트 계획
• 유닛:  
  - `/etc/passwd` 파서 및 ignore_users 필터 테스트.  
  - stat/ls 출력 파서 및 owner/permission 판정 테스트.  
  - 파일 미존재/부분 오류 처리 및 결과 제한(max_results) 테스트.
• 통합(선택): `fixtures/` 샘플 출력으로 원격/로컬 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-24 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u24"],
    "scan_config": {
      "remote_kisa_u24": {
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
