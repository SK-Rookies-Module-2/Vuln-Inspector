U-31: 홈 디렉토리 소유자 및 권한 설정
• 중요도: 중
• 점검 목적: 사용자 홈 디렉터리의 무단 변조 방지.
• 보안 위협: 타 사용자가 홈 디렉터리에 악성 파일을 생성하거나 설정 파일을 변조할 수 있음.
점검 대상 및 판단 기준
• 양호: 홈 디렉터리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 없는 경우.
• 취약: 소유자가 타인이거나, 타 사용자 쓰기 권한이 있는 경우.
상세 점검 로직 (Scripting Guide)
• 로직:
    1. /etc/passwd에서 홈 디렉터리 경로 추출.
    2. 각 디렉터리에 대해 ls -ld 수행.
    3. Owner가 해당 계정과 일치하는지 확인.
    4. Permission에서 Others의 Write(w) 권한이 없는지 확인.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 디렉터리 권한 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u31/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u31"
name: "Home Directory Permission Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-31"
description: "Check home directory ownership and permissions."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    passwd_path:
      type: string
    ignore_users:
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
class_name: "HomeDirectoryPermissionCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `passwd_path=/etc/passwd`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `ignore_users`로 제외할 계정 설정.  
• group/other 쓰기 허용 여부는 기본 false.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 권한 확인 허용.
3) 홈 디렉터리 수집  
• `/etc/passwd`에서 사용자/홈 경로를 파싱.  
• 홈 경로가 비정상인 항목은 제외.
4) 권한 확인  
• 각 홈 디렉터리에 대해 소유자 및 권한 확인.  
• Owner가 해당 계정과 다르면 취약.  
• group/other 쓰기 권한이 있으면 취약.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-31"`, `severity="Medium"`  
  - `tags=["KISA:U-31"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `checked_dirs`, `missing_dirs`, `policy`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• `/etc/passwd`에서 사용자/홈 필드만 사용.  
• `stat -c '%a %U'`, `stat -f '%Lp %Su'`, `ls -ld` 출력 파싱.

### 테스트 계획
• 유닛:  
  - `/etc/passwd` 파서 및 ignore_users 필터 테스트.  
  - 권한 판정 및 파일 미존재 처리 테스트.  
• 통합(선택): `fixtures/` 샘플 출력 파일로 로컬 폴백 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-31 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u31"],
    "scan_config": {
      "remote_kisa_u31": {
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
