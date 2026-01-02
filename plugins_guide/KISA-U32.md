U-32: 홈 디렉토리로 지정한 디렉토리의 존재 관리
• 중요도: 중
• 점검 목적: 홈 디렉터리가 존재하지 않는 계정의 로그인 시 루트 디렉터리(/)로 진입하는 것을 방지.
• 보안 위협: 홈 디렉터리가 없으면 로그인 시 /로 접속되어 시스템 파일 접근이 용이해질 수 있음.
점검 대상 및 판단 기준
• 양호: 모든 계정의 홈 디렉터리가 실제로 존재하는 경우.
• 취약: 홈 디렉터리가 존재하지 않는 계정이 있는 경우.
상세 점검 로직 (Scripting Guide)
• 로직:
    1. /etc/passwd 파싱.
    2. 명시된 홈 디렉터리 경로가 실제 파일 시스템에 존재하는지 (test -d) 확인.
    3. 단, /dev/null 등을 홈으로 사용하는 시스템 계정은 예외 처리 가능.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 /etc/passwd 및 홈 디렉터리 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u32/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u32"
name: "Home Directory Existence Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-32"
description: "Check that account home directories exist."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    passwd_path:
      type: string
      default: "/etc/passwd"
    ignore_users:
      type: array
      default: []
    ignore_home_paths:
      type: array
      default:
        - "/dev/null"
        - "/nonexistent"
        - "/var/empty"
    ignore_home_prefixes:
      type: array
      default: []
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
class_name: "HomeDirectoryExistenceCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `passwd_path=/etc/passwd`  
• 예외 홈 경로: `/dev/null`, `/nonexistent`, `/var/empty`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `passwd_path`, 예외 홈 경로 기본값 적용.  
• `ignore_users`, `ignore_home_prefixes`로 제외 대상 조정.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 확인 허용.
3) /etc/passwd 파싱  
• 사용자 계정과 홈 디렉터리 추출.  
• 홈 경로가 비어있거나 절대 경로가 아니면 취약 후보로 기록.
4) 홈 디렉터리 존재 확인  
• 각 홈 경로에 `test -d` 실행(SSH 또는 로컬).  
• 존재하지 않으면 취약.  
• 확인 실패는 `partial_errors`에 기록하고 전체 실패 시 `Info`로 보고.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-32"`, `severity="Medium"`  
  - `tags=["KISA:U-32"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `checked_count`

### 파서 설계(요약)
• `/etc/passwd`의 6번째 필드(home)를 사용.  
• 홈 경로가 비어있거나 절대 경로가 아니면 오류로 기록.  
• `test -d` 결과로 홈 디렉터리 존재 여부 판정.

### 테스트 계획
• 유닛:  
  - /etc/passwd 파서(홈 경로 미설정/상대 경로/예외 경로) 테스트.  
  - 홈 디렉터리 존재 여부 매핑 및 결과 제한(max_results) 테스트.  
• 통합(선택): `fixtures/`에 샘플 passwd 파일을 두고 로컬 폴백 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-32 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u32"],
    "scan_config": {
      "remote_kisa_u32": {
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
