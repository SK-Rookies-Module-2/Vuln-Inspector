U-17: 시스템 시작 스크립트 권한 설정
• 중요도: 상
• 점검 목적: 부팅 시 실행되는 스크립트의 변조 방지.
• 보안 위협: 시작 스크립트에 쓰기 권한이 있으면, 부팅 시 악성 코드가 관리자 권한으로 실행될 수 있음.
점검 대상 및 판단 기준
• 양호: 소유자가 root이고, 일반 사용자에게 쓰기 권한이 없는 경우.
• 취약: root 소유가 아니거나, 일반 사용자에게 쓰기 권한이 있는 경우.
상세 점검 로직 (Scripting Guide)
1) 공통
• 대상 파일: /etc/rc*.d/*, /etc/init.d/* 등.
• 로직:
    ◦ ls -l 명령으로 해당 디렉터리 내 파일 확인.
    ◦ Owner가 root가 아니거나, Others 권한에 w(쓰기)가 있으면 취약.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일 권한 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u17/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u17"
name: "Startup Script Permission Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-17"
description: "Check ownership and permissions of startup scripts."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    script_paths:
      type: array
      default:
        - "/etc/rc.d"
        - "/etc/rc*.d"
        - "/etc/init.d"
    required_owner:
      type: string
      default: "root"
    check_others_writable:
      type: boolean
      default: true
    max_results:
      type: integer
      default: 200
    list_command:
      type: string
      default: "ls -l {path}"
    use_sudo:
      type: boolean
      default: false
    sudo_user:
      type: string
    allow_local_fallback:
      type: boolean
      default: false
entry_point: "main.py"
class_name: "StartupScriptPermissionCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `script_paths`/`list_command` 기본값 제공.  
• `required_owner` 기본값 root, `check_others_writable` 기본 true.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 명령 실행 허용.
3) 스크립트 목록 수집  
• `list_command`를 `script_paths`에 대해 실행(`{path}` 치환).  
• 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 판정  
• `ls -l` 출력에서 권한/소유자 파싱.  
• 소유자가 root가 아니거나, others 권한에 `w`가 있으면 취약.  
• 결과는 `max_results`까지 evidence에 포함.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-17"`, `severity="High"`  
  - `title`에 OS 포함(예: "Linux 시작 스크립트 권한 미흡")  
  - `tags=["KISA:U-17"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode(remote/local)`, `host`, `count`

### 파서 설계(요약)
• `ls -l` 라인에서 권한 문자열(예: `-rwxr-xr-x`)과 소유자 필드 파싱.  
• others 쓰기 여부는 권한 문자열 9번째 위치(`w`)로 판단.

### 테스트 계획
• 유닛:  
  - `ls -l` 파서(권한/소유자/경로) 변형 케이스 테스트.  
  - others writable 판정 테스트.  
• 통합(선택): `fixtures/`에 샘플 `ls -l` 출력 파일로 로컬 폴백 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-17 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u17"],
    "scan_config": {
      "remote_kisa_u17": {
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
