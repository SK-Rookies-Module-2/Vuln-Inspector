U-14: root 홈, 패스 디렉터리 권한 및 패스 설정
• 중요도: 상
• 점검 목적: PATH 환경변수에 현재 디렉터리(. )가 포함되지 않도록 하여, 의도치 않은 악성 프로그램 실행 방지.
• 보안 위협: PATH의 맨 앞이나 중간에 .이 포함되면, 공격자가 관리자 명령어로 위장한 악성 파일을 현재 디렉터리에 두어 실행을 유도할 수 있음.
점검 대상 및 판단 기준
• 양호: PATH 환경변수에 . 이 맨 앞이나 중간에 포함되지 않은 경우.
• 취약: . 이 맨 앞이나 중간에 포함된 경우.
상세 점검 로직 (Scripting Guide)
1) 공통
• 점검 대상: root 계정의 환경변수 및 /etc/profile.
• 명령어: echo $PATH
• 로직:
    ◦ 출력된 PATH 문자열 분석.
    ◦ :: (빈 값은 . 을 의미), ^.: (맨 앞의 .), /:. (중간의 .) 패턴이 존재하면 취약.
    ◦ 맨 마지막에 있는 . 은 양호로 간주하는 경우가 많으나, 원칙적으로는 제거 권고.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 환경변수/프로필 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u14/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u14"
name: "Root PATH Safety Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-14"
description: "Detect unsafe PATH entries containing current directory."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    path_command:
      type: string
      default: "sh -lc 'echo $PATH'"
    profile_paths:
      type: array
      default:
        - "/etc/profile"
    check_runtime_path:
      type: boolean
      default: true
    check_profile_paths:
      type: boolean
      default: true
    allow_trailing_dot:
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
class_name: "RootPathSafetyCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `profile_paths=/etc/profile`, `path_command=sh -lc 'echo $PATH'`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `path_command`/`profile_paths`는 기본값 제공.  
• `check_runtime_path`/`check_profile_paths`로 점검 범위 선택.  
• `allow_trailing_dot=true`이면 PATH의 맨 마지막 `.`은 허용.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 명령/파일 읽기 허용.
3) PATH 수집  
• 런타임 PATH: `path_command` 실행 결과 첫 줄 사용.  
• 프로필 PATH: `/etc/profile`에서 `PATH=...` 또는 `export PATH=...` 라인 파싱.  
• 모든 수집 실패 시 `Info`로 "점검 불가" 기록.
4) 판정  
• PATH 항목을 `:`로 분리하여 `.` 또는 빈 항목(= `.`) 탐지.  
• `.`이 맨 앞/중간에 있으면 취약.  
• `.`이 맨 끝에만 있으면 `allow_trailing_dot=true`일 때 양호로 처리.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-14"`, `severity="High"`  
  - `title`에 OS 포함(예: "Linux PATH 안전 설정 미흡")  
  - `tags=["KISA:U-14"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `line`, `mode(remote/local)`, `host`, `source(runtime|profile|mixed)`

### 파서 설계(요약)
• 공백/주석 라인 무시.  
• `PATH=...`, `export PATH=...`, `PATH=...; export PATH` 형태 지원.  
• PATH 항목 분리는 `:` 기준(빈 항목은 `.`로 간주).

### 테스트 계획
• 유닛:  
  - PATH 분리/`.` 위치 판정 테스트(앞/중간/끝).  
  - 프로필 PATH 라인 파서 테스트.  
• 통합(선택): `fixtures/`에 샘플 `/etc/profile`을 두고 `allow_local_fallback=true` 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-14 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u14"],
    "scan_config": {
      "remote_kisa_u14": {
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
