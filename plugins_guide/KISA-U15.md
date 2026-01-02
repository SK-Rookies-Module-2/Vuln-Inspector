U-15: 파일 및 디렉터리 소유자 설정
• 중요도: 상
• 점검 목적: 소유자가 존재하지 않는 파일(nouser, nogroup)을 탐색하여 삭제 또는 관리.
• 보안 위협: 소유자가 없는 파일은 새로운 사용자가 해당 UID/GID를 할당받을 경우 소유권을 획득하게 되어 정보 유출 및 변조 위험이 있음.
점검 대상 및 판단 기준
• 양호: 소유자가 존재하지 않는 파일 및 디렉터리가 없는 경우.
• 취약: 소유자가 존재하지 않는 파일 및 디렉터리가 발견된 경우.
상세 점검 로직 (Scripting Guide)
1) 공통
• 명령어: find / -nouser -o -nogroup -xdev -ls
• 로직:
    ◦ 명령어 실행 결과에 파일이 출력되면 취약.
    ◦ 단, /proc, /sys 등 가상 파일 시스템은 제외.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 명령 실행)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u15/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u15"
name: "Orphan File Ownership Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-15"
description: "Find files/directories without owners (nouser/nogroup)."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    find_command:
      type: string
      default: "find {path} -xdev {prune} \\( -nouser -o -nogroup \\) -ls"
    search_paths:
      type: array
      default:
        - "/etc"
        - "/var"
        - "/home"
        - "/opt"
        - "/root"
    exclude_paths:
      type: array
      default:
        - "/proc"
        - "/sys"
        - "/dev"
        - "/run"
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
class_name: "OrphanFileOwnershipCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `find_command`/`search_paths`/`exclude_paths`/`max_results` 기본값 제공.  
• `find_command`는 `{path}`/`{prune}` 치환을 지원.  
• `search_paths` 경로별로 `find`를 분할 실행(타임아웃 완화).  
• `exclude_paths`는 `{prune}`에 `-path <path> -prune -o` 형태로 삽입.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 명령 실행 허용.
3) 명령 실행  
• `search_paths` 각각에 대해 `find` 명령을 분할 실행.  
• 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 판정  
• 출력 라인이 1개 이상이면 취약.  
• `max_results`만큼만 evidence에 포함(나머지는 summary로 count만 기록).
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-15"`, `severity="High"`  
  - `title`에 OS 포함(예: "Linux 소유자 없는 파일 존재")  
  - `tags=["KISA:U-15"]`  
  - `evidence`: `os_type`, `config_path(command)`, `detected_value`, `mode(remote/local)`, `host`, `count`

### 파서 설계(요약)
• `find -ls` 출력 라인을 그대로 보관하고, 경로 추출은 선택 사항.  
• 빈 줄은 제거.

### 테스트 계획
• 유닛:  
  - exclude_paths 적용 시 명령 문자열 조합 테스트.  
  - 출력 라인 제한(max_results) 동작 테스트.  
• 통합(선택): `fixtures/`에 샘플 find 출력 파일을 두고 로컬 폴백 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-15 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u15"],
    "scan_config": {
      "remote_kisa_u15": {
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
