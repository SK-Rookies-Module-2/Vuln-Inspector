U-25: world writable 파일 점검
• 중요도: 상
• 점검 목적: 모든 사용자(Everyone)가 수정 가능한 파일을 식별하여 무단 변조 방지.
• 보안 위협: 시스템 중요 파일이 World Writable일 경우 악의적인 변조나 삭제가 가능함.
점검 대상 및 판단 기준
• 양호: World Writable 파일이 존재하지 않거나, 의도된 파일인 경우.
• 취약: 불필요한 World Writable 파일이 존재하는 경우.
상세 점검 로직 (Scripting Guide)
• 명령어: find / -type f -perm -2 -xdev -ls
• 로직:
    1. 시스템 전체에서 Others 권한에 쓰기(w, 숫자 2)가 있는 파일 검색.
    2. /proc, /sys 등 가상 파일 시스템은 제외.
    3. 발견된 파일 목록을 리포팅 (시스템 로그 파일이나 lock 파일 등 정상적인 경우도 있으므로 목록 확인 필요).

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 명령 실행)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u25/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u25"
name: "World Writable File Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-25"
description: "Detect world writable files."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    find_command:
      type: string
      default: "find {path} -xdev {prune} -type f -perm -2 -ls"
    search_paths:
      type: array
      default:
        - "/etc"
        - "/var"
        - "/home"
        - "/opt"
        - "/root"
        - "/bin"
        - "/sbin"
        - "/usr/bin"
        - "/usr/sbin"
        - "/usr/local/bin"
        - "/usr/local/sbin"
    exclude_paths:
      type: array
      default:
        - "/proc"
        - "/sys"
        - "/dev"
        - "/run"
    whitelist_paths:
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
class_name: "WorldWritableFileCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `find_command`/`search_paths`/`exclude_paths` 기본값 제공.  
• `whitelist_paths`로 허용 파일 목록 설정.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 명령 실행 허용.
3) 명령 실행  
• `search_paths` 각각에 대해 분할 `find`를 실행하고 결과를 합산.  
• 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 판정  
• `find -ls` 출력에서 파일 경로 추출 후 `whitelist_paths` 제외.  
• 화이트리스트 외 항목이 존재하면 취약.  
• `max_results`만 evidence에 포함(나머지는 count만 기록).
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-25"`, `severity="High"`  
  - `tags=["KISA:U-25"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `partial_errors`

### 파서 설계(요약)
• `find -ls` 출력에서 마지막 필드를 경로로 사용.  
• 공백/빈 줄 제외.

### 테스트 계획
• 유닛:  
  - find 출력 파서 테스트.  
  - whitelist 필터 및 출력 제한(max_results) 테스트.  
• 통합(선택): `fixtures/` 샘플 find 출력으로 로컬 폴백 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-25 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u25"],
    "scan_config": {
      "remote_kisa_u25": {
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
