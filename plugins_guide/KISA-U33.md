U-33: 숨겨진 파일 및 디렉토리 검색 및 제거
• 중요도: 하
• 점검 목적: 악의적인 목적의 은닉 파일 탐지.
• 보안 위협: 공격자가 생성한 백도어, 해킹 도구 등은 주로 숨김 파일(점 . 으로 시작) 형태일 수 있음.
점검 대상 및 판단 기준
• 양호: 불필요하거나 의심스러운 숨겨진 파일이 없는 경우.
• 취약: 의심스러운 숨겨진 파일이 발견된 경우.
상세 점검 로직 (Scripting Guide)
• 명령어: find / -type f -name ".*" -ls
• 로직:
    1. 시스템 전체에서 .으로 시작하는 파일 검색.
    2. .profile, .bashrc 등 정상적인 환경 설정 파일은 제외.
    3. 예상치 못한 경로(예: /tmp, /var/tmp, /dev 등)에 있는 숨김 파일을 중점적으로 리포팅.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 find 실행)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u33/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u33"
name: "Hidden File Discovery"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-33"
description: "Detect suspicious hidden files."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    find_command:
      type: string
      default: "find {path} -xdev {prune} -type f -name '.*' -ls"
    search_paths:
      type: array
      default:
        - "/"
        - "/home"
        - "/root"
        - "/tmp"
        - "/var"
        - "/var/tmp"
        - "/dev"
    exclude_paths:
      type: array
      default:
        - "/proc"
        - "/sys"
        - "/run"
    allowed_basenames:
      type: array
      default:
        - ".profile"
        - ".bashrc"
        - ".bash_profile"
        - ".bash_logout"
        - ".cshrc"
        - ".kshrc"
        - ".login"
        - ".logout"
        - ".zshrc"
        - ".zprofile"
        - ".zlogin"
        - ".zlogout"
        - ".vimrc"
        - ".viminfo"
        - ".nanorc"
        - ".tmux.conf"
        - ".screenrc"
        - ".inputrc"
        - ".gitconfig"
        - ".pwd.lock"
    whitelist_paths:
      type: array
      default: []
    suspicious_paths:
      type: array
      default:
        - "/tmp"
        - "/var/tmp"
        - "/dev"
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
class_name: "HiddenFileCheck"
```

### 기본 검색 경로(코드 내 기본값)
• /, /home, /root, /tmp, /var, /var/tmp, /dev  
• 제외 경로: /proc, /sys, /run

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수.  
• `find_command`, `search_paths`, `exclude_paths` 기본값 적용.  
• `allowed_basenames`/`whitelist_paths`로 정상 dotfile 제외.  
• `suspicious_paths`로 우선 리포팅 경로 정의.
3) 숨김 파일 탐색  
• search_paths마다 find 실행.  
• 실행 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 판정  
• 제외/화이트리스트를 제외한 숨김 파일이 있으면 취약.  
• suspicious_paths 하위 파일은 우선순위로 결과 상단에 배치.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-33"`, `severity="Low"`  
  - `tags=["KISA:U-33"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `count`, `suspicious_count`, `host`

### 파서 설계(요약)
• `find ... -ls` 출력에서 마지막 컬럼을 경로로 파싱.

### 테스트 계획
• 유닛:  
  - find 출력 파싱/필터링 로직 테스트.  
  - allowed/whitelist/suspicious 경로 분기 테스트.
• 통합(선택): 로컬 폴백(find 실행) 결과 샘플 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-33 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u33"],
    "scan_config": {
      "remote_kisa_u33": {
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
