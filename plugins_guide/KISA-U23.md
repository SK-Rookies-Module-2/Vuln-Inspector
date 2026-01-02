U-23: SUID, SGID, Sticky bit 설정 파일 점검
• 중요도: 상
• 점검 목적: 불필요한 특수 권한(SetUID, SetGID)이 설정된 파일을 식별하여 권한 상승 공격 방지.
• 보안 위협: 취약한 SUID 파일 실행 시 root 권한을 탈취당할 수 있음.
점검 대상 및 판단 기준
• 양호: 주요 실행 파일 외에 불필요한 SUID/SGID가 설정되어 있지 않은 경우.
• 취약: 불필요하거나 악의적인 파일에 SUID/SGID가 설정된 경우.
상세 점검 로직 (Scripting Guide)
• 명령어: find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -ls
• 로직:
    1. 시스템 전역에서 SUID(4000), SGID(2000)가 설정된 파일 검색.
    2. 화이트리스트 비교: /usr/bin/passwd, /usr/bin/su, /bin/ping 등 OS 구동에 필수적인 잘 알려진 파일은 제외.
    3. 그 외의 경로(특히 /tmp, /var, /home 등)에서 발견된 SUID 파일은 취약 가능성 높음으로 리포팅.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 명령 실행)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u23/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u23"
name: "SUID/SGID File Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-23"
description: "Detect unnecessary SUID/SGID files."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    find_command:
      type: string
      default: "find {path} -xdev {prune} -user root -type f \\( -perm -04000 -o -perm -02000 \\) -ls"
    search_paths:
      type: array
      default:
        - "/"
    exclude_paths:
      type: array
      default:
        - "/proc"
        - "/sys"
        - "/dev"
        - "/run"
    whitelist_paths:
      type: array
      default:
        - "/usr/bin/passwd"
        - "/usr/bin/su"
        - "/bin/ping"
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
class_name: "SuidSgidFileCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `find_command`/`search_paths`/`exclude_paths` 기본값 제공.  
• `whitelist_paths`로 허용 파일 목록 설정.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 명령 실행 허용.
3) 명령 실행  
• `search_paths` 각각에 대해 `find`를 실행하고 결과를 합산.  
• 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 판정  
• `find -ls` 출력에서 파일 경로 추출 후 화이트리스트 제외.  
• 화이트리스트 외 항목이 존재하면 취약.  
• `max_results`만 evidence에 포함(나머지는 count만 기록).
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-23"`, `severity="High"`  
  - `title`에 OS 포함(예: "Linux SUID/SGID 파일 과다")  
  - `tags=["KISA:U-23"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode(remote/local)`, `host`, `count`

### 파서 설계(요약)
• `find -ls` 출력에서 마지막 필드를 경로로 사용.  
• 공백/빈 줄 제외.

### 테스트 계획
• 유닛:  
  - 화이트리스트 필터 및 출력 제한(max_results) 테스트.  
  - find 출력 파서 테스트.  
• 통합(선택): `fixtures/`에 샘플 find 출력 파일로 로컬 폴백 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-23 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u23"],
    "scan_config": {
      "remote_kisa_u23": {
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
