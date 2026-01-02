U-09: 계정이 존재하지 않는 GID 금지
• 중요도: 하
• 점검 목적: 그룹 설정 파일에 불필요하거나 계정이 없는 그룹이 존재하는지 점검.
• 보안 위협: 소유자가 없는 그룹의 권한으로 설정된 파일이 악용될 수 있음.
점검 대상 및 판단 기준
• 양호: 불필요한 그룹이 존재하지 않는 경우.
• 취약: 계정이 없는 그룹 등 불필요한 그룹이 존재하는 경우.
상세 점검 로직 (Scripting Guide)
1) 공통
• 파일: /etc/group, /etc/passwd
• 로직:
    ◦ /etc/group의 모든 GID를 추출.
    ◦ /etc/passwd의 GID 필드와 비교.
    ◦ passwd 파일에 할당되지 않은 GID가 group 파일에 존재하는지 확인 (시스템 기본 그룹 제외).

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 /etc/group, /etc/passwd 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u09/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u09"
name: "Unassigned GID Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-09"
description: "Detect groups whose GID is not assigned to any account."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    group_path:
      type: string
    passwd_path:
      type: string
    exclude_groups:
      type: array
      default:
        - "root"
        - "bin"
        - "daemon"
        - "sys"
        - "adm"
        - "uucp"
        - "lp"
        - "mail"
        - "news"
    exclude_gids:
      type: array
    use_sudo:
      type: boolean
      default: false
    sudo_user:
      type: string
    allow_local_fallback:
      type: boolean
      default: false
entry_point: "main.py"
class_name: "UnassignedGidCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `group_path=/etc/group`, `passwd_path=/etc/passwd`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. 경로 오버라이드는 있으면 사용, 없으면 기본값 적용.  
• `exclude_groups`/`exclude_gids`는 배열로 검증.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 읽기 허용.
3) 파일 읽기  
• 기본은 SSH로 `cat <path>` 수행. 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 파싱/판정  
• `/etc/group`에서 그룹명과 GID를 파싱.  
• `/etc/passwd`에서 모든 GID(4번째 필드)를 수집.  
• `exclude_groups` 및 `exclude_gids`는 제외.  
• passwd에 할당되지 않은 GID를 가진 그룹이 있으면 취약.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-09"`, `severity="Low"`  
  - `title`에 OS 포함(예: "Linux 계정 없는 GID 존재")  
  - `tags=["KISA:U-09"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `line`, `mode(remote/local)`, `host`, `group`, `gid`

### 파서 설계(요약)
• 공백/주석 라인 무시.  
• `/etc/group`: `:` 기준 분리 후 `len(fields) >= 3`만 처리.  
• `/etc/passwd`: `:` 기준 분리 후 `len(fields) >= 4`만 처리.  
• GID 파싱 실패 시 해당 라인 스킵.

### 테스트 계획
• 유닛:  
  - group/passwd GID 파서 및 비교 로직 테스트.  
  - exclude_groups/exclude_gids 필터 적용 테스트.  
• 통합(선택): `fixtures/`에 샘플 `/etc/group`, `/etc/passwd`를 두고 `allow_local_fallback=true` 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-09 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u09"],
    "scan_config": {
      "remote_kisa_u09": {
        "os_type": "linux",
        "use_sudo": false
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
