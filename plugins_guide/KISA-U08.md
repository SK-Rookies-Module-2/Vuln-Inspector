U-08: 관리자 그룹에 최소한의 계정 포함
• 중요도: 중
• 점검 목적: root 그룹(관리자 그룹)에 불필요한 계정이 포함되어 있는지 점검.
• 보안 위협: 관리자 그룹에 일반 계정이 포함되면 시스템 운영 파일에 대한 접근 권한을 갖게 되어 변조 위험이 있음.
점검 대상 및 판단 기준
• 양호: 관리자 그룹에 불필요한 계정이 없는 경우.
• 취약: 관리자 그룹에 불필요한 계정이 있는 경우.
상세 점검 로직 (Scripting Guide)
1) 공통
• 파일: /etc/group
• 로직:
    ◦ 그룹명이 root (또는 OS별 관리자 그룹)인 라인 파싱.
    ◦ 그룹원 목록(네 번째 필드 등)에 root 외의 불필요한 계정이 포함되어 있는지 확인.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 /etc/group 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u08/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u08"
name: "Admin Group Membership Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-08"
description: "Check for unnecessary accounts in admin groups."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    group_path:
      type: string
    admin_groups:
      type: array
      default:
        - "root"
        - "wheel"
    allowed_members:
      type: array
      default:
        - "root"
    use_sudo:
      type: boolean
      default: false
    sudo_user:
      type: string
    allow_local_fallback:
      type: boolean
      default: false
entry_point: "main.py"
class_name: "AdminGroupMembershipCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `group_path=/etc/group`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `group_path` 오버라이드는 있으면 사용, 없으면 기본값 적용.  
• `admin_groups`/`allowed_members`는 배열로 검증하며 기본값 제공.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 읽기 허용.
3) 파일 읽기  
• 기본은 SSH로 `cat <path>` 수행. 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 파싱/판정  
• `/etc/group` 라인을 `:`로 분리해 그룹명과 그룹원 목록(4번째 필드) 파싱.  
• `admin_groups`에 포함된 그룹만 대상.  
• 그룹원 중 `allowed_members`에 없는 계정을 모두 수집.  
• 불필요한 계정이 1개 이상이면 취약.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-08"`, `severity="Medium"`  
  - `title`에 OS 포함(예: "Linux 관리자 그룹 계정 과다")  
  - `tags=["KISA:U-08"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `line`, `mode(remote/local)`, `host`, `group`

### 파서 설계(요약)
• 공백/주석 라인 무시.  
• `:` 기준 분리 후 `len(fields) >= 4`인 라인만 처리.  
• 그룹원 목록은 `,`로 분리하고 공백 제거.

### 테스트 계획
• 유닛:  
  - 관리자 그룹 멤버 파싱 및 `allowed_members` 필터 테스트.  
  - 그룹원 필드가 비어 있거나 누락된 케이스.  
• 통합(선택): `fixtures/`에 샘플 `/etc/group`를 두고 `allow_local_fallback=true` 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-08 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u08"],
    "scan_config": {
      "remote_kisa_u08": {
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
