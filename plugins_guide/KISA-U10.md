U-10: 동일한 UID 금지
• 중요도: 중
• 점검 목적: 중복된 UID를 가진 계정이 있는지 점검.
• 보안 위협: UID가 중복되면 시스템은 동일 사용자로 인식하여 권한 중복 및 감사 추적의 어려움이 발생함.
점검 대상 및 판단 기준
• 양호: 동일한 UID를 가진 계정이 없는 경우.
• 취약: 동일한 UID를 가진 계정이 존재하는 경우.
상세 점검 로직 (Scripting Guide)
1) 공통
• 파일: /etc/passwd
• 로직:
    ◦ 파일의 세 번째 필드(UID)를 추출.
    ◦ 중복된 UID 값이 있는지 검사.
    ◦ 중복된 경우 해당 UID를 사용하는 계정 목록 출력

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 /etc/passwd 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u10/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u10"
name: "Duplicate UID Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-10"
description: "Detect duplicate UID assignments in /etc/passwd."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    passwd_path:
      type: string
    exclude_uids:
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
class_name: "DuplicateUidCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `passwd_path=/etc/passwd`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `passwd_path` 오버라이드는 있으면 사용, 없으면 기본값 적용.  
• `exclude_uids`는 배열로 검증(선택).  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 읽기 허용.
3) 파일 읽기  
• 기본은 SSH로 `cat <path>` 수행. 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 파싱/판정  
• `/etc/passwd`에서 UID를 파싱해 UID → 계정 목록을 구성.  
• 동일 UID가 2개 이상인 경우 취약으로 판단.  
• `exclude_uids`에 포함된 UID는 결과에서 제외.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-10"`, `severity="Medium"`  
  - `title`에 OS 포함(예: "Linux 동일 UID 존재")  
  - `tags=["KISA:U-10"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `line`, `mode(remote/local)`, `host`, `uid`

### 파서 설계(요약)
• 공백/주석 라인 무시.  
• `:` 기준 분리 후 `len(fields) >= 3`만 처리.  
• UID 파싱 실패 시 해당 라인 스킵.

### 테스트 계획
• 유닛:  
  - UID 중복 검출 및 exclude_uids 필터 테스트.  
  - 파싱 실패/필드 누락 케이스.  
• 통합(선택): `fixtures/`에 샘플 `/etc/passwd`를 두고 `allow_local_fallback=true` 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-10 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u10"],
    "scan_config": {
      "remote_kisa_u10": {
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
