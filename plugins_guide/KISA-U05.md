U-05: root 이외의 UID가 '0' 금지
• 중요도: 상
• 점검 목적: root 권한(UID 0)을 가진 다른 계정이 존재하는지 확인.
• 보안 위협: UID가 0인 계정은 root와 동일한 권한을 가지므로, 의도치 않은 관리자 권한 부여를 방지해야 함.
점검 대상 및 판단 기준
• 양호: root 계정 외에 UID가 0인 계정이 없는 경우.
• 취약: root 계정 외에 UID가 0인 계정이 존재하는 경우.
상세 점검 로직 (Scripting Guide)
1) 공통 (Solaris, Linux, AIX, HP-UX)
• 파일: /etc/passwd
• 로직:
    ◦ 파일을 라인별로 파싱.
    ◦ 구분자(:)로 필드 분리.
    ◦ 세 번째 필드(UID)가 0인 계정 추출.
    ◦ 계정명이 root가 아닌데 UID가 0인 경우 취약으로 판단

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 /etc/passwd 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u05/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u05"
name: "UID 0 Non-root Account Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-05"
description: "Detect non-root accounts with UID 0 in /etc/passwd."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    passwd_path:
      type: string
    use_sudo:
      type: boolean
      default: false
    sudo_user:
      type: string
    allow_local_fallback:
      type: boolean
      default: false
entry_point: "main.py"
class_name: "UidZeroAccountCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `passwd_path=/etc/passwd`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `passwd_path` 오버라이드는 있으면 사용, 없으면 기본값 적용.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 읽기 허용.
3) 파일 읽기  
• 기본은 SSH로 `cat <path>` 수행. 실패 시 `Info`로 "점검 불가" Finding 기록.  
• `/etc/passwd`는 기본적으로 읽기 가능하지만, `use_sudo`로 접근 제어에 대비.
4) 파싱/판정  
• 라인별로 `:` 분리 후 세 번째 필드(UID) 확인.  
• UID가 0이면서 계정명이 `root`가 아닌 항목을 모두 수집.  
• 한 건이라도 존재하면 취약으로 판단(단일 Finding으로 집계).
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-05"`, `severity="High"`  
  - `title`에 OS 포함(예: "Linux UID 0 계정 존재")  
  - `tags=["KISA:U-05"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `line`, `mode(remote/local)`, `host`

### 파서 설계(요약)
• 공백/주석 라인 무시.  
• `:` 기준으로 필드 분리 후 `len(fields) >= 3`만 처리.  
• UID 파싱 실패 시 해당 라인은 스킵.  
• `username != root` && `uid == 0` 조건으로 취약 목록 생성.

### 테스트 계획
• 유닛:  
  - root 제외/UID 0 탐지 로직 테스트(`tests/test_kisa_u05_parsers.py`).  
  - 빈 라인/주석/필드 누락/UID 파싱 실패 케이스.  
• 통합(선택): `fixtures/`에 샘플 `/etc/passwd`를 두고 `allow_local_fallback=true` 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-05 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u05"],
    "scan_config": {
      "remote_kisa_u05": {
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
