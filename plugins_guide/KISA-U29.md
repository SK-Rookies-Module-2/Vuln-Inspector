U-29: hosts.lpd 파일 소유자 및 권한 설정
• 중요도: 하
• 점검 목적: 프린터 서비스 허용 호스트 파일의 변조 방지.
• 보안 위협: 파일 변조 시 프린터 서비스 방해 및 정보 유출 가능성.
점검 대상 및 판단 기준
• 양호: 파일이 없거나, 소유자가 root이고 권한이 600인 경우.
• 취약: 소유자가 root가 아니거나 권한이 600을 초과하는 경우.
상세 점검 로직 (Scripting Guide)
• 대상 파일: /etc/hosts.lpd
• 로직:
    1. 파일이 없으면 양호.
    2. 있다면 ls -l로 Owner(root) 및 Permission(600) 확인.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일 권한 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u29/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u29"
name: "hosts.lpd Permission Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-29"
description: "Check /etc/hosts.lpd ownership and permissions."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    hosts_lpd_path:
      type: string
    required_owner:
      type: string
      default: "root"
    max_mode:
      type: integer
      default: 600
    allow_group_write:
      type: boolean
      default: false
    allow_other_write:
      type: boolean
      default: false
    use_sudo:
      type: boolean
      default: false
    sudo_user:
      type: string
    allow_local_fallback:
      type: boolean
      default: false
entry_point: "main.py"
class_name: "HostsLpdPermissionCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `hosts_lpd_path=/etc/hosts.lpd`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `hosts_lpd_path` 기본값 적용.  
• `required_owner` 기본 root, `max_mode` 기본 600.  
• group/other 쓰기 허용 여부는 기본 false.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 권한 확인 허용.
3) 권한 확인  
• 파일이 없으면 양호(결과 없음).  
• 존재하면 소유자/권한 확인.  
• 파싱 실패/명령 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 판정  
• 소유자가 root가 아니면 취약.  
• 권한이 600 초과이거나 group/other 쓰기 권한이 있으면 취약.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-29"`, `severity="Low"`  
  - `tags=["KISA:U-29"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`

### 파서 설계(요약)
• `stat -c '%a %U'`, `stat -f '%Lp %Su'`, `ls -ld` 출력 파싱.

### 테스트 계획
• 유닛:  
  - stat/ls 출력 파서 변형 케이스 테스트.  
  - owner/권한 판정 및 파일 미존재 처리 테스트.
• 통합(선택): `fixtures/` 샘플 출력 파일로 로컬 폴백 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-29 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u29"],
    "scan_config": {
      "remote_kisa_u29": {
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
