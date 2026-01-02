U-41: 불필요한 automountd 제거
• 중요도: 상
• 점검 목적: automountd 서비스는 로컬 공격 취약점(RPC 관련)이 존재하므로 미사용 시 제거.
• 보안 위협: 파일 시스템 마운트 옵션을 악용하여 권한 상승 등의 공격 가능.
점검 대상 및 판단 기준
• 양호: automountd 서비스가 비활성화된 경우.
• 취약: automountd 서비스가 활성화된 경우.
상세 점검 로직 (Scripting Guide)
• 프로세스 확인: ps -ef | grep -E "automount|autofs"
• 판단: 프로세스가 조회되면 취약.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 프로세스 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u41/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u41"
name: "Automountd Disable Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-41"
description: "Check whether automountd/autofs services are disabled."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    process_command:
      type: string
      default: "ps -ef"
    process_pattern:
      type: string
      default: "automount|autofs"
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
class_name: "AutomountdDisableCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `process_command`, `process_pattern` 기본값 제공.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 명령 실행 허용.
3) 명령 실행  
• `process_command` 실행 결과에서 `process_pattern` 매칭 여부 확인.  
• 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 판정  
• 프로세스가 발견되면 취약.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-41"`, `severity="High"`  
  - `tags=["KISA:U-41"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`

### 파서 설계(요약)
• `ps -ef` 출력에서 패턴 매칭.  
• `grep` 자기 자신 라인은 제외.

### 테스트 계획
• 유닛:  
  - 프로세스 매칭 필터 테스트.  
  - regex 오류 처리 테스트.  
• 통합(선택): `fixtures/` 샘플 ps 출력으로 로컬 폴백 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-41 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u41"],
    "scan_config": {
      "remote_kisa_u41": {
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
