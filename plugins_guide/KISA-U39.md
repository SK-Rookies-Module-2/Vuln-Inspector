U-39: 불필요한 NFS 서비스 비활성화
• 중요도: 상
• 점검 목적: 사용하지 않는 NFS(Network File System) 서비스를 중지하여 침해 위험 제거.
• 보안 위협: NFS는 접근 통제가 미흡할 경우 파일 시스템 전체가 노출될 수 있음.
점검 대상 및 판단 기준
• 양호: NFS 서비스를 사용하지 않거나, 불가피하게 사용 시 프로세스가 확인되는 경우(미사용 시 비활성화가 원칙).
• 취약: 사용하지 않는데 NFS 관련 데몬(nfsd, statd, lockd)이 실행 중인 경우.
상세 점검 로직 (Scripting Guide)
• 프로세스 확인: ps -ef | grep -E "nfsd|statd|lockd"
• 판단: 프로세스가 실행 중이면 서비스 사용 여부와 대조. 미사용 시 실행 중이면 취약.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 프로세스 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u39/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u39"
name: "NFS Service Disable Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-39"
description: "Check whether NFS related daemons are running."
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
      default: "nfsd|statd|lockd"
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
class_name: "NfsServiceDisableCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `process_command`/`process_pattern` 기본값 적용.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 명령 확인 허용.
3) 프로세스 점검  
• `ps -ef` 출력에서 `nfsd|statd|lockd` 프로세스 존재 여부를 확인.  
• 프로세스가 존재하면 취약으로 판단.
4) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-39"`, `severity="High"`  
  - `tags=["KISA:U-39"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• `ps -ef` 출력에서 `process_pattern` 정규식 매칭.  
• `grep`으로 인한 자기 매칭 라인은 제외.

### 테스트 계획
• 유닛:  
  - 프로세스 라인 매칭 및 `grep` 제외 처리 테스트.  
  - 명령 실패/출력 없음 처리 테스트.  
• 통합(선택): 로컬 폴백으로 샘플 출력 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-39 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u39"],
    "scan_config": {
      "remote_kisa_u39": {
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
