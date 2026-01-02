U-43: NIS, NIS+ 점검
• 중요도: 상
• 점검 목적: 보안이 취약한 NIS(Network Information Service) 대신 NIS+를 사용하거나 서비스 비활성화.
• 보안 위협: NIS는 정보를 평문으로 전송하며, 비인가자가 맵 파일 등을 탈취하여 root 권한 획득 가능.
점검 대상 및 판단 기준
• 양호: NIS 서비스(ypserv, ypbind 등)를 사용하지 않거나, 필요시 NIS+를 사용하는 경우.
• 취약: 안전하지 않은 NIS 서비스를 사용하는 경우.
상세 점검 로직 (Scripting Guide)
• 프로세스 확인: ps -ef | grep -E "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"
• 판단: 프로세스가 실행 중이면 취약 (단, NIS+ 사용 시 예외 검토).

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 프로세스 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u43/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u43"
name: "NIS/NIS+ Service Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-43"
description: "Check whether NIS daemons are running."
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
      default: "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"
    check_nis_plus:
      type: boolean
      default: false
    nis_plus_pattern:
      type: string
      default: "rpc.nisd|nisplus"
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
class_name: "NisServiceCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `process_command`/`process_pattern` 기본값 적용.  
• `check_nis_plus=true`이면 NIS+ 프로세스 패턴도 함께 확인.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 명령 확인 허용.
3) 프로세스 점검  
• `ps -ef` 출력에서 NIS 관련 프로세스 존재 여부 확인.  
• NIS 프로세스가 존재하면 취약으로 판정.  
• NIS+ 프로세스 발견 시 evidence에 기록.
4) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-43"`, `severity="High"`  
  - `tags=["KISA:U-43"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `nis_plus_detected`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• `ps -ef` 출력에서 `process_pattern` 정규식 매칭.  
• `grep`으로 인한 자기 매칭 라인은 제외.

### 테스트 계획
• 유닛:  
  - NIS/NIS+ 프로세스 라인 매칭 및 `grep` 제외 처리 테스트.  
  - 명령 실패/출력 없음 처리 테스트.  
• 통합(선택): 로컬 폴백으로 샘플 출력 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-43 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u43"],
    "scan_config": {
      "remote_kisa_u43": {
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
