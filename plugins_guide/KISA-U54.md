U-54: 암호화되지 않는 FTP 서비스 비활성화
• 중요도: 중
• 점검 목적: 평문으로 전송되는 일반 FTP 대신 SFTP 등 암호화된 전송 방식 사용 권고.
• 보안 위협: 일반 FTP 사용 시 계정 및 데이터가 평문으로 노출될 위험이 있음.
상세 점검 로직 (Scripting Guide)
• 점검: FTP 서비스(port 21)가 활성화되어 있는지 프로세스 및 포트 확인.
• 판단: 일반 FTP 서비스가 구동 중이면 취약 (단, 업무상 불가피한 경우 예외 처리)

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 프로세스/포트 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u54/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u54"
name: "Plain FTP Service Disable Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-54"
description: "Check whether plain FTP service is running."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    check_process:
      type: boolean
      default: true
    process_command:
      type: string
      default: "ps -ef"
    ftp_process_names:
      type: array
      default:
        - "ftpd"
        - "vsftpd"
        - "proftpd"
        - "pure-ftpd"
    check_port:
      type: boolean
      default: true
    netstat_command:
      type: string
      default: "netstat -an"
    ftp_port:
      type: integer
      default: 21
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
class_name: "PlainFtpDisableCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. 프로세스/포트 점검 옵션 기본값 적용.  
• `check_process`/`check_port` 중 하나라도 true여야 함.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 명령 확인 허용.
3) 프로세스/포트 점검  
• `ps -ef`에서 FTP 데몬 프로세스 존재 여부 확인.  
• `netstat -an`에서 21 포트 리스닝 확인.  
• 둘 중 하나라도 활성 상태면 취약.
4) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-54"`, `severity="Medium"`  
  - `tags=["KISA:U-54"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `checked_sources`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• ps 출력: ftp 프로세스 토큰 매칭.  
• netstat 출력: LISTEN 상태의 `:<port>` 매칭.

### 테스트 계획
• 유닛:  
  - FTP 프로세스 매칭 테스트.  
  - 포트 리스닝 매칭 테스트.  
  - 명령 실패 처리 테스트.
• 통합(선택): 로컬 폴백으로 샘플 출력 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-54 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u54"],
    "scan_config": {
      "remote_kisa_u54": {
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
