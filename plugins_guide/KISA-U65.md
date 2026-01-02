U-65: NTP 및 시각 동기화 설정
• 중요도: 중
• 점검 목적: 정확한 로그 분석을 위해 시스템 시간을 NTP 서버와 동기화.
• 보안 위협: 시간이 동기화되지 않으면 침해사고 발생 시 로그의 시간 정보 불일치로 분석이 어려움.
상세 점검 로직 (Scripting Guide)
• 파일: /etc/ntp.conf 또는 /etc/chrony.conf
• 명령어: ntpq -p, chronyc sources, ps -ef | grep ntp
• 로직:
    ◦ NTP 서비스 데몬 실행 여부 확인.
    ◦ 설정 파일에 유효한 Time Server가 등록되어 있는지 확인.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일/프로세스 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u65/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u65"
name: "NTP/Time Sync Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-65"
description: "Check NTP/chrony daemon and time server configuration."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    ntp_conf_paths:
      type: array
      default:
        - "/etc/ntp.conf"
    chrony_conf_paths:
      type: array
      default:
        - "/etc/chrony.conf"
        - "/etc/chrony/chrony.conf"
    process_command:
      type: string
      default: "ps -ef"
    process_pattern:
      type: string
      default: "ntpd|chronyd|systemd-timesyncd"
    insecure_sources:
      type: array
      default:
        - "127.0.0.1"
        - "127.127.1.0"
        - "localhost"
        - "::1"
    require_process:
      type: boolean
      default: true
    require_time_servers:
      type: boolean
      default: true
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
class_name: "NtpTimeSyncCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `ntp_conf_paths`/`chrony_conf_paths` 기본값 제공.  
• `process_pattern`으로 ntpd/chronyd/timesyncd 프로세스를 확인.  
• `insecure_sources`(기본 localhost 등)만 등록된 경우 취약 처리.  
• `require_process`/`require_time_servers`로 판정 기준 조정.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 확인 허용.
3) 파일/프로세스 확인  
• `ps -ef` 출력에서 NTP 데몬 실행 여부 확인.  
• 설정 파일에서 `server`/`pool`/`peer` 라인을 파싱.
4) 판정  
• 프로세스 미실행 또는 시간 서버 미설정 시 취약.  
• 서버가 모두 로컬(127.127.* 등)일 경우 취약.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-65"`, `severity="Medium"`  
  - `tags=["KISA:U-65"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `checked_files`, `missing_files`, `policy`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• 주석(#) 제거 후 `server`/`pool`/`peer` 라인에서 서버 주소 추출.  
• `ps -ef` 출력에서 패턴 매칭, `grep` 자기 자신은 제외.

### 테스트 계획
• 유닛:  
  - 프로세스 매칭 필터 테스트.  
  - 서버 라인 파서 및 로컬 서버 판정 테스트.  
  - 파일 미존재/오류 처리 테스트.
• 통합(선택): `fixtures/` 샘플 설정 파일로 로컬 폴백 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-65 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u65"],
    "scan_config": {
      "remote_kisa_u65": {
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
