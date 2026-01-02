U-66: 정책에 따른 시스템 로깅 설정
• 중요도: 중
• 점검 목적: 주요 이벤트(인증, 에러 등)가 적절히 로깅되도록 설정.
• 보안 위협: 로그가 남지 않으면 침해 사고 추적이 불가능함.
상세 점검 로직 (Scripting Guide)
• 파일: /etc/syslog.conf 또는 /etc/rsyslog.conf
• 로직:
    ◦ *.info, authpriv.*, mail.*, cron.*, *.alert, *.emerg 등의 주요 로그 레벨이 설정되어 있는지 확인.
    ◦ 예시: *.info;mail.none;authpriv.none;cron.none /var/log/messages

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 로그 설정 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u66/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u66"
name: "System Logging Policy Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-66"
description: "Check syslog/rsyslog policy configuration for key facilities."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    syslog_conf_paths:
      type: array
      default:
        - "/etc/syslog.conf"
        - "/etc/rsyslog.conf"
    required_selectors:
      type: array
      default:
        - "*.info"
        - "authpriv.*"
        - "mail.*"
        - "cron.*"
        - "*.alert"
        - "*.emerg"
    allow_missing_config:
      type: boolean
      default: false
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
class_name: "SystemLoggingPolicyCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. syslog 설정 경로/필수 셀렉터 기본값 적용.  
• `allow_missing_config=false`이면 모든 설정 파일이 없을 때 점검 불가로 처리.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 확인 허용.
3) 설정 파일 확인  
• syslog/rsyslog 파일에서 selector 구문을 파싱해 후보 목록을 생성.  
• `required_selectors`가 모두 충족되는지 확인.
4) 판정  
• 필수 셀렉터가 하나라도 누락되면 취약.  
• 모든 필수 셀렉터가 존재하면 양호.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-66"`, `severity="Medium"`  
  - `tags=["KISA:U-66"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `checked_files`, `missing_files`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• 각 라인의 selector 파트를 분리해 `facility.priority` 토큰으로 정규화.  
• `none`/`!`는 제외하고 `=`는 제거하여 비교.  
• `required_selectors`의 와일드카드(`*`)를 패턴으로 사용해 매칭.

### 테스트 계획
• 유닛:  
  - selector 파서 테스트(semicolon/comma/none 처리).  
  - required_selectors 매칭 테스트.  
  - 파일 미존재 처리 테스트.
• 통합(선택): 로컬 폴백으로 샘플 syslog 설정 파일 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-66 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u66"],
    "scan_config": {
      "remote_kisa_u66": {
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
