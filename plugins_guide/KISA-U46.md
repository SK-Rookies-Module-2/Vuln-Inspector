U-46: 일반 사용자의 메일 서비스 실행 방지
• 중요도: 상
• 점검 목적: 일반 사용자가 메일 큐를 조작하지 못하도록 설정(Sendmail restrictqrun 옵션).
• 보안 위협: 일반 사용자가 메일 큐를 조작하여 서비스 거부 공격을 유발할 수 있음.
점검 대상 및 판단 기준
• 양호: SMTP 서비스 미사용 또는 restrictqrun 옵션이 설정된 경우.
• 취약: SMTP 서비스 사용 시 해당 옵션이 없는 경우.
상세 점검 로직 (Scripting Guide)
• Sendmail:
    ◦ 파일: /etc/mail/sendmail.cf
    ◦ 로직: O PrivacyOptions= 라인에 restrictqrun이 포함되어 있는지 확인.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 설정 파일 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u46/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u46"
name: "Sendmail restrictqrun Option Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-46"
description: "Check whether Sendmail restrictqrun option is set."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    sendmail_cf_path:
      type: string
      default: "/etc/mail/sendmail.cf"
    require_smtp_enabled:
      type: boolean
      default: false
    check_service:
      type: boolean
      default: false
    smtp_process_command:
      type: string
      default: "ps -ef"
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
class_name: "SendmailRestrictQrunCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. sendmail.cf 경로 기본값 적용.  
• `require_smtp_enabled=true`이면 SMTP 프로세스가 있지 않은 경우 점검 제외(양호 처리).  
• `check_service=true`이면 `smtp_process_command`로 SMTP 프로세스 여부 확인.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 확인 허용.
3) SMTP 프로세스 점검(선택)  
• `ps -ef`에서 sendmail 프로세스 존재 여부 확인.  
• SMTP 미사용으로 판단되면 결과 없음(양호).
4) sendmail.cf 점검  
• `O PrivacyOptions=` 라인에서 `restrictqrun` 포함 여부 확인.  
• 설정 파일이 없으면 SMTP 미사용으로 보고 양호 처리.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-46"`, `severity="High"`  
  - `tags=["KISA:U-46"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `checked_sources`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• sendmail.cf: 주석(#) 제거 후 `O PrivacyOptions` 라인의 옵션 목록에서 `restrictqrun` 존재 확인.  
• ps 출력: `sendmail` 토큰 매칭.

### 테스트 계획
• 유닛:  
  - sendmail.cf 옵션 파서 테스트.  
  - SMTP 프로세스 판정 테스트.  
  - 파일 미존재/읽기 실패 처리 테스트.
• 통합(선택): 로컬 폴백으로 샘플 설정 파일 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-46 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u46"],
    "scan_config": {
      "remote_kisa_u46": {
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
