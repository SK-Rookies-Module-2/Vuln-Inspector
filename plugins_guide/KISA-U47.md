U-47: 스팸 메일 릴레이 제한
• 중요도: 상
• 점검 목적: SMTP 서버가 스팸 메일 경유지로 악용되지 않도록 릴레이 제한 설정.
• 보안 위협: 릴레이가 허용되면 스팸 메일 발송처로 악용되어 서버가 블랙리스트에 등재되거나 과부하 발생.
점검 대상 및 판단 기준
• 양호: SMTP 서비스 미사용 또는 릴레이 제한이 설정된 경우.
• 취약: 릴레이 제한이 설정되지 않은 경우.
상세 점검 로직 (Scripting Guide)
• Sendmail:
    ◦ 파일: /etc/mail/access
    ◦ 로직: DB 파일이 존재하고, 릴레이 허용 정책이 적절한지 확인. (promiscuous_relay 설정 금지)
    ◦ 파일: /etc/mail/sendmail.cf 에서 R$* $#error $@ 5.7.1 $: "550 Relaying denied" 설정 확인.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 Sendmail 설정 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u47/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u47"
name: "SMTP Relay Restriction Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-47"
description: "Check sendmail relay restriction settings."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    access_path:
      type: string
      default: "/etc/mail/access"
    access_db_path:
      type: string
      default: "/etc/mail/access.db"
    sendmail_cf_path:
      type: string
      default: "/etc/mail/sendmail.cf"
    check_access:
      type: boolean
      default: true
    check_access_db:
      type: boolean
      default: true
    check_sendmail_cf:
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
class_name: "SmtpRelayRestrictionCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. access/sendmail 경로와 체크 옵션 기본값 적용.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 확인 허용.
3) access/access.db 점검  
• `/etc/mail/access`에서 `promiscuous_relay` 사용 여부 확인.  
• `/etc/mail/access.db`가 존재하는지 확인.  
• sendmail 관련 파일이 모두 없으면 서비스 미사용으로 간주.
4) sendmail.cf 점검  
• `Relaying denied` 규칙 문자열 존재 여부 확인.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-47"`, `severity="High"`  
  - `tags=["KISA:U-47"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `missing_files`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• access 파일에서 `promiscuous_relay` 문자열 탐지.  
• sendmail.cf에서 `Relaying denied` 문자열 탐지.  
• 주석 라인은 제외하고 검사.

### 테스트 계획
• 유닛:  
  - access 파일에서 promiscuous_relay 탐지 테스트.  
  - sendmail.cf 문자열 검출 테스트.  
  - access.db 미존재 처리 테스트.  
• 통합(선택): 로컬 폴백으로 샘플 설정 파일 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-47 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u47"],
    "scan_config": {
      "remote_kisa_u47": {
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
