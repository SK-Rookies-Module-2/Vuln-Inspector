U-48: expn, vrfy 명령어 제한
• 중요도: 중
• 점검 목적: SMTP 명령어 중 사용자 계정 유무를 확인하는 expn, vrfy 명령어 차단.
• 보안 위협: 공격자가 해당 명령어로 유효한 사용자 계정을 수집하여 비밀번호 대입 공격에 활용 가능.
점검 대상 및 판단 기준
• 양호: SMTP 서비스 미사용 또는 noexpn, novrfy 옵션이 설정된 경우.
• 취약: 해당 옵션이 설정되지 않은 경우.
상세 점검 로직 (Scripting Guide)
• Sendmail:
    ◦ 파일: /etc/mail/sendmail.cf
    ◦ 로직: O PrivacyOptions= 라인에 noexpn, novrfy (또는 goaway)가 포함되어 있는지 확인.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일 내용 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u48/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u48"
name: "SMTP EXPN/VRFY Disable Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-48"
description: "Check sendmail PrivacyOptions for noexpn/novrfy."
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
    required_tokens:
      type: array
      default:
        - "noexpn"
        - "novrfy"
    allow_goaway:
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
class_name: "SmtpExpnVrfyCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `sendmail_cf_path=/etc/mail/sendmail.cf`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `sendmail_cf_path` 기본값 제공.  
• `required_tokens` 기본 noexpn/novrfy.  
• `allow_goaway=true`면 goaway 설정을 허용(동등 판정).
3) 파일 내용 점검  
• `O PrivacyOptions=` 라인에서 옵션 목록 추출.  
• noexpn, novrfy 또는 goaway 포함 여부 확인.  
• 파일 미존재면 SMTP 미사용으로 판단하여 양호 처리(결과 없음).  
• 읽기 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-48"`, `severity="Medium"`  
  - `tags=["KISA:U-48"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `partial_errors`

### 파서 설계(요약)
• `O PrivacyOptions=` 또는 `PrivacyOptions=` 라인을 읽고 `,` 구분값 파싱.  
• 토큰 비교는 소문자 기준.

### 테스트 계획
• 유닛:  
  - PrivacyOptions 라인 파싱 및 토큰 매칭 테스트.  
  - 파일 미존재 처리 및 오류 처리 테스트.
• 통합(선택): `fixtures/` 샘플 sendmail.cf로 로컬 폴백 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-48 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u48"],
    "scan_config": {
      "remote_kisa_u48": {
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
