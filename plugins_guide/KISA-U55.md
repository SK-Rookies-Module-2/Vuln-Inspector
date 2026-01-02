U-55: FTP 계정 Shell 제한
• 중요도: 중
• 점검 목적: FTP 접속 전용 계정에 쉘(/bin/false 등)을 부여하여 시스템 로그인을 차단.
• 보안 위협: FTP 계정에 일반 쉘이 부여되면 시스템에 직접 로그인하여 불필요한 명령어를 실행할 수 있음.
상세 점검 로직 (Scripting Guide)
• 파일: /etc/passwd
• 로직:
    ◦ ftp 계정의 쉘 설정 확인.
    ◦ /bin/false 또는 /sbin/nologin이 아니면 취약

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 /etc/passwd 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u55/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u55"
name: "FTP Account Shell Restriction Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-55"
description: "Check that FTP accounts use non-login shells."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    passwd_path:
      type: string
      default: "/etc/passwd"
    ftp_accounts:
      type: array
      default:
        - "ftp"
    allowed_shells:
      type: array
      default:
        - "/bin/false"
        - "/sbin/nologin"
        - "/usr/sbin/nologin"
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
class_name: "FtpAccountShellCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `passwd_path`, ftp 계정 목록, 허용 쉘 기본값 적용.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 확인 허용.
3) /etc/passwd 파싱  
• ftp 계정의 쉘 값을 추출.  
• 계정이 없으면 양호 처리.
4) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-55"`, `severity="Medium"`  
  - `tags=["KISA:U-55"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• /etc/passwd의 7번째 필드(shell)를 사용.  
• 허용 쉘 목록에 없으면 취약.

### 테스트 계획
• 유닛:  
  - ftp 계정 존재/미존재 및 쉘 판정 테스트.  
  - passwd 파서 오류 처리 테스트.  
• 통합(선택): 로컬 폴백으로 샘플 passwd 파일 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-55 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u55"],
    "scan_config": {
      "remote_kisa_u55": {
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
