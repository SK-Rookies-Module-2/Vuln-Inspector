U-62: 로그인 시 경고 메시지 설정
• 중요도: 하
• 점검 목적: 서버 로그인 시 불법 접근에 대한 경고 메시지를 출력하여 법적 대응 근거 마련 및 경각심 고취.
• 보안 위협: 시스템 정보(OS 버전 등)가 배너에 노출되면 공격 정보로 활용될 수 있음.
상세 점검 로직 (Scripting Guide)
• 파일: /etc/motd, /etc/issue, /etc/issue.net, /etc/ssh/sshd_config (Banner 옵션)
• 로직:
    ◦ 해당 파일들에 경고 메시지가 설정되어 있는지 확인.
    ◦ 시스템 버전 등 불필요한 정보가 포함되어 있는지 확인.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 배너 설정 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u62/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u62"
name: "Login Warning Banner Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-62"
description: "Check login warning banner settings and exposure of system info."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    motd_path:
      type: string
      default: "/etc/motd"
    issue_path:
      type: string
      default: "/etc/issue"
    issue_net_path:
      type: string
      default: "/etc/issue.net"
    sshd_config_path:
      type: string
      default: "/etc/ssh/sshd_config"
    required_banner_phrases:
      type: array
      default:
        - "unauthorized"
        - "unauthorised"
        - "prohibited"
        - "authorized"
        - "authorised"
        - "접근"
        - "무단"
        - "불법"
        - "금지"
    disallowed_patterns:
      type: array
      default:
        - "Linux"
        - "Ubuntu"
        - "Debian"
        - "CentOS"
        - "Red Hat"
        - "SunOS"
        - "AIX"
        - "HP-UX"
        - "Kernel"
        - "\\\\r"
        - "\\\\m"
        - "\\\\s"
        - "\\\\v"
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
class_name: "LoginWarningBannerCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. 배너 파일 경로 기본값 적용.  
• 경고 문구 판단용 `required_banner_phrases`와 노출 패턴 `disallowed_patterns` 설정.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 확인 허용.
3) 배너 파일 확인  
• motd/issue/issue.net 파일 내용 확인.  
• sshd_config의 `Banner` 경로를 읽어 실제 배너 파일 내용 확인.  
• 파일이 없으면 해당 경로는 양호로 처리.
4) 판정  
• 배너 파일에 경고 문구가 없으면 취약.  
• 배너 내용에 시스템 정보 패턴이 포함되면 취약.  
• 하나 이상의 배너 파일이 정상 경고를 포함하고 정보 노출이 없으면 양호.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-62"`, `severity="Low"`  
  - `tags=["KISA:U-62"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `checked_files`, `missing_files`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• sshd_config: `Banner` 라인에서 파일 경로 추출.  
• 배너 파일 내용은 소문자 비교로 경고 문구 포함 여부 확인.  
• `disallowed_patterns`는 정규식으로 검사.

### 테스트 계획
• 유닛:  
  - 배너 문구 포함 여부 판정 테스트.  
  - disallowed 패턴 매칭 테스트.  
  - sshd_config Banner 파서 테스트.  
• 통합(선택): 로컬 폴백으로 샘플 배너 파일 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-62 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u62"],
    "scan_config": {
      "remote_kisa_u62": {
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
