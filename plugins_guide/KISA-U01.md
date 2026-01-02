U-01: root 계정 원격 접속 제한
• 중요도: 상
• 점검 목적: 관리자 계정 탈취 방지를 위해 외부 비인가자의 root 계정 원격 접근을 원천 차단함.
• 보안 위협: root 계정은 운영체제의 모든 기능을 제어할 수 있으므로, 원격 접속 허용 시 무차별 대입 공격(Brute Force Attack) 등에 취약함.
점검 대상 및 판단 기준
• 대상: SOLARIS, LINUX, AIX, HP-UX
• 양호: 원격 터미널(Telnet, SSH) 서비스 사용 시 root 직접 접속이 차단된 경우
• 취약: 원격 터미널 서비스 사용 시 root 직접 접속이 허용된 경우
OS별 상세 점검 로직 (Scripting Guide)
1) Linux
• Telnet 점검:
    ◦ 파일: /etc/securetty
    ◦ 로직: 파일 내 pts/0 ~ pts/x 관련 설정이 존재하면 취약 (주석 처리 또는 제거되어야 함).
    ◦ 참고: CentOS 8, Ubuntu 20.04 이상은 해당 파일이 없거나 Telnet이 기본 비활성화됨.
• SSH 점검:
    ◦ 파일: /etc/ssh/sshd_config
    ◦ 로직: PermitRootLogin 설정값이 No가 아니면 취약.
2) Solaris
• Telnet 점검:
    ◦ 파일: /etc/default/login
    ◦ 로직: CONSOLE=/dev/console 설정이 주석 처리되어 있거나 없으면 취약.
• SSH 점검:
    ◦ 파일: /etc/ssh/sshd_config
    ◦ 로직: PermitRootLogin 값이 No가 아니면 취약.
3) AIX
• Telnet 점검:
    ◦ 파일: /etc/security/user
    ◦ 로직: rlogin 값이 false가 아니면 취약.
• SSH 점검:
    ◦ 파일: /etc/ssh/sshd_config
    ◦ 로직: PermitRootLogin 값이 No가 아니면 취약.
4) HP-UX
• Telnet 점검:
    ◦ 파일: /etc/securetty
    ◦ 로직: 파일 내 console 항목이 없으면 취약.
• SSH 점검:
    ◦ 파일: /opt/ssh/etc/sshd_config
    ◦ 로직: PermitRootLogin 값이 No가 아니면 취약.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일 확인)
• 대상: TargetType.SERVER
• 플러그인 위치(권장): `plugins/remote/kisa_u01/`
  - 기존 데모 플러그인 `remote_linux_kisa_u01`과 충돌을 피하기 위해 ID는 별도로 사용

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u01"
name: "Root Remote Login Restriction"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-01"
description: "Check root remote login restriction across SSH/Telnet by OS."
config_schema:
  required: ["os_type"]
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    protocols:
      type: array
      default: ["ssh", "telnet"]
    sshd_config_path:
      type: string
    telnet_config_path:
      type: string
    use_sudo:
      type: boolean
      default: false
    sudo_user:
      type: string
    allow_local_fallback:
      type: boolean
      default: false
entry_point: "main.py"
class_name: "RootRemoteLoginCheck"
```

### OS별 기본 경로(코드 내 기본값)
• linux: `sshd_config_path=/etc/ssh/sshd_config`, `telnet_config_path=/etc/securetty`  
• solaris: `sshd_config_path=/etc/ssh/sshd_config`, `telnet_config_path=/etc/default/login`  
• aix: `sshd_config_path=/etc/ssh/sshd_config`, `telnet_config_path=/etc/security/user`  
• hpux: `sshd_config_path=/opt/ssh/etc/sshd_config`, `telnet_config_path=/etc/securetty`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수, `protocols`는 `["ssh","telnet"]` 중만 허용(코드에서 추가 검증).  
• 경로 오버라이드가 없으면 OS별 기본 경로를 적용.
3) 파일 읽기  
• 기본은 SSH로 원격 파일을 읽음(`SshClient.run("cat <path>")`).  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 읽기 허용.  
• 읽기 실패/파일 없음은 `severity=Info`로 "점검 불가" Finding을 남김(증적 포함).
4) 파싱/판정  
• SSH: `PermitRootLogin` 값이 `no`가 아니거나(대소문자 무시) 미설정이면 취약.  
• Telnet(Linux): `/etc/securetty`에 주석 처리되지 않은 `pts/<n>` 항목이 있으면 취약.  
• Telnet(Solaris): `/etc/default/login`에 주석 처리되지 않은 `CONSOLE=/dev/console`이 없으면 취약.  
• Telnet(AIX): `/etc/security/user`에서 `root` 또는 `default` 스탠자 내 `rlogin` 값이 `false`가 아니면 취약.  
• Telnet(HP-UX): `/etc/securetty`에 `console` 항목이 없으면 취약.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-01"`, `severity="High"`  
  - `title`에 OS/프로토콜 포함(예: "Linux SSH root 원격 로그인 허용")  
  - `tags=["KISA:U-01"]` (+ 필요 시 "SSH"/"TELNET" 보조 태그)  
  - `evidence`: `os_type`, `protocol`, `config_path`, `detected_value`, `line`, `mode(remote/local)`, `host`

### 파서 설계(요약)
• 공통: 공백 라인/주석(`#`)은 무시.  
• `PermitRootLogin` 파서: 첫 번째 유효 라인의 값을 사용.  
• AIX 스탠자 파싱: `<section>:` 블록을 기준으로 `key = value` 수집, `root` 우선.

### 테스트 계획
• 유닛: OS별 파서 입력/출력 테스트(`tests/test_kisa_u01_parsers.py`).  
• 통합(선택): `fixtures/`에 샘플 설정 파일을 두고 `allow_local_fallback=true`로 실행 경로 검증.
