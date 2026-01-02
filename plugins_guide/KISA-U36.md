U-36: r 계열 서비스 비활성화
• 중요도: 상
• 점검 목적: rlogin, rsh, rexec 등 인증 없이 관리자 접속이 가능한 취약한 서비스를 차단.
• 보안 위협: r-command는 인증 과정이 취약하여 IP 스푸핑 공격 등에 악용될 수 있음.
점검 대상 및 판단 기준
• 양호: r 계열 서비스가 비활성화된 경우.
• 취약: r 계열 서비스가 활성화된 경우.
상세 점검 로직 (Scripting Guide)
• Inetd/Xinetd 확인:
    ◦ 파일: /etc/inetd.conf, /etc/xinetd.d/rlogin, /etc/xinetd.d/rsh, /etc/xinetd.d/rexec
    ◦ 로직: disable = yes가 아니거나 inetd.conf 내 주석 처리되지 않은 라인이 있으면 취약.
• Systemd/Service 확인:
    ◦ 명령어: systemctl list-unit-files | grep -E 'rlogin|rsh|rexec'
    ◦ 로직: 상태가 enabled 또는 active이면 취약.
• 프로세스 확인: ps -ef | grep -E "rlogind|rshd|rexecd"

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일/명령 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u36/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u36"
name: "R Services Disable Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-36"
description: "Check rlogin/rsh/rexec service disablement."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    inetd_conf_path:
      type: string
      default: "/etc/inetd.conf"
    xinetd_dir:
      type: string
      default: "/etc/xinetd.d"
    xinetd_services:
      type: array
      default:
        - "rlogin"
        - "rsh"
        - "rexec"
    check_inetd:
      type: boolean
      default: true
    check_xinetd:
      type: boolean
      default: true
    check_systemd:
      type: boolean
      default: true
    check_processes:
      type: boolean
      default: true
    systemd_list_units_command:
      type: string
      default: "systemctl list-unit-files"
    systemd_active_units_command:
      type: string
      default: "systemctl list-units --type=service --state=active"
    process_command:
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
class_name: "RServiceDisableCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `inetd_conf_path=/etc/inetd.conf`  
• linux: `xinetd_dir=/etc/xinetd.d`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. 경로/명령 기본값 적용.  
• `check_inetd`/`check_xinetd`/`check_systemd`/`check_processes`로 점검 범위 제어.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 확인 허용.
3) Inetd/Xinetd 점검  
• `/etc/inetd.conf`에서 rlogin/rsh/rexec 관련 라인이 주석 처리되지 않았으면 취약.  
• `/etc/xinetd.d/{rlogin,rsh,rexec}`에서 `disable = yes`가 아니면 취약.
4) Systemd/프로세스 점검  
• `systemctl list-unit-files`에서 r 계열 서비스가 enabled면 취약.  
• `systemctl list-units --state=active`에서 r 계열 서비스가 active면 취약.  
• `ps -ef`에서 `rlogind|rshd|rexecd` 프로세스가 있으면 취약.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-36"`, `severity="High"`  
  - `tags=["KISA:U-36"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• 파일 내용에서 주석을 제거한 뒤 `disable` 설정값 확인.  
• systemd/ps 출력에서 rlogin/rsh/rexec 관련 토큰 탐지.

### 테스트 계획
• 유닛:  
  - inetd/xinetd 라인 파싱 및 disable 설정 판정 테스트.  
  - systemd/ps 출력 파서 테스트.
• 통합(선택): `fixtures/` 샘플 출력으로 로컬 폴백 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-36 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u36"],
    "scan_config": {
      "remote_kisa_u36": {
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
