U-52: Telnet 서비스 비활성화
• 중요도: 중
• 점검 목적: 보안에 취약한 Telnet 서비스를 비활성화하고 SSH 사용을 권장함.
• 보안 위협: Telnet은 평문 통신을 하므로 계정 정보 및 중요 데이터가 스니핑(Sniffing) 될 위험이 있음.
상세 점검 로직 (Scripting Guide)
• Inetd/Xinetd 확인:
    ◦ /etc/inetd.conf 내 telnet 라인이 주석 처리되지 않았으면 취약.
    ◦ /etc/xinetd.d/telnet 파일 내 disable = yes가 아니면 취약.
• Systemd 확인:
    ◦ systemctl list-units --type=socket | grep telnet 확인. 활성화 시 취약.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일/명령 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u52/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u52"
name: "Telnet Disable Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-52"
description: "Check telnet service disablement."
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
        - "telnet"
    check_inetd:
      type: boolean
      default: true
    check_xinetd:
      type: boolean
      default: true
    check_systemd:
      type: boolean
      default: true
    systemd_socket_command:
      type: string
      default: "systemctl list-units --type=socket"
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
class_name: "TelnetDisableCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `inetd_conf_path=/etc/inetd.conf`  
• linux: `xinetd_dir=/etc/xinetd.d`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `inetd_conf_path`/`xinetd_dir` 기본값 제공.  
• `xinetd_services` 기본값(telnet) 사용.  
• `check_systemd=true`면 systemd socket 목록을 확인.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 확인 허용.
3) Inetd/Xinetd 점검  
• `/etc/inetd.conf`에서 telnet 라인이 주석 처리되지 않으면 취약.  
• `/etc/xinetd.d/telnet`에서 `disable = yes`가 아니면 취약.
4) Systemd 점검  
• `systemctl list-units --type=socket` 출력에서 telnet socket이 있으면 취약.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-52"`, `severity="Medium"`  
  - `tags=["KISA:U-52"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• inetd.conf 라인을 주석 제거 후 telnet 토큰 탐지.  
• xinetd 서비스 파일에서 disable 설정값 파싱.  
• systemd 소켓 목록에서 telnet 토큰 탐지.

### 테스트 계획
• 유닛:  
  - inetd 라인 서비스 토큰 탐지 테스트.  
  - xinetd disable 설정 판정 테스트.  
  - systemd 출력 파서 테스트.
• 통합(선택): `fixtures/` 샘플 출력으로 로컬 폴백 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-52 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u52"],
    "scan_config": {
      "remote_kisa_u52": {
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
