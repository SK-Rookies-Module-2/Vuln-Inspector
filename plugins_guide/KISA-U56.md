U-56: FTP 서비스 접근 제어 설정
• 중요도: 하
• 점검 목적: ftpusers 파일 등을 통해 FTP 접속을 허용하지 않을 계정을 등록하거나 특정 IP만 접속 허용.
• 보안 위협: 접근 제어가 없을 경우 무차별 대입 공격 등에 노출될 수 있음.
상세 점검 로직 (Scripting Guide)
• vsFTP: userlist_enable=YES 및 userlist_deny 설정 확인. /etc/vsftpd.ftpusers 등 접근 제어 파일 설정 여부 확인.
• ProFTP: Limit LOGIN 설정 확인.
• TCP Wrapper: /etc/hosts.allow, /etc/hosts.deny 설정 확인.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u56/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u56"
name: "FTP Access Control Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-56"
description: "Check FTP access control configuration."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    vsftpd_conf_path:
      type: string
      default: "/etc/vsftpd.conf"
    vsftpd_userlist_files:
      type: array
      default:
        - "/etc/vsftpd.ftpusers"
        - "/etc/vsftpd/user_list"
        - "/etc/ftpusers"
    proftpd_conf_paths:
      type: array
      default:
        - "/etc/proftpd.conf"
        - "/etc/proftpd/proftpd.conf"
    hosts_allow_path:
      type: string
      default: "/etc/hosts.allow"
    hosts_deny_path:
      type: string
      default: "/etc/hosts.deny"
    check_vsftpd:
      type: boolean
      default: true
    check_proftpd:
      type: boolean
      default: true
    check_tcp_wrapper:
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
class_name: "FtpAccessControlCheck"
```

### OS별 기본 경로(코드 내 기본값)
• vsftpd: `/etc/vsftpd.conf`  
• vsftpd userlist: `/etc/vsftpd.ftpusers`, `/etc/vsftpd/user_list`, `/etc/ftpusers`  
• proftpd: `/etc/proftpd.conf`, `/etc/proftpd/proftpd.conf`  
• TCP Wrapper: `/etc/hosts.allow`, `/etc/hosts.deny`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. 경로 기본값 적용.  
• `check_vsftpd`/`check_proftpd`/`check_tcp_wrapper`로 점검 범위 제어.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 확인 허용.
3) vsftpd 점검  
• `userlist_enable=YES` 여부 확인.  
• `userlist_deny` 설정 여부 확인.  
• `userlist_file` 또는 기본 userlist 파일 존재 확인.
4) proftpd 점검  
• 설정 파일에서 `Limit LOGIN` 지시자 존재 확인.
5) TCP Wrapper 점검  
• `hosts.allow/hosts.deny`에서 ftp 관련 항목 또는 `ALL:ALL` 존재 확인.
6) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-56"`, `severity="Low"`  
  - `tags=["KISA:U-56"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• vsftpd 설정은 key/value 파싱 후 userlist 관련 옵션 판단.  
• proftpd는 `Limit LOGIN` 라인 탐지.  
• TCP Wrapper는 ftp 토큰 또는 `ALL:ALL` 패턴 탐지.

### 테스트 계획
• 유닛:  
  - vsftpd key/value 파서 및 userlist 설정 판정 테스트.  
  - proftpd Limit LOGIN 감지 테스트.  
  - TCP Wrapper 패턴 탐지 테스트.
• 통합(선택): `fixtures/` 샘플 설정으로 로컬 폴백 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-56 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u56"],
    "scan_config": {
      "remote_kisa_u56": {
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
