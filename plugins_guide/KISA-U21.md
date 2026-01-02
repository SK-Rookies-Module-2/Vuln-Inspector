U-21: /etc/(r)syslog.conf 파일 소유자 및 권한 설정
• 중요도: 상
• 점검 목적: 로그 설정 파일의 변조를 방지하여 로그 위변조 및 미기록 시도를 차단함.
• 보안 위협: 비인가자가 설정 파일을 수정하여 로그를 남기지 않거나 허위 로그를 남길 수 있음.
점검 대상 및 판단 기준
• 양호: 소유자가 root(또는 bin, sys)이고, 권한이 640 이하인 경우.
• 취약: 소유자가 root(또는 bin, sys)가 아니거나, 권한이 640을 초과하는 경우.
상세 점검 로직 (Scripting Guide)
• 대상 파일: /etc/syslog.conf, /etc/rsyslog.conf
• 로직:
    1. 파일 존재 여부 확인.
    2. ls -l 정보 파싱.
    3. Owner: root, bin, sys 중 하나인지 확인.
    4. Permission: Group Write(w), Others Read(r)/Write(w)/Execute(x)가 없는지 확인 (640 이하).

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일 권한 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u21/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u21"
name: "Syslog Config Permission Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-21"
description: "Check syslog/rsyslog configuration file ownership and permissions."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    syslog_conf_path:
      type: string
    rsyslog_conf_path:
      type: string
    allowed_owners:
      type: array
      default:
        - "root"
        - "bin"
        - "sys"
    max_mode:
      type: integer
      default: 640
    allow_group_write:
      type: boolean
      default: false
    allow_other_permissions:
      type: boolean
      default: false
    use_sudo:
      type: boolean
      default: false
    sudo_user:
      type: string
    allow_local_fallback:
      type: boolean
      default: false
entry_point: "main.py"
class_name: "SyslogConfigPermissionCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `syslog_conf_path=/etc/syslog.conf`, `rsyslog_conf_path=/etc/rsyslog.conf`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. 경로 오버라이드는 있으면 사용, 없으면 기본값 적용.  
• `allowed_owners` 기본값 root/bin/sys, `max_mode` 기본값 640.  
• `allow_group_write`/`allow_other_permissions` 기본 false.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 권한 확인 허용.
3) 권한 확인  
• 기본은 SSH로 `stat` 또는 `ls -ld` 실행.  
• 두 파일 모두 없을 경우 `Info`로 "점검 불가" Finding 기록.
4) 판정  
• 소유자가 `allowed_owners`에 없으면 취약.  
• 권한이 `max_mode`보다 크면 취약.  
• group write 또는 other 권한이 있으면 취약(allow_* 옵션이 true인 경우 예외).
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-21"`, `severity="High"`  
  - `title`에 OS 포함(예: "Linux syslog 권한 설정 미흡")  
  - `tags=["KISA:U-21"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode(remote/local)`, `host`, `owner`, `permission`, `count`

### 파서 설계(요약)
• `stat -c '%a %U'` 또는 `stat -f '%Lp %Su'` 출력 파싱.  
• 실패 시 `ls -ld` 출력에서 권한/소유자 파싱.

### 테스트 계획
• 유닛:  
  - stat/ls 출력 파서 변형 케이스 테스트.  
  - owner 허용 목록/권한 비교/others 권한 판정 테스트.  
• 통합(선택): `fixtures/`에 샘플 `ls -ld` 출력 파일로 로컬 폴백 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-21 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u21"],
    "scan_config": {
      "remote_kisa_u21": {
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
