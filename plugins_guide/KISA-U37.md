U-37: crontab 설정파일 권한 설정 미흡
• 중요도: 상
• 점검 목적: 스케줄링 서비스(cron, at) 관련 설정 파일의 변조 방지.
• 보안 위협: 일반 사용자가 cron 설정을 변조하여 관리자 권한으로 악성 스크립트를 주기적으로 실행시킬 수 있음.
점검 대상 및 판단 기준
• 양호: crontab, at 명령어의 일반 사용자 실행 권한이 없고, 관련 설정 파일 소유자가 root이며 권한이 640 이하인 경우.
• 취약: 위 조건을 만족하지 않는 경우.
상세 점검 로직 (Scripting Guide)
• 명령어 권한 점검:
    ◦ 파일: /usr/bin/crontab, /usr/bin/at
    ◦ 로직: ls -l 권한 확인. 일반 사용자 실행 권한(x)이 있으면 취약. (750 이하 권고)
• 설정 파일 권한 점검:
    ◦ 대상: /etc/cron.d/*, /etc/cron.daily/*, /etc/at.allow, /etc/cron.allow 등
    ◦ 로직: 소유자가 root가 아니거나, 권한이 640보다 높으면(예: 644, 666) 취약.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일 권한 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u37/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u37"
name: "Cron/At Permission Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-37"
description: "Check cron/at command and config file permissions."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    command_paths:
      type: array
      default:
        - "/usr/bin/crontab"
        - "/usr/bin/at"
    allow_group_execute:
      type: boolean
      default: false
    allow_other_execute:
      type: boolean
      default: false
    config_search_paths:
      type: array
      default:
        - "/etc/cron.d"
        - "/etc/cron.daily"
        - "/etc/cron.allow"
        - "/etc/at.allow"
    find_command:
      type: string
      default: "find {path} -type f -ls"
    allowed_owners:
      type: array
      default:
        - "root"
    max_mode:
      type: integer
      default: 640
    allow_group_write:
      type: boolean
      default: false
    allow_other_write:
      type: boolean
      default: false
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
class_name: "CronAtPermissionCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `command_paths`, `config_search_paths` 기본값 제공.  
• 일반 사용자 실행 허용 여부는 `allow_group_execute/allow_other_execute`로 제어.  
• 설정 파일 소유자/권한 정책은 `allowed_owners`, `max_mode`로 설정.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 확인 허용.
3) 명령어 권한 점검  
• `command_paths`에 대해 소유자/권한 확인.  
• group/other 실행 권한이 있으면 취약.
4) 설정 파일 권한 점검  
• `config_search_paths` 각각에서 `find`로 파일 목록을 수집.  
• 소유자가 root가 아니거나 권한이 640 초과이면 취약.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-37"`, `severity="High"`  
  - `tags=["KISA:U-37"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `checked_files`, `missing_paths`, `policy`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• `stat -c '%a %U'`, `stat -f '%Lp %Su'`, `ls -ld` 출력 파싱.  
• `find -ls` 출력에서 권한/소유자/경로를 파싱.

### 테스트 계획
• 유닛:  
  - 명령어 실행 권한 판정 테스트.  
  - find 출력 파서 및 권한/소유자 판정 테스트.  
  - 파일 미존재 및 오류 처리 테스트.
• 통합(선택): `fixtures/` 샘플 출력 파일로 로컬 폴백 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-37 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u37"],
    "scan_config": {
      "remote_kisa_u37": {
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
