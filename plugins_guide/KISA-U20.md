U-20: /etc/(x)inetd.conf 파일 소유자 및 권한 설정
• 중요도: 상
• 점검 목적: 슈퍼데몬 설정 파일 변조 방지.
• 보안 위협: 설정 파일 변조 시 불법 서비스 실행이나 서비스 거부 공격 등이 가능함.
점검 대상 및 판단 기준
• 양호: 소유자가 root이고, 권한이 600 이하인 경우.
• 취약: 권한이 600을 초과하거나 소유자가 root가 아닌 경우.
상세 점검 로직 (Scripting Guide)
1) Linux (xinetd/inetd)
• 파일: /etc/inetd.conf, /etc/xinetd.conf, /etc/xinetd.d/*
• 로직: Owner: root, Perm: 600 확인.
2) Solaris, AIX, HP-UX
• 파일: /etc/inetd.conf
• 로직: Owner: root, Perm: 600 확인.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일 권한 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u20/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u20"
name: "Inetd Config Permission Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-20"
description: "Check inetd/xinetd configuration file ownership and permissions."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    inetd_conf_path:
      type: string
    xinetd_conf_path:
      type: string
    xinetd_dir:
      type: string
    required_owner:
      type: string
      default: "root"
    max_mode:
      type: integer
      default: 600
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
class_name: "InetdConfigPermissionCheck"
```

### OS별 기본 경로(코드 내 기본값)
• linux: `inetd_conf_path=/etc/inetd.conf`, `xinetd_conf_path=/etc/xinetd.conf`, `xinetd_dir=/etc/xinetd.d`  
• solaris/aix/hpux: `inetd_conf_path=/etc/inetd.conf`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. OS별 경로 오버라이드는 있으면 사용, 없으면 기본값 적용.  
• `required_owner` 기본값 root, `max_mode` 기본값 600.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 권한 확인 허용.
3) 권한 확인  
• Linux: `/etc/inetd.conf`, `/etc/xinetd.conf`, `/etc/xinetd.d/*` 권한 확인.  
• Solaris/AIX/HP-UX: `/etc/inetd.conf` 권한 확인.  
• 파싱 실패/명령 실패 시 `Info`로 "점검 불가" Finding 기록(모든 대상이 없을 때).
4) 판정  
• 소유자 불일치 또는 권한이 `max_mode`보다 크면 취약.  
• 권한 비교는 8진수 기준(예: 0600).
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-20"`, `severity="High"`  
  - `title`에 OS 포함(예: "Linux inetd 권한 설정 미흡")  
  - `tags=["KISA:U-20"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode(remote/local)`, `host`, `owner`, `permission`, `count`

### 파서 설계(요약)
• `stat -c '%a %U'` 또는 `stat -f '%Lp %Su'` 출력 파싱.  
• 실패 시 `ls -ld` 출력에서 권한/소유자 파싱.

### 테스트 계획
• 유닛:  
  - stat/ls 출력 파서 변형 케이스 테스트.  
  - 권한 비교 경계값(600/640/666) 테스트.  
• 통합(선택): `fixtures/`에 샘플 `ls -ld` 출력 파일로 로컬 폴백 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-20 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u20"],
    "scan_config": {
      "remote_kisa_u20": {
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
