U-40: NFS 접근 통제
• 중요도: 상
• 점검 목적: NFS 서비스 사용 시 허용된 클라이언트만 접근하도록 설정.
• 보안 위협: 접근 통제가 없으면 누구나 해당 서버의 파일 시스템을 마운트하여 데이터를 유출/변조할 수 있음.
점검 대상 및 판단 기준
• 양호: /etc/exports에 접근 가능한 호스트가 제한되어 있고 권한이 적절히 설정된 경우.
• 취약: 접근 제한이 없거나(*), 설정 파일 권한이 취약한 경우.
상세 점검 로직 (Scripting Guide)
• 설정 파일 점검:
    ◦ 파일: /etc/exports
    ◦ 로직: 내용 중 * (모든 호스트 허용) 설정이 있거나, insecure 옵션이 있으면 취약.
• 파일 권한 점검: /etc/exports의 소유자가 root이고 권한이 644 이하인지 확인.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일 권한/내용 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u40/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u40"
name: "NFS Access Control Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-40"
description: "Check NFS exports access control and permissions."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    exports_path:
      type: string
      default: "/etc/exports"
    required_owner:
      type: string
      default: "root"
    max_mode:
      type: integer
      default: 644
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
class_name: "NfsAccessControlCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `exports_path=/etc/exports`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `exports_path` 기본값 제공.  
• `required_owner` 기본 root, `max_mode` 기본 644.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 확인 허용.
3) 파일 내용 점검  
• `/etc/exports`에서 주석 제외 후 `*`(모든 호스트 허용) 또는 `insecure` 옵션 존재 여부 확인.  
• 파일이 없으면 양호(결과 없음).  
• 읽기 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 권한 점검  
• 소유자 root 및 권한 644 이하 여부 확인.  
• 소유자 불일치 또는 권한 초과 시 취약.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-40"`, `severity="High"`  
  - `tags=["KISA:U-40"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `partial_errors`

### 파서 설계(요약)
• `/etc/exports`에서 `*` 호스트 또는 `insecure` 옵션 탐지.  
• `stat -c '%a %U'` 또는 `stat -f '%Lp %Su'` 출력 파싱, 실패 시 `ls -ld` 파싱.

### 테스트 계획
• 유닛:  
  - exports 라인 파서(`*`, `insecure`) 감지 테스트.  
  - 권한/소유자 판정 테스트 및 파일 미존재 처리 테스트.
• 통합(선택): `fixtures/` 샘플 출력으로 로컬 폴백 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-40 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u40"],
    "scan_config": {
      "remote_kisa_u40": {
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
