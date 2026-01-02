U-64: 주기적 보안 패치 및 벤더 권고사항 적용
• 중요도: 상
• 점검 목적: OS 및 서비스의 최신 보안 패치 적용 여부 확인.
• 보안 위협: 알려진 취약점을 방치할 경우 공격의 대상이 됨.
상세 점검 로직 (Scripting Guide)
• 명령어: uname -a, rpm -qa (Linux), showrev -p (Solaris), oslevel -s (AIX) 등.
• 로직: 현재 커널 및 패키지 버전을 확인하여 벤더사의 최신 권고 버전과 비교(자동화 도구에서는 버전 정보 수집 후 DB와 비교).

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 명령 실행)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u64/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u64"
name: "Security Patch Level Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-64"
description: "Collect kernel/package version info for patch verification."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    kernel_command:
      type: string
      default: "uname -a"
    package_commands:
      type: array
      default: []
    min_kernel_version:
      type: string
    report_unknown:
      type: boolean
      default: true
    max_lines_per_command:
      type: integer
      default: 200
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
class_name: "SecurityPatchLevelCheck"
```

### OS별 기본 명령(코드 내 기본값)
• linux: `uname -a`, `rpm -qa`  
• solaris: `uname -a`, `showrev -p`  
• aix: `uname -a`, `oslevel -s`  
• hpux: `uname -a`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `kernel_command` 기본값 사용.  
• `package_commands`가 없으면 OS별 기본 명령 목록을 사용.  
• `min_kernel_version`이 있으면 커널 버전 비교 수행.  
• `report_unknown=true`면 기준 버전 부재/파싱 실패 시 Info로 보고.
3) 명령 실행  
• 커널/패키지 명령을 실행하고 결과를 제한된 라인 수로 수집.  
• 명령 실패 시 `Info`로 "점검 불가" Finding 기록.
4) 판정  
• `min_kernel_version` 대비 커널 버전이 낮으면 취약.  
• 기준 버전 정보가 없으면 "확인 필요" Info로 리포팅.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-64"`, `severity="High"`  
  - `tags=["KISA:U-64"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `partial_errors`  
• 확인 필요 시 `Info` Finding 기록.

### 파서 설계(요약)
• `uname -a` 출력에서 숫자 버전 토큰 추출 후 비교.  
• 패키지 명령은 라인만 수집하여 비교는 외부 DB에서 수행.

### 테스트 계획
• 유닛:  
  - 커널 버전 파서 및 버전 비교 테스트.  
  - 명령 실패/미존재 처리 테스트.
• 통합(선택): `fixtures/` 샘플 출력으로 로컬 폴백 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-64 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u64"],
    "scan_config": {
      "remote_kisa_u64": {
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
