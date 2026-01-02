U-38: DoS 공격에 취약한 서비스 비활성화
• 중요도: 상
• 점검 목적: echo, discard, daytime, chargen 등 DoS 공격에 악용될 수 있는 단순 TCP/UDP 서비스를 차단.
• 보안 위협: 해당 서비스들은 트래픽 증폭 공격(Amplification Attack) 등에 악용될 수 있음.
점검 대상 및 판단 기준
• 양호: 해당 서비스들이 비활성화된 경우.
• 취약: 해당 서비스들이 활성화된 경우.
상세 점검 로직 (Scripting Guide)
• Inetd/Xinetd 확인:
    ◦ 파일: /etc/inetd.conf, /etc/xinetd.d/echo, /etc/xinetd.d/discard, /etc/xinetd.d/daytime, /etc/xinetd.d/chargen
    ◦ 로직: 주석 처리되지 않았거나 disable = no인 경우 취약.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 설정 파일 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u38/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u38"
name: "DoS-Prone Service Disable Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-38"
description: "Check whether echo/discard/daytime/chargen services are disabled."
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
    services:
      type: array
      default:
        - "echo"
        - "discard"
        - "daytime"
        - "chargen"
    check_inetd:
      type: boolean
      default: true
    check_xinetd:
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
class_name: "DosServiceDisableCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. inetd/xinetd 경로와 서비스 목록 기본값 적용.  
• `check_inetd`/`check_xinetd`로 점검 범위 선택.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 확인 허용.
3) inetd.conf 점검  
• 주석 제거 후 서비스명이 대상 목록에 포함된 라인이 있으면 취약.  
• 파일이 없으면 해당 경로는 양호로 처리.
4) xinetd 점검  
• `/etc/xinetd.d/<service>` 파일에서 `disable = yes`가 아니면 취약.  
• 파일이 없으면 해당 경로는 양호로 처리.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-38"`, `severity="High"`  
  - `tags=["KISA:U-38"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `checked_sources`, `missing_files`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• inetd.conf: 주석 제거 후 첫 토큰의 서비스명이 대상 목록에 포함되면 활성으로 판단.  
• xinetd: `disable = yes` 확인(없거나 yes가 아니면 활성으로 판단).

### 테스트 계획
• 유닛:  
  - inetd/xinetd 설정 파서 테스트.  
  - 서비스 목록 매칭 및 결과 집계 테스트.  
  - 파일 미존재/읽기 실패 처리 테스트.
• 통합(선택): 로컬 폴백으로 샘플 설정 파일 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-38 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u38"],
    "scan_config": {
      "remote_kisa_u38": {
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
