U-06: 사용자 계정 su 기능 제한
• 중요도: 상
• 점검 목적: 일반 사용자가 su 명령어를 통해 무분별하게 root 권한을 획득하는 것을 방지.
• 보안 위협: 불필요한 계정이 관리자 권한을 획득할 위험이 있음.
점검 대상 및 판단 기준
• 양호: 특정 그룹(예: wheel)에 속한 사용자만 su 명령어를 사용할 수 있는 경우.
• 취약: 모든 사용자가 su 명령어를 사용할 수 있는 경우.
OS별 상세 점검 로직 (Scripting Guide)
1) Solaris, AIX, HP-UX
• 점검:
    ◦ 파일: /usr/bin/su 권한 확인.
    ◦ 로직: 파일 권한이 4750이며, 그룹이 wheel(또는 관리자 그룹)로 설정되어 있는지 확인.
2) Linux
• PAM 모듈 미사용 시:
    ◦ 파일: /usr/bin/su
    ◦ 로직: 권한 4750, 그룹 wheel 확인.
• PAM 모듈 사용 시:
    ◦ 파일: /etc/pam.d/su
    ◦ 로직: auth required pam_wheel.so use_uid 설정이 주석 처리되지 않고 존재하는지 확인

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u06/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u06"
name: "SU Access Restriction Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-06"
description: "Check whether su is restricted to privileged group users."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    su_path:
      type: string
    pam_su_path:
      type: string
    privileged_group:
      type: string
      default: "wheel"
    use_sudo:
      type: boolean
      default: false
    sudo_user:
      type: string
    allow_local_fallback:
      type: boolean
      default: false
entry_point: "main.py"
class_name: "SuAccessRestrictionCheck"
```

### OS별 기본 경로(코드 내 기본값)
• 공통: `su_path=/usr/bin/su`  
• linux: `pam_su_path=/etc/pam.d/su`

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. OS별 경로 오버라이드는 있으면 사용, 없으면 기본값 적용.  
• `privileged_group` 기본값은 `wheel`.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 읽기/권한 확인 허용.
3) Linux PAM 점검  
• `/etc/pam.d/su`를 `cat`으로 읽어 주석/공백 라인을 제거.  
• `pam_wheel.so`가 포함되고 `use_uid`가 있는 `auth` 라인이 있으면 양호.  
• PAM 파일이 없거나 해당 라인이 없으면 4)로 이동.
4) su 바이너리 권한/그룹 점검  
• `/usr/bin/su` 권한이 `4750`이고 그룹이 `privileged_group`인지 확인.  
• 권한/그룹이 다르면 취약.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-06"`, `severity="High"`  
  - `title`에 OS 포함(예: "Linux su 기능 제한 미흡")  
  - `tags=["KISA:U-06"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `line`, `mode(remote/local)`, `host`, `source(pam|permission)`
• 파일 접근 실패 시 `Info`로 "점검 불가" Finding 기록.

### 파서 설계(요약)
• PAM: 주석/공백 라인 제거 후 `auth` 스택에서 `pam_wheel.so` + `use_uid` 포함 라인을 탐색.  
• 권한: `stat` 출력(권한 숫자/그룹) 파싱. `stat` 미지원 시 `ls -ld`로 대체 파싱.  
• 로컬 폴백: `os.stat()`의 `st_mode`로 권한, `grp.getgrgid()`로 그룹 이름 확인.

### 테스트 계획
• 유닛:  
  - PAM 라인 파서 정상/주석 처리/옵션 누락 케이스.  
  - 권한/그룹 파서(`stat`/`ls -ld`) 변형 케이스.  
• 통합(선택): `fixtures/`에 샘플 `/etc/pam.d/su`와 `ls -ld` 출력 샘플을 두고 `allow_local_fallback=true` 경로 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-06 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u06"],
    "scan_config": {
      "remote_kisa_u06": {
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
