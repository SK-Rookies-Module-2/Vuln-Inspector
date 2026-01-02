U-57: Ftpusers 파일 설정
• 중요도: 중
• 점검 목적: FTP 접속 제한 계정 목록 파일(ftpusers)에 root 등 중요 계정이 포함되어 있는지 확인.
• 보안 위협: root 계정의 FTP 직접 접속 허용 시 관리자 비밀번호 노출 및 권한 탈취 위험이 큼.
상세 점검 로직 (Scripting Guide)
• 파일: /etc/ftpusers, /etc/vsftpd/ftpusers, /etc/proftpd.ftpusers 등
• 로직:
    ◦ 해당 파일 내에 root 계정이 명시되어 있는지 확인.
    ◦ 없으면(주석 처리 포함) 취약.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일 내용 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u57/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u57"
name: "Ftpusers File Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-57"
description: "Check ftpusers files for root account entries."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    ftpusers_paths:
      type: array
      default:
        - "/etc/ftpusers"
        - "/etc/vsftpd/ftpusers"
        - "/etc/proftpd.ftpusers"
    required_users:
      type: array
      default:
        - "root"
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
class_name: "FtpusersFileCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. `ftpusers_paths`/`required_users` 기본값 제공.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 확인 허용.
3) 파일 확인  
• `ftpusers_paths`에서 파일을 읽고 주석(#/;) 제거 후 계정 목록 확인.  
• `required_users`(기본 root)가 포함되어 있지 않으면 취약.
4) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-57"`, `severity="Medium"`  
  - `tags=["KISA:U-57"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `checked_files`, `missing_files`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• 주석(#/;) 제거 후 첫 토큰이 계정명인지 확인.  
• `required_users` 목록과 매칭.

### 테스트 계획
• 유닛:  
  - 계정 파서 및 주석 처리 테스트.  
  - required_users 미포함 판정 테스트.  
  - 파일 미존재/오류 처리 테스트.
• 통합(선택): `fixtures/` 샘플 파일로 로컬 폴백 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-57 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u57"],
    "scan_config": {
      "remote_kisa_u57": {
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
