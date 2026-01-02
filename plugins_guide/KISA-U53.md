U-53: FTP 서비스 정보 노출 제한
• 중요도: 하
• 점검 목적: FTP 접속 시 출력되는 배너 정보를 제한하여 서버 버전 등의 불필요한 정보 노출 방지.
• 보안 위협: 버전 정보 노출 시 해당 버전의 알려진 취약점을 이용한 공격 시도가 가능함.
상세 점검 로직 (Scripting Guide)
• vsFTP:
    ◦ 파일: /etc/vsftpd.conf
    ◦ 로직: ftpd_banner 설정이 주석 처리되어 있거나 기본값인 경우 확인.
• ProFTP:
    ◦ 파일: /etc/proftpd.conf
    ◦ 로직: ServerIdent 설정이 off가 아니거나 버전 정보를 포함하는 경우 확인.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 파일 내용 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u53/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u53"
name: "FTP Banner Exposure Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-53"
description: "Check FTP banner configuration for vsftpd/proftpd."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    check_vsftpd:
      type: boolean
      default: true
    vsftpd_conf_paths:
      type: array
      default:
        - "/etc/vsftpd.conf"
        - "/etc/vsftpd/vsftpd.conf"
    check_proftpd:
      type: boolean
      default: true
    proftpd_conf_path:
      type: string
      default: "/etc/proftpd/proftpd.conf"
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
class_name: "FtpBannerExposureCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. vsftpd/proftpd 설정 경로 기본값 제공.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 파일 확인 허용.
3) vsftpd 점검  
• `ftpd_banner` 설정이 없거나 기본값(버전 노출)인 경우 취약.  
• 사용자 정의 배너면 양호.
4) proftpd 점검  
• `ServerIdent`가 off가 아니거나 버전 정보를 포함하면 취약.  
• `ServerIdent off`면 양호.
5) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-53"`, `severity="Low"`  
  - `tags=["KISA:U-53"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `checked_files`, `missing_files`, `partial_errors`  
• 점검 불가 시 `Info` Finding 기록.

### 파서 설계(요약)
• 주석(#/;) 제거 후 키-값 라인 파싱.  
• vsftpd: `ftpd_banner` 미설정/기본값 여부 확인.  
• proftpd: `ServerIdent` 값이 off인지, 버전 키워드 포함 여부 확인.

### 테스트 계획
• 유닛:  
  - vsftpd 배너 파서 및 기본값 판정 테스트.  
  - proftpd ServerIdent 파서 및 off 판정 테스트.  
  - 파일 미존재/오류 처리 테스트.
• 통합(선택): `fixtures/` 샘플 설정 파일로 로컬 폴백 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-53 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u53"],
    "scan_config": {
      "remote_kisa_u53": {
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
