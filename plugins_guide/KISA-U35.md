U-35: 공유 서비스에 대한 익명 접근 제한 설정
• 중요도: 상
• 점검 목적: FTP, SMB(Samba), NFS 등의 공유 서비스 이용 시 익명(Anonymous) 접속을 차단하여 불필요한 정보 유출 방지.
• 보안 위협: 익명 접속 허용 시 비인가자가 시스템에 접근하여 쓰기 권한이 있는 디렉터리에 악성코드를 업로드하거나 중요 정보를 탈취할 수 있음.
점검 대상 및 판단 기준
• 양호: 공유 서비스에 익명 접근이 제한된 경우.
• 취약: 공유 서비스에 익명 접근이 허용된 경우.
OS별 상세 점검 로직 (Scripting Guide)
1) FTP (vsftpd, ProFTPD, Default FTP)
• Linux (vsftpd):
    ◦ 파일: /etc/vsftpd.conf 또는 /etc/vsftpd/vsftpd.conf
    ◦ 로직: anonymous_enable 값이 NO인지 확인.
• Linux (ProFTPD):
    ◦ 파일: /etc/proftpd/proftpd.conf
    ◦ 로직: <Anonymous ~ftp> 섹션이 존재하면 취약으로 간주하거나 주석 처리 확인.
• Solaris/AIX/HP-UX (Default FTP):
    ◦ 파일: /etc/passwd
    ◦ 로직: ftp 또는 anonymous 계정이 존재하는지 확인. 존재하면 취약 가능성 있음 (계정 제거 권고).
2) Samba
• 공통:
    ◦ 파일: /etc/samba/smb.conf 또는 /usr/lib/smb.conf
    ◦ 로직: guest ok = yes 설정이 존재하는지 확인 (no여야 양호).
3) NFS
• 공통:
    ◦ 파일: /etc/exports (Linux/AIX/HP-UX) 또는 /etc/dfs/dfstab (Solaris)
    ◦ 로직: 옵션에 insecure가 있거나 anon 설정이 취약하게 되어 있는지 확인.

---

## 구현 설계

### 플러그인 형태
• 채널: remote (SSH 기반 원격 설정 파일 확인)  
• 대상: TargetType.SERVER  
• 플러그인 위치(권장): `plugins/remote/kisa_u35/`

### plugin.yml 설계(예시)
```yaml
id: "remote_kisa_u35"
name: "Anonymous Access Restriction Check"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-35"
description: "Check anonymous access settings for FTP/Samba/NFS."
config_schema:
  required:
    - os_type
  properties:
    os_type:
      type: string
      enum: ["linux", "solaris", "aix", "hpux"]
    passwd_path:
      type: string
      default: "/etc/passwd"
    check_ftp_accounts:
      type: boolean
      default: true
    ftp_account_names:
      type: array
      default:
        - "ftp"
        - "anonymous"
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
    check_samba:
      type: boolean
      default: true
    samba_conf_paths:
      type: array
      default:
        - "/etc/samba/smb.conf"
        - "/usr/lib/smb.conf"
    check_nfs:
      type: boolean
      default: true
    nfs_export_paths:
      type: array
      default:
        - "/etc/exports"
        - "/etc/dfs/dfstab"
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
class_name: "AnonymousAccessRestrictionCheck"
```

### 점검 흐름
1) Target 검증  
• `context.target.type`이 SERVER가 아니면 `PluginConfigError`로 종료.
2) 입력값 정리  
• `os_type` 필수. 서비스별 설정 경로 기본값 제공.  
• 원격 접근 정보가 없고 `allow_local_fallback=true`이면 로컬 확인 허용.
3) FTP 익명 접근 점검  
• Linux: vsftpd `anonymous_enable` 값이 YES이면 취약.  
• Linux: ProFTPD `<Anonymous>` 섹션이 존재하면 취약.  
• Solaris/AIX/HP-UX: `/etc/passwd`에 `ftp`/`anonymous` 계정이 있으면 취약.
4) Samba 점검  
• `guest ok = yes` 설정이 있으면 취약.
5) NFS 점검  
• `/etc/exports` 또는 `/etc/dfs/dfstab` 라인에서 `insecure` 또는 `anon` 옵션이 있으면 취약.
6) 결과 기록  
• 취약 시 `add_finding()` 호출:  
  - `vuln_id="KISA-U-35"`, `severity="High"`  
  - `tags=["KISA:U-35"]`  
  - `evidence`: `os_type`, `config_path`, `detected_value`, `mode`, `host`, `count`, `checked_files`, `missing_files`, `partial_errors`  
• 모든 점검이 실패하면 `Info` Finding 기록.

### 파서 설계(요약)
• 주석(#, ;) 제거 후 라인 기준으로 설정을 검사.  
• vsftpd: `anonymous_enable`의 최종 값 확인.  
• ProFTPD: `<Anonymous ...>` 섹션 존재 여부 확인.  
• Samba: `guest ok = yes/true/1` 매칭.  
• NFS: `insecure`, `anon`, `anonuid`, `anongid`, `anon=` 키워드 매칭.

### 테스트 계획
• 유닛:  
  - vsftpd/proftpd/samba 설정 파서 테스트.  
  - NFS exports/dfstab 옵션 파서 테스트.  
  - ftp/anonymous 계정 탐지 및 오류 처리 테스트.  
• 통합(선택): `fixtures/` 샘플 설정 파일로 로컬 폴백 검증.

### 실제 환경 테스트 절차 (KISA-U01 대상 재사용)
#### 1) Target 확인
• KISA-U01 가이드에서 등록한 Target을 그대로 사용합니다.  
• `target_id`는 이전 응답의 `id`를 사용하세요.

#### 2) Job 실행 (U-35 점검)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_kisa_u35"],
    "scan_config": {
      "remote_kisa_u35": {
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
