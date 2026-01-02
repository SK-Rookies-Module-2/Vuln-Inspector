U-67: 로그 파일 소유자 및 권한 설정

- 중요도: 중
- 점검 목적: /var/log 내 주요 로그 파일이 적절한 소유자(root)와 권한(0644 이하)로 설정되어 무단 열람·변조를 방지하도록 한다.
- 보안 위협: 로그 파일 소유자/권한이 느슨하면 중요 기록이 삭제·변조되거나 개인정보가 노출될 수 있다.

점검 대상 및 판단 기준

- 대상: Linux (`/var/log` 사용 시스템)
- 양호: /var/log 내 로그 파일의 소유자가 root이고 권한이 0644 이하
- 취약: 소유자가 root가 아니거나 권한이 0644 초과(예: 0666, 0777)인 로그 파일이 존재

준비물

- 대상 서버 SSH 접속 정보(host, port, username, key_path 또는 password)
- sudo 필요 시 use_sudo, sudo_user 설정

OS별 상세 점검 로직 (Scripting Guide)

1. Linux
   • find로 /var/log 상위(기본 depth 1) 파일을 수집: `find /var/log -maxdepth 1 -type f -printf '%p\t%u\t%#m\n'`
   • 소유자가 root가 아닌 파일을 취약 목록에 추가
   • 권한이 0644를 초과(8진수 비교)하거나 파싱 불가 시 취약 목록에 추가
   • 취약 파일이 하나라도 있으면 취약

---

## 구현 설계

### 플러그인 형태

- 채널: remote (SSH 기반 원격 파일 확인)
- 대상: TargetType.SERVER
- 플러그인 위치: `plugins/remote/linux_kisa_u67_log_file_perm/`
- 플러그인 ID/클래스: remote_linux_kisa_u67_log_file_perm / LinuxKisaU67LogFilePerm

### plugin.yml 설계(실제 적용)

```yaml
id: 'remote_linux_kisa_u67_log_file_perm'
name: 'KISA U-67 로그 파일 소유자/권한 점검'
version: '0.1.0'
type: 'remote'
category: 'infrastructure'
tags:
  - 'KISA:U-67'
description: '/var/log 내 로그 파일의 소유자와 권한이 권고값(root, 0644)인지 점검합니다.'
config_schema:
  properties:
    log_dir:
      type: string
      default: '/var/log'
    max_depth:
      type: integer
      default: 1
      description: 'find 탐색 깊이 (기본: 상위 디렉터리만)'
    expected_owner:
      type: string
      default: 'root'
    max_mode:
      type: string
      default: '0644'
      description: '허용 최대 권한(8진수, 예: 0644)'
      pattern: '^[0-7]{3,4}$'
    use_sudo:
      type: boolean
      default: false
    sudo_user:
      type: string
entry_point: 'main.py'
class_name: 'LinuxKisaU67LogFilePerm'
```

### 점검 흐름

1. 입력값 정리
   - `log_dir` 기본 `/var/log`, `max_depth` 기본 1, `expected_owner` 기본 `root`
   - `max_mode`를 8진수로 파싱(실패 시 `PluginConfigError`)
2. 파일 목록 수집
   - SSH로 `find <log_dir> -maxdepth <n> -type f -printf '%p\t%u\t%#m\n'` 실행
   - 실행 실패 시 `PluginConfigError`
3. 파싱/판정
   - 각 라인에서 path/owner/mode 추출, mode를 8진수 정수로 변환
   - 소유자가 `expected_owner`가 아니면 취약 목록 추가
   - mode가 `max_mode` 초과이거나 파싱 불가면 취약 목록 추가
   - 취약 파일 존재 시 `severity="High"`, 없으면 `severity="Info"`
4. 결과 기록
   - `add_finding(vuln_id="KISA-U-67", tags=["KISA:U-67"])`
   - evidence: `log_dir`, 실행 명령, raw_output, 모든 파일 목록, 불일치(owner/mode) 목록, 기준값(expected_owner/max_mode)

### 테스트 계획

- 유닛: `_parse_find_output`, 권한 파싱(8진수), 기준 비교 경계값 테스트
- 통합(선택): 로컬/픽스처 `find` 출력 샘플을 사용해 owner/mode 불일치 검증

### 설정 예시 (빠른 실행)

#### 1) Target 등록 예시

```json
{
  "connection_info": { "host": "10.0.0.5", "port": 22 },
  "credentials": { "username": "ubuntu", "key_path": "~/.ssh/id_rsa" }
}
```

#### 2) Job 실행 예시 (기본값)

```json
{
  "target_id": 1,
  "scan_scope": ["remote_linux_kisa_u67_log_file_perm"],
  "scan_config": {}
}
```

#### 3) 결과 확인

```bash
curl http://127.0.0.1:8000/api/v1/jobs/1/findings
```

#### 4) 하위 디렉터리까지 점검 (depth 확장)

```json
{
  "target_id": 1,
  "scan_scope": ["remote_linux_kisa_u67_log_file_perm"],
  "scan_config": {
    "remote_linux_kisa_u67_log_file_perm": {
      "max_depth": 2
    }
  }
}
```

#### 5) 결과 확인

```bash
curl http://127.0.0.1:8000/api/v1/jobs/1/findings
```

### 실제 환경 테스트 예시 (AWS Private Subnet + Bastion)

#### 1) 키 파일 준비

```bash
chmod 600 ~/.ssh/bastion-server-key.pem
```

#### 2) Target 등록 (Bastion 경유)

```json
{
  "name": "aws-private-ubuntu-u67",
  "type": "SERVER",
  "connection_info": {
    "host": "10.7.143.237",
    "port": 22,
    "proxy_command": "ssh -i ~/.ssh/bastion-server-key.pem -o IdentitiesOnly=yes -W %h:%p ubuntu@44.251.33.188",
    "identities_only": true
  },
  "credentials": {
    "username": "ubuntu",
    "key_path": "~/.ssh/bastion-server-key.pem"
  },
  "description": "AWS private subnet Ubuntu via bastion (U-67)"
}
```

#### 3) Job 실행 (기본값)

```json
{
  "target_id": 1,
  "scan_scope": ["remote_linux_kisa_u67_log_file_perm"],
  "scan_config": {}
}
```

#### 4) 결과 확인

```bash
curl http://127.0.0.1:8000/api/v1/jobs/1/findings
```
