U-30: UMASK 설정

- 중요도: 중
- 점검 목적: 로그인 시 기본 파일/디렉터리 생성 권한이 과도하게 널널해지는 것을 막기 위해 umask를 표준값(022)으로 강제한다.
- 보안 위협: umask가 낮으면 신규 파일/디렉터리가 666/777 등으로 생성되어 민감 정보가 노출될 수 있다.

점검 대상 및 판단 기준

- 대상: Linux (로그인 시 /etc/profile, /etc/login.defs를 사용하는 시스템)
- 양호: /etc/profile, /etc/login.defs 두 곳 모두 UMASK가 권고값(기본 022)으로 설정
- 취약: UMASK 누락, 공란, 또는 두 파일 중 하나라도 권고값과 불일치

준비물

- 대상 서버 SSH 접속 정보(host, port, username, key_path 또는 password)
- sudo 필요 시 use_sudo, sudo_user 설정

OS별 상세 점검 로직 (Scripting Guide)

1. Linux
   • /etc/profile: `umask 022` 및 `export umask` 여부 확인(주석/공백 제거 후 umask 값 추출)
   • /etc/login.defs: `UMASK 022` 확인
   • 두 파일 중 하나라도 값이 권고값과 다르거나 누락되면 취약
   • 운영 관행상 두 파일을 모두 동일하게 설정해야 실제 적용 누락을 방지할 수 있음

---

## 구현 설계

### 플러그인 형태

- 채널: remote (SSH 기반 원격 파일 확인)
- 대상: TargetType.SERVER
- 플러그인 위치(예시): `plugins/remote/linux_kisa_u30_umask_policy/`
- 플러그인 ID/클래스: remote_linux_kisa_u30_umask / LinuxKisaU30UmaskPolicy

### plugin.yml 설계(예시)

```yaml
id: 'remote_linux_kisa_u30_umask'
name: 'KISA U-30 UMASK 설정 점검'
version: '0.1.0'
type: 'remote'
category: 'infrastructure'
tags:
  - 'KISA:U-30'
description: '/etc/profile과 /etc/login.defs의 UMASK가 권고값(기본 022)인지 점검합니다.'
config_schema:
  properties:
    profile_path:
      type: string
      default: '/etc/profile'
    login_defs_path:
      type: string
      default: '/etc/login.defs'
    expected_umask:
      type: string
      default: '022'
      description: 'KISA U-30 권고 UMASK 값'
entry_point: 'main.py'
class_name: 'LinuxKisaU30UmaskPolicy'
```

### 점검 흐름

1. 입력값 정리
   - `expected_umask` 기본값은 "022". 공란이면 `PluginConfigError`.
2. 파일 읽기
   - SSH 자격이 있으면 `/etc/profile`, `/etc/login.defs`를 `cat`으로 읽음. 없으면 None 처리(로컬 폴백 없음).
3. 파싱
   - 주석/공백 제거 후 `parse_kv_lines`로 key/value 파싱.
   - `umask` 또는 `UMASK` 키를 찾아 문자열로 추출(첫 번째 값 사용).
4. 정책 계산
   - `effective_policy = { profile_umask, login_defs_umask }`로 구성.
5. 판정
   - `diagnose_policy`로 두 항목이 모두 `expected_umask`와 `==`인지 확인. 누락(None)도 실패로 간주.
6. 결과 기록
   - `build_report`로 요약/가이드 문구 생성, `severity`는 미준수 시 High, 충족 시 Info.
   - `add_finding(vuln_id="KISA-U-30", tags=["KISA:U-30"], evidence=파일 경로·라인·파싱 값·effective_policy·diagnose)`

### 파서 설계(요약)

- `ssh_read_config`에서 공백/주석/inline 주석을 제거한 라인만 전달.
- `parse_kv_lines`로 `key=value` 또는 `key value` 형태 모두 파싱.
- `extract_umask`는 `umask`/`UMASK` 키를 찾아 공백 제거 후 반환. 없으면 None.

### 설정 예시 (빠른 실행)

#### 1) Target 등록 예시

```json
{
  "connection_info": { "host": "10.0.0.5", "port": 22 },
  "credentials": { "username": "ubuntu", "key_path": "~/.ssh/id_rsa" }
}
```

#### 2) Job 실행 예시 (기본값 사용)

```json
{
  "target_id": 1,
  "scan_scope": ["remote_linux_kisa_u30_umask"],
  "scan_config": {}
}
```

#### 3) 권고값 변경 예시 (예: 027로 강화)

```json
{
  "target_id": 1,
  "scan_scope": ["remote_linux_kisa_u30_umask"],
  "scan_config": {
    "remote_linux_kisa_u30_umask": {
      "expected_umask": "027"
    }
  }
}
```

### 테스트 계획

- 유닛: `extract_umask`, `diagnose_policy` 경계값 테스트(누락/공백/소문자 umask 등).
- 픽스처: `/etc/profile`, `/etc/login.defs` 샘플을 `fixtures/`에 두고 정상/취약 케이스 검증.
- 통합(선택): SSH 자격이 없는 경우 None 처리 동작 확인.

### 실제 환경 테스트 절차 (ProxyCommand 경유 예시)

#### 1) Target 등록

```bash
curl -X POST http://127.0.0.1:8000/api/v1/targets \
  -H "Content-Type: application/json" \
  -d '{
    "name": "aws-private-ubuntu-u30",
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
    "description": "AWS private subnet Ubuntu via bastion (U-30)"
  }'
```

#### 2) Job 실행 (기본값 022)

```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_linux_kisa_u30_umask"],
    "scan_config": {}
  }'
```

#### 3) Job 실행 (권고값 강화 예: 027)

```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_scope": ["remote_linux_kisa_u30_umask"],
    "scan_config": {
      "remote_linux_kisa_u30_umask": {
        "expected_umask": "027"
      }
    }
  }'
```

#### 4) 결과 확인

```bash
curl http://127.0.0.1:8000/api/v1/jobs/1/findings
```

_`target_id`/`jobs/{id}`는 실제 반환된 ID로 교체_
