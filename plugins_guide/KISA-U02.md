U-02: 비밀번호 복잡성 및 이력 관리 정책
- 중요도: 상
- 점검 목적: 비밀번호 추측·대입 공격 및 재사용 위험을 줄이기 위해 복잡성, 사용 기간, 재사용 제한을 강제한다.
- 보안 위협: 짧거나 단순한 비밀번호, 장기 미변경, 반복 재사용 시 계정 탈취 가능성이 크게 높아진다.

점검 대상 및 판단 기준
- 대상: Linux(PAM/pwquality 사용 서버)
- 양호: 비밀번호 복잡도, 길이, 최소/최대 사용 기간, 최근 이력 금지 설정이 권고값을 충족
- 취약: 위 항목 중 하나라도 권고값을 만족하지 않거나 미설정

OS별 상세 점검 로직 (Scripting Guide)
1) Debian/Ubuntu 등 PAM 기반 Linux
   - 파일: /etc/security/pwquality.conf 또는 pam_pwquality.so 옵션
     - minlen >= 8
     - lcredit, ucredit, dcredit, ocredit 각각 -1 이하 (소문자/대문자/숫자/특수문자 최소 1자 요구)
     - difok >= 1
   - 파일: /etc/pam.d/common-password
     - pam_pwhistory.so 또는 pam_unix.so 옵션 remember >= 4
   - 파일: /etc/login.defs
     - PASS_MIN_DAYS >= 1
     - PASS_MAX_DAYS <= 90
   - 종합: pam_pwquality/pam_pwhistory 모듈이 pam_unix.so보다 위에 위치하는지 확인

---

## 구현 설계

### 플러그인 형태
- 채널: remote (SSH 기반 원격 파일 확인, 로컬 폴백)
- 대상: TargetType.SERVER
- 플러그인 위치(예시): plugins/remote/linux_kisa_u02_password_policy/
- 플러그인 ID/클래스: remote_linux_kisa_u02 / LinuxKisaU02PasswordPolicy

### plugin.yml 설계(예시)
```yaml
id: "remote_linux_kisa_u02"
name: "KISA U-02 비밀번호 정책 점검"
version: "0.1.0"
type: "remote"
category: "infrastructure"
tags:
  - "KISA:U-02"
description: "pwquality.conf, common-password, login.defs 기반 비밀번호 정책 점검"
config_schema:
  properties:
    pwquality_path:
      type: string
      default: "/etc/security/pwquality.conf"
    common_password_path:
      type: string
      default: "/etc/pam.d/common-password"
    login_defs_path:
      type: string
      default: "/etc/login.defs"
    required_settings:
      type: object
      default:
        lcredit: -1
        ucredit: -1
        dcredit: -1
        ocredit: -1
        minlen: 8
        PASS_MIN_DAYS: 1
        PASS_MAX_DAYS: 90
        remember: 4
        difok: 1
entry_point: "main.py"
class_name: "LinuxKisaU02PasswordPolicy"
```

### 점검 흐름
1) 입력값 정리
   - 설정에서 파일 경로와 required_settings를 읽고 정수 변환 검증(required_settings 각 키 필수).
2) 파일 읽기
   - SSH 자격이 있으면 SshClient.run("cat <path>")으로 원격 파일 획득, 없으면 None 반환.
   - 세 파일 모두 읽기 실패 시 PluginConfigError.
3) 파싱
   - pwquality.conf: key=value 또는 key value 라인을 파싱해 dict 생성.
   - common-password: PAM 엔트리 파싱 후 password 스택에서 pam_pwquality.so, pam_pwhistory.so, pam_unix.so 옵션 추출.
   - login.defs: key value 파싱.
4) 정책 계산
   - pwquality.conf와 PAM 옵션을 병합해 difok, minlen, l/u/d/o credit 결정.
   - remember 값(pam_pwhistory 또는 pam_unix)과 PASS_MIN_DAYS, PASS_MAX_DAYS 적용.
5) 판정
   - required_settings의 op(<=, >= 등)에 따라 비교, 미설정 또는 기준 미달 항목을 failed 목록에 추가.
6) 결과 기록
   - add_finding(vuln_id="KISA-U-02", severity=High/Info)
   - evidence: 각 파일 경로와 파싱 결과, effective_policy, diagnose 상세
   - tags: ["KISA:U-02"]

### 파서 설계(요약)
- 공통: 공백/주석 라인 제거, inline 주석(#) 제거
- PAM 엔트리: ptype, control, module, options 분해; password 스택만 사용
- 옵션 병합 우선순위: PAM 옵션 > pwquality.conf 값

### 테스트 계획
- 유닛: 파서(pwquality, PAM), required_settings 검증, 진단 로직 경계값 테스트
- 픽스처: 샘플 pwquality.conf, common-password, login.defs 조합으로 정상/취약 케이스 검증
