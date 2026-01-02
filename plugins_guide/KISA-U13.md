U-13: 안전한 비밀번호 암호화 알고리즘 사용
• 중요도: 중
• 점검 목적: 패스워드 저장 시 취약한 해시 알고리즘(MD5 등) 대신 안전한 알고리즘(SHA-256 이상) 사용 여부 확인.
• 보안 위협: 취약한 알고리즘 사용 시 해시값이 유출되었을 때 복호화(Cracking)될 가능성이 높음.
점검 대상 및 판단 기준
• 양호: SHA-256 이상의 암호화 알고리즘을 사용하는 경우 (예: $5, $6 등).
• 취약: MD5(1),Blowfish(2a) 등 취약하거나 낮은 수준의 암호화를 사용하는 경우.
OS별 상세 점검 로직 (Scripting Guide)
1) Linux
• 파일: /etc/login.defs (Redhat 계열), /etc/pam.d/common-password (Debian 계열)
• 점검 로직:
    ◦ /etc/login.defs 내 ENCRYPT_METHOD 값이 SHA512인지 확인.
    ◦ 또는 PAM 설정에 sha512 옵션이 적용되어 있는지 확인.
2) Solaris
• 파일: /etc/security/policy.conf
• 점검 로직: CRYPT_DEFAULT=6 (SHA-512) 또는 5 (SHA-256) 설정 확인.
3) AIX
• 파일: /etc/security/login.cfg
• 점검 로직: pwd_algorithm 값이 ssha256 또는 ssha512 인지 확인.