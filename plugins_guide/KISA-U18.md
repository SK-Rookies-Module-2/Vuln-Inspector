U-18: /etc/shadow 파일 소유자 및 권한 설정
• 중요도: 상
• 점검 목적: 패스워드 해시 파일의 유출 방지.
• 보안 위협: 해시 파일이 유출되면 오프라인 크래킹 공격(John the Ripper 등)에 노출됨.
점검 대상 및 판단 기준
• 양호: 소유자가 root이고, 권한이 400(또는 000) 이하인 경우.
• 취약: 권한이 400을 초과하거나 소유자가 root가 아닌 경우.
상세 점검 로직 (Scripting Guide)
1) Linux, Solaris
• 파일: /etc/shadow
• 로직: Owner: root, Perm: 400 (-r--------) 또는 000 확인.
2) AIX
• 파일: /etc/security/passwd
• 로직: Owner: root, Perm: 400 확인.
3) HP-UX
• 파일: /tcb/files/auth (Trusted Mode), /etc/shadow
• 로직: Owner: root, Perm: 400 확인.