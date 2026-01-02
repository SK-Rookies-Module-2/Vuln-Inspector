U-23: SUID, SGID, Sticky bit 설정 파일 점검
• 중요도: 상
• 점검 목적: 불필요한 특수 권한(SetUID, SetGID)이 설정된 파일을 식별하여 권한 상승 공격 방지.
• 보안 위협: 취약한 SUID 파일 실행 시 root 권한을 탈취당할 수 있음.
점검 대상 및 판단 기준
• 양호: 주요 실행 파일 외에 불필요한 SUID/SGID가 설정되어 있지 않은 경우.
• 취약: 불필요하거나 악의적인 파일에 SUID/SGID가 설정된 경우.
상세 점검 로직 (Scripting Guide)
• 명령어: find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -ls
• 로직:
    1. 시스템 전역에서 SUID(4000), SGID(2000)가 설정된 파일 검색.
    2. 화이트리스트 비교: /usr/bin/passwd, /usr/bin/su, /bin/ping 등 OS 구동에 필수적인 잘 알려진 파일은 제외.
    3. 그 외의 경로(특히 /tmp, /var, /home 등)에서 발견된 SUID 파일은 취약 가능성 높음으로 리포팅.
