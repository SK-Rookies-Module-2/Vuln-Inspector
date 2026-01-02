U-55: FTP 계정 Shell 제한
• 중요도: 중
• 점검 목적: FTP 접속 전용 계정에 쉘(/bin/false 등)을 부여하여 시스템 로그인을 차단.
• 보안 위협: FTP 계정에 일반 쉘이 부여되면 시스템에 직접 로그인하여 불필요한 명령어를 실행할 수 있음.
상세 점검 로직 (Scripting Guide)
• 파일: /etc/passwd
• 로직:
    ◦ ftp 계정의 쉘 설정 확인.
    ◦ /bin/false 또는 /sbin/nologin이 아니면 취약