U-57: Ftpusers 파일 설정
• 중요도: 중
• 점검 목적: FTP 접속 제한 계정 목록 파일(ftpusers)에 root 등 중요 계정이 포함되어 있는지 확인.
• 보안 위협: root 계정의 FTP 직접 접속 허용 시 관리자 비밀번호 노출 및 권한 탈취 위험이 큼.
상세 점검 로직 (Scripting Guide)
• 파일: /etc/ftpusers, /etc/vsftpd/ftpusers, /etc/proftpd.ftpusers 등
• 로직:
    ◦ 해당 파일 내에 root 계정이 명시되어 있는지 확인.
    ◦ 없으면(주석 처리 포함) 취약.