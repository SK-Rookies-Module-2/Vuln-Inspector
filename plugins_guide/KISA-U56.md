U-56: FTP 서비스 접근 제어 설정
• 중요도: 하
• 점검 목적: ftpusers 파일 등을 통해 FTP 접속을 허용하지 않을 계정을 등록하거나 특정 IP만 접속 허용.
• 보안 위협: 접근 제어가 없을 경우 무차별 대입 공격 등에 노출될 수 있음.
상세 점검 로직 (Scripting Guide)
• vsFTP: userlist_enable=YES 및 userlist_deny 설정 확인. /etc/vsftpd.ftpusers 등 접근 제어 파일 설정 여부 확인.
• ProFTP: Limit LOGIN 설정 확인.
• TCP Wrapper: /etc/hosts.allow, /etc/hosts.deny 설정 확인.
