U-53: FTP 서비스 정보 노출 제한
• 중요도: 하
• 점검 목적: FTP 접속 시 출력되는 배너 정보를 제한하여 서버 버전 등의 불필요한 정보 노출 방지.
• 보안 위협: 버전 정보 노출 시 해당 버전의 알려진 취약점을 이용한 공격 시도가 가능함.
상세 점검 로직 (Scripting Guide)
• vsFTP:
    ◦ 파일: /etc/vsftpd.conf
    ◦ 로직: ftpd_banner 설정이 주석 처리되어 있거나 기본값인 경우 확인.
• ProFTP:
    ◦ 파일: /etc/proftpd.conf
    ◦ 로직: ServerIdent 설정이 off가 아니거나 버전 정보를 포함하는 경우 확인.