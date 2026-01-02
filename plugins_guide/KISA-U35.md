U-35: 공유 서비스에 대한 익명 접근 제한 설정
• 중요도: 상
• 점검 목적: FTP, SMB(Samba), NFS 등의 공유 서비스 이용 시 익명(Anonymous) 접속을 차단하여 불필요한 정보 유출 방지.
• 보안 위협: 익명 접속 허용 시 비인가자가 시스템에 접근하여 쓰기 권한이 있는 디렉터리에 악성코드를 업로드하거나 중요 정보를 탈취할 수 있음.
점검 대상 및 판단 기준
• 양호: 공유 서비스에 익명 접근이 제한된 경우.
• 취약: 공유 서비스에 익명 접근이 허용된 경우.
OS별 상세 점검 로직 (Scripting Guide)
1) FTP (vsftpd, ProFTPD, Default FTP)
• Linux (vsftpd):
    ◦ 파일: /etc/vsftpd.conf 또는 /etc/vsftpd/vsftpd.conf
    ◦ 로직: anonymous_enable 값이 NO인지 확인.
• Linux (ProFTPD):
    ◦ 파일: /etc/proftpd/proftpd.conf
    ◦ 로직: <Anonymous ~ftp> 섹션이 존재하면 취약으로 간주하거나 주석 처리 확인.
• Solaris/AIX/HP-UX (Default FTP):
    ◦ 파일: /etc/passwd
    ◦ 로직: ftp 또는 anonymous 계정이 존재하는지 확인. 존재하면 취약 가능성 있음 (계정 제거 권고).
2) Samba
• 공통:
    ◦ 파일: /etc/samba/smb.conf 또는 /usr/lib/smb.conf
    ◦ 로직: guest ok = yes 설정이 존재하는지 확인 (no여야 양호).
3) NFS
• 공통:
    ◦ 파일: /etc/exports (Linux/AIX/HP-UX) 또는 /etc/dfs/dfstab (Solaris)
    ◦ 로직: 옵션에 insecure가 있거나 anon 설정이 취약하게 되어 있는지 확인.