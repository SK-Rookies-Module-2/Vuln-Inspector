U-44: tftp, talk 서비스 비활성화
• 중요도: 상
• 점검 목적: 인증 절차가 없는 Trivial FTP(tftp) 및 talk 서비스를 차단.
• 보안 위협: tftp는 인증 없이 파일을 다운로드/업로드할 수 있어 시스템 중요 파일 유출 위험이 매우 큼.
점검 대상 및 판단 기준
• 양호: tftp, talk, ntalk 서비스가 비활성화된 경우.
• 취약: 해당 서비스가 활성화된 경우.
상세 점검 로직 (Scripting Guide)
• Inetd/Xinetd 확인:
    ◦ 파일: /etc/inetd.conf, /etc/xinetd.d/tftp, /etc/xinetd.d/talk
    ◦ 로직: 주석 처리되지 않았거나 disable = no이면 취약.