U-52: Telnet 서비스 비활성화
• 중요도: 중
• 점검 목적: 보안에 취약한 Telnet 서비스를 비활성화하고 SSH 사용을 권장함.
• 보안 위협: Telnet은 평문 통신을 하므로 계정 정보 및 중요 데이터가 스니핑(Sniffing) 될 위험이 있음.
상세 점검 로직 (Scripting Guide)
• Inetd/Xinetd 확인:
    ◦ /etc/inetd.conf 내 telnet 라인이 주석 처리되지 않았으면 취약.
    ◦ /etc/xinetd.d/telnet 파일 내 disable = yes가 아니면 취약.
• Systemd 확인:
    ◦ systemctl list-units --type=socket | grep telnet 확인. 활성화 시 취약.