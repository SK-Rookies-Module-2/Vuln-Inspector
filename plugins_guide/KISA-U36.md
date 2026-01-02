U-36: r 계열 서비스 비활성화
• 중요도: 상
• 점검 목적: rlogin, rsh, rexec 등 인증 없이 관리자 접속이 가능한 취약한 서비스를 차단.
• 보안 위협: r-command는 인증 과정이 취약하여 IP 스푸핑 공격 등에 악용될 수 있음.
점검 대상 및 판단 기준
• 양호: r 계열 서비스가 비활성화된 경우.
• 취약: r 계열 서비스가 활성화된 경우.
상세 점검 로직 (Scripting Guide)
• Inetd/Xinetd 확인:
    ◦ 파일: /etc/inetd.conf, /etc/xinetd.d/rlogin, /etc/xinetd.d/rsh, /etc/xinetd.d/rexec
    ◦ 로직: disable = yes가 아니거나 inetd.conf 내 주석 처리되지 않은 라인이 있으면 취약.
• Systemd/Service 확인:
    ◦ 명령어: systemctl list-unit-files | grep -E 'rlogin|rsh|rexec'
    ◦ 로직: 상태가 enabled 또는 active이면 취약.
• 프로세스 확인: ps -ef | grep -E "rlogind|rshd|rexecd"