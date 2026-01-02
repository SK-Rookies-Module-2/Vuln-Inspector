U-38: DoS 공격에 취약한 서비스 비활성화
• 중요도: 상
• 점검 목적: echo, discard, daytime, chargen 등 DoS 공격에 악용될 수 있는 단순 TCP/UDP 서비스를 차단.
• 보안 위협: 해당 서비스들은 트래픽 증폭 공격(Amplification Attack) 등에 악용될 수 있음.
점검 대상 및 판단 기준
• 양호: 해당 서비스들이 비활성화된 경우.
• 취약: 해당 서비스들이 활성화된 경우.
상세 점검 로직 (Scripting Guide)
• Inetd/Xinetd 확인:
    ◦ 파일: /etc/inetd.conf, /etc/xinetd.d/echo, /etc/xinetd.d/discard, /etc/xinetd.d/daytime, /etc/xinetd.d/chargen
    ◦ 로직: 주석 처리되지 않았거나 disable = no인 경우 취약.