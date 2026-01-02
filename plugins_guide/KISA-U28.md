U-28: 접속 IP 및 포트 제한
• 중요도: 상
• 점검 목적: 허용된 IP에서만 서비스에 접속할 수 있도록 접근 제어 설정(TCP Wrapper, IPFilter 등).
• 보안 위협: 접근 제어가 없을 경우 불법적인 접속 및 침해사고 발생 가능.
점검 대상 및 판단 기준
• 양호: hosts.deny에 ALL:ALL 설정 후 hosts.allow에 필요 IP만 허용했거나, 방화벽(IPtables 등)을 사용 중인 경우.
• 취약: 접속 제한 설정이 없는 경우.
상세 점검 로직 (Scripting Guide)
• TCP Wrapper 점검:
    ◦ 파일: /etc/hosts.deny
    ◦ 내용: ALL:ALL (또는 모든 서비스 거부 설정) 확인.
    ◦ 파일: /etc/hosts.allow
    ◦ 내용: 정상 IP 등록 여부 확인.
• IPtables/FirewallD 점검:
    ◦ 명령어: iptables -L 또는 firewall-cmd --list-all
    ◦ 정책(Policy)이 DROP/REJECT 이거나 특정 규칙이 적용되어 있는지 확인.