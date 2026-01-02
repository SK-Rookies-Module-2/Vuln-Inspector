U-61: SNMP Access Control 설정
• 중요도: 상
• 점검 목적: SNMP 서비스에 접근할 수 있는 IP(Manager)를 제한.
• 보안 위협: 접근 통제가 없으면 임의의 사용자가 SNMP 쿼리를 통해 정보를 수집할 수 있음.
상세 점검 로직 (Scripting Guide)
• 파일: /etc/snmp/snmpd.conf
• 로직:
    ◦ com2sec, rocommunity 등의 설정에 특정 IP/Network 제한이 있는지 확인.
    ◦ default 또는 0.0.0.0 허용 시 취약.