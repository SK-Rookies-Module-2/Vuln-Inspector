U-60: SNMP Community String 복잡성 설정
• 중요도: 중
• 점검 목적: SNMP v1/v2c 사용 시 기본 커뮤니티 스트링(public, private) 사용 금지 및 복잡성 요구.
• 보안 위협: 기본값 사용 시 공격자가 손쉽게 시스템 정보를 획득하거나 설정을 변경할 수 있음.
상세 점검 로직 (Scripting Guide)
• 파일: /etc/snmp/snmpd.conf
• 로직:
    ◦ rocommunity, rwcommunity 설정값 확인.
    ◦ public, private 문자열이 포함되어 있으면 취약.
