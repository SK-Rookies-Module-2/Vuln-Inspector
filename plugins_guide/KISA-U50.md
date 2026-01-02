U-50: DNS Zone Transfer 설정
• 중요도: 상
• 점검 목적: 비인가자에게 DNS Zone 정보(전체 도메인 목록, IP 등) 전송 차단.
• 보안 위협: Zone Transfer가 허용되면 공격자가 네트워크 구조를 파악하여 공격 표면을 넓힐 수 있음.
점검 대상 및 판단 기준
• 양호: Zone Transfer가 허가된 사용자(Secondary DNS)에게만 허용된 경우.
• 취약: 임의의 사용자에게 Zone Transfer가 허용된 경우.
상세 점검 로직 (Scripting Guide)
• 파일: /etc/named.conf 또는 /etc/bind/named.conf.options
• 로직:
    ◦ allow-transfer 구문 확인.
    ◦ { any; } 로 설정되어 있거나 설정이 아예 없으면(기본값 allow) 취약.
    ◦ { none; } 이거나 특정 IP(x.x.x.x)만 명시되어야 함.
