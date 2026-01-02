U-22: /etc/services 파일 소유자 및 권한 설정
• 중요도: 상
• 점검 목적: 포트와 서비스 매핑 파일의 변조 방지.
• 보안 위협: 파일 변조 시 정상적인 서비스를 제한하거나 허용되지 않은 포트를 악성 서비스에 연동할 수 있음.
점검 대상 및 판단 기준
• 양호: 소유자가 root(또는 bin, sys)이고, 권한이 644 이하인 경우.
• 취약: 소유자가 root(또는 bin, sys)가 아니거나, 권한이 644를 초과하는 경우.
상세 점검 로직 (Scripting Guide)
• 대상 파일: /etc/services
• 로직:
    1. ls -l /etc/services 실행.
    2. Owner: root, bin, sys 확인.
    3. Permission: 644 이하 (-rw-r--r--) 확인.