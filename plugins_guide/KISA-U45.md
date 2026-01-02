U-45: 메일 서비스 버전 점검
• 중요도: 상
• 점검 목적: Sendmail, Postfix 등의 메일 서비스 버전을 최신으로 유지하여 알려진 취약점 방어.
• 보안 위협: 구버전 Sendmail은 버퍼 오버플로우 등 심각한 원격 실행 취약점을 다수 내포함.
점검 대상 및 판단 기준
• 양호: 메일 서비스를 사용하지 않거나, 최신 패치가 적용된 버전을 사용하는 경우.
• 취약: 취약한 구버전 메일 서비스를 사용하는 경우.
상세 점검 로직 (Scripting Guide)
• Sendmail: sendmail -d0.1 < /dev/null | grep Version 명령어로 버전 확인.
• Postfix: postconf mail_version 명령어로 버전 확인.
• 조치: 벤더사 권고 최신 버전이 아니면 취약.