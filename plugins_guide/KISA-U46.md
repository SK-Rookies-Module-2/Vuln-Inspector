U-46: 일반 사용자의 메일 서비스 실행 방지
• 중요도: 상
• 점검 목적: 일반 사용자가 메일 큐를 조작하지 못하도록 설정(Sendmail restrictqrun 옵션).
• 보안 위협: 일반 사용자가 메일 큐를 조작하여 서비스 거부 공격을 유발할 수 있음.
점검 대상 및 판단 기준
• 양호: SMTP 서비스 미사용 또는 restrictqrun 옵션이 설정된 경우.
• 취약: SMTP 서비스 사용 시 해당 옵션이 없는 경우.
상세 점검 로직 (Scripting Guide)
• Sendmail:
    ◦ 파일: /etc/mail/sendmail.cf
    ◦ 로직: O PrivacyOptions= 라인에 restrictqrun이 포함되어 있는지 확인.