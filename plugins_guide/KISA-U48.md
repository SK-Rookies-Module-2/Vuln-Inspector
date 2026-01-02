U-48: expn, vrfy 명령어 제한
• 중요도: 중
• 점검 목적: SMTP 명령어 중 사용자 계정 유무를 확인하는 expn, vrfy 명령어 차단.
• 보안 위협: 공격자가 해당 명령어로 유효한 사용자 계정을 수집하여 비밀번호 대입 공격에 활용 가능.
점검 대상 및 판단 기준
• 양호: SMTP 서비스 미사용 또는 noexpn, novrfy 옵션이 설정된 경우.
• 취약: 해당 옵션이 설정되지 않은 경우.
상세 점검 로직 (Scripting Guide)
• Sendmail:
    ◦ 파일: /etc/mail/sendmail.cf
    ◦ 로직: O PrivacyOptions= 라인에 noexpn, novrfy (또는 goaway)가 포함되어 있는지 확인.