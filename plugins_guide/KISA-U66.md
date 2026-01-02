U-66: 정책에 따른 시스템 로깅 설정
• 중요도: 중
• 점검 목적: 주요 이벤트(인증, 에러 등)가 적절히 로깅되도록 설정.
• 보안 위협: 로그가 남지 않으면 침해 사고 추적이 불가능함.
상세 점검 로직 (Scripting Guide)
• 파일: /etc/syslog.conf 또는 /etc/rsyslog.conf
• 로직:
    ◦ *.info, authpriv.*, mail.*, cron.*, *.alert, *.emerg 등의 주요 로그 레벨이 설정되어 있는지 확인.
    ◦ 예시: *.info;mail.none;authpriv.none;cron.none /var/log/messages