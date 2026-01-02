U-65: NTP 및 시각 동기화 설정
• 중요도: 중
• 점검 목적: 정확한 로그 분석을 위해 시스템 시간을 NTP 서버와 동기화.
• 보안 위협: 시간이 동기화되지 않으면 침해사고 발생 시 로그의 시간 정보 불일치로 분석이 어려움.
상세 점검 로직 (Scripting Guide)
• 파일: /etc/ntp.conf 또는 /etc/chrony.conf
• 명령어: ntpq -p, chronyc sources, ps -ef | grep ntp
• 로직:
    ◦ NTP 서비스 데몬 실행 여부 확인.
    ◦ 설정 파일에 유효한 Time Server가 등록되어 있는지 확인.