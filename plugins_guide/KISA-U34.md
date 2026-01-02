U-34: Finger 서비스 비활성화
• 중요도: 상
• 점검 목적: 사용자 정보 유출을 막기 위해 Finger 서비스 차단.
• 보안 위협: Finger 서비스는 계정명, 홈 디렉터리, 로그인 시간 등 민감 정보를 외부로 노출함.
점검 대상 및 판단 기준
• 양호: Finger 서비스가 비활성화된 경우.
• 취약: Finger 서비스가 활성화된 경우.
상세 점검 로직 (Scripting Guide)
• Linux (inetd/xinetd):
    ◦ /etc/inetd.conf에서 finger 라인이 주석 처리되었는지 확인.
    ◦ /etc/xinetd.d/finger 파일에서 disable = yes 확인.
• Solaris/Linux (Process):
    ◦ ps -ef | grep finger 프로세스 확인.
    ◦ netstat -an | grep 79 포트 리스닝 확인.