U-20: /etc/(x)inetd.conf 파일 소유자 및 권한 설정
• 중요도: 상
• 점검 목적: 슈퍼데몬 설정 파일 변조 방지.
• 보안 위협: 설정 파일 변조 시 불법 서비스 실행이나 서비스 거부 공격 등이 가능함.
점검 대상 및 판단 기준
• 양호: 소유자가 root이고, 권한이 600 이하인 경우.
• 취약: 권한이 600을 초과하거나 소유자가 root가 아닌 경우.
상세 점검 로직 (Scripting Guide)
1) Linux (xinetd/inetd)
• 파일: /etc/inetd.conf, /etc/xinetd.conf, /etc/xinetd.d/*
• 로직: Owner: root, Perm: 600 확인.
2) Solaris, AIX, HP-UX
• 파일: /etc/inetd.conf
• 로직: Owner: root, Perm: 600 확인.