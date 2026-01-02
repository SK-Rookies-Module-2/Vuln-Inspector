U-12: 세션 종료 시간 설정
• 중요도: 하
• 점검 목적: 일정 시간 사용하지 않는 세션을 자동 종료하여, 자리를 비운 사이 발생할 수 있는 비인가자의 접근을 차단함.
• 보안 위협: 세션 타임아웃이 설정되지 않으면 유휴 시간 동안 공격자가 시스템을 제어할 위험이 있음.
점검 대상 및 판단 기준
• 양호: Session Timeout이 600초(10분) 이하로 설정된 경우.
• 취약: 설정되지 않거나 600초를 초과한 경우.
OS별 상세 점검 로직 (Scripting Guide)
1) 공통 (Linux, Solaris, AIX, HP-UX)
• 파일: /etc/profile, /etc/bashrc, ~/.profile (sh, ksh, bash) 또는 /etc/csh.login, /etc/csh.cshrc (csh)
• 점검 로직:
    ◦ TMOUT=600 (또는 그 이하 값) 및 export TMOUT 설정 확인.
    ◦ csh의 경우 set autologout=10 (분 단위) 설정 확인.
    ◦ 설정값이 없거나 600초(10분)를 초과하면 취약.