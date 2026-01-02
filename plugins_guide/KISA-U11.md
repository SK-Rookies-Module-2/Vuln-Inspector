U-11: 사용자 shell 점검
• 중요도: 하
• 점검 목적: 로그인이 필요 없는 시스템 계정(daemon, bin, sys 등)에 쉘(/bin/false, /sbin/nologin)을 부여하여 로그인을 차단함.
• 보안 위협: 불필요한 계정에 로그인이 가능한 쉘이 부여되면 공격자가 이를 통해 시스템에 접근하거나 명령어를 실행할 수 있음.
점검 대상 및 판단 기준
• 대상: SOLARIS, LINUX, AIX, HP-UX
• 양호: 로그인이 필요 없는 계정에 /bin/false 또는 /sbin/nologin 쉘이 부여된 경우.
• 취약: 로그인이 필요 없는 계정에 /bin/sh, /bin/bash 등의 쉘이 부여된 경우.
OS별 상세 점검 로직 (Scripting Guide)
1) 공통 (Linux, AIX, HP-UX, Solaris)
• 파일: /etc/passwd
• 점검 로직:
    1. passwd 파일에서 시스템 기본 계정(daemon, bin, sys, adm, listen, nobody, nobody4, noaccess, diag, operator, games, gopher 등) 리스트를 정의.
    2. 해당 계정들의 쉘 설정 필드(마지막 필드) 확인.
    3. 쉘이 /bin/false 또는 /sbin/nologin이 아니면 취약.
    ◦ 주의: 로그인이 필요한 업무용 계정은 제외해야 함.