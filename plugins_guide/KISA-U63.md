U-63: sudo 명령어 접근 관리
• 중요도: 중
• 점검 목적: /etc/sudoers 파일의 접근 권한 관리.
• 보안 위협: 비인가자가 sudoers 파일을 변조하여 관리자 권한을 획득할 수 있음.
상세 점검 로직 (Scripting Guide)
• 파일: /etc/sudoers
• 로직:
    ◦ ls -l /etc/sudoers 실행.
    ◦ 소유자가 root이고 권한이 440(읽기 전용) 또는 600 이하인지 확인.
    ◦ 가이드 기준: 소유자 root, 권한 640 이하 양호.