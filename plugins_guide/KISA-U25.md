U-25: world writable 파일 점검
• 중요도: 상
• 점검 목적: 모든 사용자(Everyone)가 수정 가능한 파일을 식별하여 무단 변조 방지.
• 보안 위협: 시스템 중요 파일이 World Writable일 경우 악의적인 변조나 삭제가 가능함.
점검 대상 및 판단 기준
• 양호: World Writable 파일이 존재하지 않거나, 의도된 파일인 경우.
• 취약: 불필요한 World Writable 파일이 존재하는 경우.
상세 점검 로직 (Scripting Guide)
• 명령어: find / -type f -perm -2 -xdev -ls
• 로직:
    1. 시스템 전체에서 Others 권한에 쓰기(w, 숫자 2)가 있는 파일 검색.
    2. /proc, /sys 등 가상 파일 시스템은 제외.
    3. 발견된 파일 목록을 리포팅 (시스템 로그 파일이나 lock 파일 등 정상적인 경우도 있으므로 목록 확인 필요).