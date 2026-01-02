U-41: 불필요한 automountd 제거
• 중요도: 상
• 점검 목적: automountd 서비스는 로컬 공격 취약점(RPC 관련)이 존재하므로 미사용 시 제거.
• 보안 위협: 파일 시스템 마운트 옵션을 악용하여 권한 상승 등의 공격 가능.
점검 대상 및 판단 기준
• 양호: automountd 서비스가 비활성화된 경우.
• 취약: automountd 서비스가 활성화된 경우.
상세 점검 로직 (Scripting Guide)
• 프로세스 확인: ps -ef | grep -E "automount|autofs"
• 판단: 프로세스가 조회되면 취약.