U-43: NIS, NIS+ 점검
• 중요도: 상
• 점검 목적: 보안이 취약한 NIS(Network Information Service) 대신 NIS+를 사용하거나 서비스 비활성화.
• 보안 위협: NIS는 정보를 평문으로 전송하며, 비인가자가 맵 파일 등을 탈취하여 root 권한 획득 가능.
점검 대상 및 판단 기준
• 양호: NIS 서비스(ypserv, ypbind 등)를 사용하지 않거나, 필요시 NIS+를 사용하는 경우.
• 취약: 안전하지 않은 NIS 서비스를 사용하는 경우.
상세 점검 로직 (Scripting Guide)
• 프로세스 확인: ps -ef | grep -E "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"
• 판단: 프로세스가 실행 중이면 취약 (단, NIS+ 사용 시 예외 검토).