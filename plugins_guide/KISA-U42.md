U-42: 불필요한 RPC 서비스 비활성화
• 중요도: 상
• 점검 목적: 버퍼 오버플로우 등 취약점이 많은 RPC(Remote Procedure Call) 서비스를 비활성화.
• 보안 위협: rpc.cmsd, rpc.ttdbserverd, sadmind 등은 원격 해킹의 주요 타겟임.
점검 대상 및 판단 기준
• 양호: 불필요한 RPC 서비스가 비활성화된 경우.
• 취약: 불필요한 RPC 서비스가 활성화된 경우.
상세 점검 로직 (Scripting Guide)
• Inetd 확인: /etc/inetd.conf에서 cmsd, ttdbserverd, sadmind, rusersd, walld, sprayd, rstatd 등의 라인이 주석 처리되지 않았으면 취약.
• 프로세스 확인: 관련 데몬 프로세스 존재 여부 확인.