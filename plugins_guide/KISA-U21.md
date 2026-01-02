U-21: /etc/(r)syslog.conf 파일 소유자 및 권한 설정
• 중요도: 상
• 점검 목적: 로그 설정 파일의 변조를 방지하여 로그 위변조 및 미기록 시도를 차단함.
• 보안 위협: 비인가자가 설정 파일을 수정하여 로그를 남기지 않거나 허위 로그를 남길 수 있음.
점검 대상 및 판단 기준
• 양호: 소유자가 root(또는 bin, sys)이고, 권한이 640 이하인 경우.
• 취약: 소유자가 root(또는 bin, sys)가 아니거나, 권한이 640을 초과하는 경우.
상세 점검 로직 (Scripting Guide)
• 대상 파일: /etc/syslog.conf, /etc/rsyslog.conf
• 로직:
    1. 파일 존재 여부 확인.
    2. ls -l 정보 파싱.
    3. Owner: root, bin, sys 중 하나인지 확인.
    4. Permission: Group Write(w), Others Read(r)/Write(w)/Execute(x)가 없는지 확인 (640 이하).