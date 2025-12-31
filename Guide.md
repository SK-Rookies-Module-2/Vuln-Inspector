<!-- Guide.md: 설계 가이드 및 아키텍처 문서 -->
1. 전체 시스템 아키텍처 (System Architecture)
본 시스템은 중앙 집중형 Orchestrator가 진단 대상을 관리하고, 실제 진단 로직은 **3개의 독립된 채널(Static, Remote, Dynamic)**을 통해 플러그인 형태로 수행되는 구조입니다. 이는 OWASP 2025의 공급망 보안(A03)부터 KISA의 인프라 설정 진단까지 포괄하기 위함입니다.
1.1. Core Orchestrator (중앙 코어)
• 역할: 자산(Target) 관리, 스캔 작업(Job) 스케줄링, 결과(Finding) 표준화 및 리포팅.
• 입력 처리: 사용자로부터 진단 대상(IP, Repo URL, Credentials) 수신.
• 플러그인 로더: plugin.yml 메타데이터를 파싱하여 가용한 진단 모듈을 메모리에 로드.
1.2. Diagnostic Channels (진단 채널 및 범위)
설계서의 요구사항에 따라 다음 3가지 채널로 진단 능력을 분할합니다.
1. Static Whitebox (정적 분석 채널)
    ◦ 대상: Git Repository, 빌드 아티팩트(jar, whl 등).
    ◦ 핵심 진단 항목:
        ▪ OWASP A03:2025 (Software Supply Chain Failures): package.json, requirements.txt 등을 분석하여 악성 패키지나 취약한 라이브러리 탐지. 외부 도구(예: OSV-Scanner, Safety)를 래핑(Wrapping)하여 통합.
        ▪ OWASP A05:2025 (Injection): 소스 코드 내 SQL Injection 패턴 정적 탐지.
    ◦ 방식: 코드를 내려받아 AST(Abstract Syntax Tree) 분석 또는 패턴 매칭 수행.
2. Remote Whitebox (원격 설정 분석 채널)
    ◦ 대상: 운영 서버(Linux/Windows), DBMS, 보안 장비.
    ◦ 핵심 진단 항목:
        ▪ KISA 기술적 취약점 가이드: SSH나 WinRM으로 접속하여 /etc/passwd, Registry 등을 직접 조회. 예: U-01 root 계정 원격 접속 제한, W-01 Administrator 계정 관리.
        ▪ OWASP A02:2025 (Security Misconfiguration): 클라우드나 서버의 잘못된 보안 설정 점검.
    ◦ 방식: Agentless 방식(SSH/SSM)으로 커맨드 실행 후 결과 파싱.
3. Dynamic Blackbox (런타임 검증 채널)
    ◦ 대상: 구동 중인 웹 애플리케이션(URL).
    ◦ 핵심 진단 항목:
        ▪ OWASP A01:2025 (Broken Access Control): IDOR(Insecure Direct Object References) 등 런타임 권한 검증.
        ▪ Heuristic Engine: 에러 메시지 노출(A10: Mishandling of Exceptional Conditions) 등을 탐지하기 위한 의심 패턴 전송.
    ◦ 방식: HTTP Request/Response 기반의 능동적 스캐닝.
--------------------------------------------------------------------------------
2. 프로젝트 디렉토리 구조 (Project Directory Structure)
확장성을 고려하여 코어 로직과 플러그인을 엄격히 분리한 구조입니다.
vuln-orchestrator/
├── app/                        # 중앙 코어 모듈
│   ├── api/                    # REST API 엔드포인트 (FastAPI/Flask)
│   ├── core/                   # 설정, 로깅, 스케줄러 엔진
│   ├── db/                     # DB 모델 및 마이그레이션 스크립트
│   ├── services/               # 비즈니스 로직 (Job Manager, Report Generator)
│   └── adapters/               # 외부 도구 연동을 위한 공통 어댑터 인터페이스
│
├── plugins/                    # 모든 진단 로직이 위치하는 곳 [4]
│   ├── static/                 # Static Whitebox 플러그인 그룹
│   │   └── dependency_check/   # 예: A03 공급망 진단 플러그인
│   │       ├── main.py         # 실행 로직
│   │       └── plugin.yml      # 메타데이터 (ID, Category, Version)
│   │
│   ├── remote/                 # Remote Whitebox 플러그인 그룹
│   │   └── linux_kisa/         # 예: KISA 리눅스 취약점 진단
│   │       ├── checks/         # U-01, U-02 등 개별 스크립트 [3]
│   │       ├── main.py
│   │       └── plugin.yml
│   │
│   └── dynamic/                # Dynamic Blackbox 플러그인 그룹
│       └── idor_scanner/       # 예: A01 권한 우회 점검 [11]
│           ├── heuristic.py    # 범용 의심 탐지 로직 [4]
│           ├── recipe.py       # 확정적 시나리오 검증 로직
│           └── plugin.yml
│
├── storage/                    # 스캔 결과, 리포트, 증적 자료 저장소
│   ├── artifacts/              # 정적 분석을 위해 클론한 소스코드 등
│   └── evidences/              # 진단 스크린샷, 로그 파일
│
├── tests/                      # 유닛 및 통합 테스트
├── docker-compose.yml          # DB, MQ, Web App 컨테이너 구성
├── requirements.txt            # 의존성 목록
└── run.py                      # 애플리케이션 진입점
--------------------------------------------------------------------------------
3. 데이터베이스 스키마 (DB Schema)
설계서의 요구사항에 따라 Targets, ScanJobs, Findings를 중심으로 설계하며, 특히 Findings는 OWASP와 KISA 기준을 모두 수용할 수 있도록 태깅 시스템을 적용합니다. (SQLAlchemy 모델 예시)
3.1. Targets (진단 대상)
• 진단할 자산 정보를 관리합니다. Credentials는 암호화하여 저장해야 합니다.
class Target(Base):
    __tablename__ = "targets"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)  # 대상 식별명
    target_type = Column(String, nullable=False) # SERVER, WEB_URL, GIT_REPO
    
    # 접속 정보 (JSON 형태로 유연하게 저장하거나 별도 테이블 분리 가능)
    # 예: { "ip": "10.0.0.1", "port": 22, "os": "Ubuntu 20.04" }
    connection_info = Column(JSON, nullable=True) 
    
    # 인증 정보 (Encrypted)
    # 예: { "username": "root", "password": "encrypted_...", "key_path": "..." }
    credentials = Column(JSON, nullable=True)
    
    description = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
3.2. ScanJobs (진단 작업)
• 비동기 진단 작업의 상태와 범위를 관리합니다.
class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    
    status = Column(String, default="PENDING") # PENDING, RUNNING, COMPLETED, FAILED
    
    # 실행할 플러그인 또는 채널 지정
    # 예: ["remote_linux_kisa", "static_dependency"]
    scan_scope = Column(JSON, nullable=False) 
    
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    
    # 요약 정보 (Critical: 1, High: 2 ...)
    summary = Column(JSON, default={})
3.3. Findings (진단 결과 - 표준 포맷)
• 외부 도구 및 내부 플러그인의 결과를 통일된 스키마로 변환하여 저장합니다.
• OWASP Top 10과 KISA 가이드 분류를 매핑합니다.
class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id"))
    
    # 취약점 식별자 (예: CVE-2025-XXXX, KISA-U-01)
    vuln_id = Column(String, index=True)
    
    # 취약점 명 (예: Root 계정 원격 접속 허용)
    title = Column(String, nullable=False)
    
    # 심각도 (Critical, High, Medium, Low, Info)
    severity = Column(String, nullable=False)
    
    # 매핑 카테고리 (중요: 확장성)
    # 예: ["OWASP:A01:2025", "KISA:Unix-Server"]
    tags = Column(JSON) 
    
    # 상세 내용
    description = Column(Text)
    solution = Column(Text)
    
    # 증적 데이터 (JSON)
    # 예: { "file": "package.json", "line": 15, "command_output": "PermitRootLogin Yes" }
    evidence = Column(JSON)
    
    # 외부 도구 원본 데이터 (필요시)
    raw_data = Column(JSON, nullable=True)
3.4. Reports (리포트)
• 사용자에게 제공할 최종 산출물 관리.
class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id"))
    format = Column(String) # PDF, HTML, JSON, CSV
    file_path = Column(String)
    generated_at = Column(DateTime, default=datetime.utcnow)
    4. API 명세 (API Specification)
Orchestrator의 기능을 외부(프론트엔드 또는 CI/CD 파이프라인)에 노출하기 위한 RESTful API 설계입니다. Python의 FastAPI 또는 Flask 사용을 가정합니다.
4.1. 자산 관리 (Target Management)
• POST /api/v1/targets
    ◦ 진단 대상을 등록합니다.
    ◦ Body: { "name": "Web Server 01", "type": "SERVER", "connection_info": {...}, "credentials": {...} }
• GET /api/v1/targets/{target_id}
    ◦ 대상 상세 정보를 조회합니다.
4.2. 진단 작업 (Scan Jobs)
• POST /api/v1/jobs
    ◦ 새로운 진단 작업을 생성하고 큐(Queue)에 등록합니다.
    ◦ Body: { "target_id": 1, "scan_scope": ["static_dep", "remote_linux_kisa"], "policy": "full_scan" }
• GET /api/v1/jobs/{job_id}/status
    ◦ 진단 진행률 및 상태를 반환합니다. (Polling용)
    ◦ Response: { "status": "RUNNING", "progress": 45, "current_step": "Checking KISA U-01..." }
4.3. 결과 및 리포트 (Findings & Reports)
• GET /api/v1/jobs/{job_id}/findings
    ◦ 발견된 취약점 목록을 표준 JSON 포맷으로 반환합니다. OWASP/KISA 태그 필터링을 지원해야 합니다.
• POST /api/v1/jobs/{job_id}/report
    ◦ 지정된 포맷(PDF, CSV)으로 리포트 생성을 요청합니다.
--------------------------------------------------------------------------------
5. 플러그인 인터페이스 정의 (Plugin Interface Definition)
모든 진단 로직(Static, Remote, Dynamic)은 중앙 코어와 **약속된 규약(Interface)**을 따라야만 확장 가능합니다.
5.1. 추상 기본 클래스 (BasePlugin)
모든 플러그인은 아래 파이썬 클래스를 상속받아 구현해야 합니다.
from abc import ABC, abstractmethod
from typing import List, Dict

class BasePlugin(ABC):
    """
    모든 진단 플러그인의 부모 클래스
    """
    def __init__(self, context: Dict):
        self.context = context  # 대상 정보(IP, Credential, Path 등)
        self.results = []       # Finding 객체 리스트

    @abstractmethod
    def check(self) -> List[Dict]:
        """
        실제 진단 로직을 수행하는 메인 메소드.
        반환값은 표준 Finding 스키마를 따른 Dict 리스트여야 함.
        """
        pass

    def add_finding(self, vuln_id, title, severity, evidence, tags):
        """
        진단 결과를 표준 포맷으로 변환하여 저장
        """
        finding = {
            "vuln_id": vuln_id,   # 예: OWASP-A03, KISA-U-01
            "title": title,
            "severity": severity, # Critical, High, Medium, Low
            "evidence": evidence, # 로그, 스크린샷 경로, 커맨드 출력값
            "tags": tags          # ["OWASP:2025:A03", "KISA:Linux"]
        }
        self.results.append(finding)
5.2. 플러그인 메타데이터 (plugin.yml)
시스템이 플러그인을 자동으로 인식하고 UI에 표시하기 위한 명세서입니다.
id: "remote_linux_kisa_u01"
name: "Root Remote Login Check"
version: "1.0.0"
type: "remote"  # static | remote | dynamic
category: "inf" # infrastructure
tags:
  - "KISA:U-01"
  - "OWASP:2025:A07" # Authentication Failures 매핑 가능 [4][5]
description: "SSH 원격 접속 시 Root 계정 직접 로그인 허용 여부를 점검합니다."
entry_point: "main.py" # 실행할 파이썬 파일
class_name: "RootLoginCheck" # 실행할 클래스명
--------------------------------------------------------------------------------
6. Heuristic Engine 및 Recipe 설계
설계서의 핵심 요구사항인 **"자동화 철학(휴리스틱+레시피)"**을 구현하기 위한 구조입니다.
6.1. Heuristic Engine (범용 의심 탐지)
OWASP Top 10 2025 A10(예외 처리 미흡)이나 A05(인젝션)와 같이, 명확한 시그니처가 없어도 비정상적인 반응을 통해 취약점을 추정하는 엔진입니다.
• 동작 원리: Probe(자극) -> Analyze(반응 분석) -> Score(점수화)
• 구현 예시 (Error Disclosure 탐지):
class HeuristicProbe(BasePlugin):
    def check(self):
        # 1. Probe: 특수문자나 잘못된 타입의 데이터 전송
        payloads = ["'", "\"", "<script>", "%00"]
        
        for payload in payloads:
            response = self.send_request(payload)
            
            # 2. Analyze: 응답 내에 스택 트레이스나 DB 에러 메시지 노출 여부 확인
            # OWASP A10:2025 Mishandling of Exceptional Conditions 대응 [7]
            if self.detect_error_pattern(response.body):
                # 3. Score: 확정적이지 않으므로 '의심(Suspicious)' 등급 부여
                self.add_finding(
                    vuln_id="HEURISTIC-ERR-01",
                    title="Potential Error Disclosure",
                    severity="Medium",
                    evidence={"payload": payload, "response_snippet": response.body[:100]},
                    tags=["OWASP:2025:A10"]
                )
6.2. Recipe Engine (확정적 시나리오 검증)
OWASP A01(접근 제어)과 같이 문맥(Context)이 필요한 취약점을 진단하기 위해, **사전에 정의된 절차(Scenario)**대로 진단을 수행합니다.
• 목적: IDOR(부적절한 인가) 등 단순 스캔으로 찾기 힘든 논리적 결함 탐지.
• Recipe 템플릿 (YAML):
recipe_id: "IDOR_PROFILE_CHECK"
description: "사용자 A의 토큰으로 사용자 B의 프로필 조회 시도"
tags: ["OWASP:2025:A01"] # Broken Access Control [4]

steps:
  - step: 1
    action: "login"
    user: "attacker"
    save_context: ["auth_token"] # 공격자의 토큰 저장

  - step: 2
    action: "http_request"
    method: "GET"
    url: "/api/users/{victim_id}" # 피해자 ID (사전 정의됨)
    headers:
      Authorization: "Bearer {auth_token}" # 공격자 토큰 사용
    
  - step: 3
    action: "assert"
    condition: "status_code == 403 OR status_code == 401"
    on_fail: # 200 OK가 떨어지면 취약점으로 간주
      severity: "High"
      title: "IDOR Vulnerability Detected"
--------------------------------------------------------------------------------
요약 및 구현 전략
1. 플러그인 중심 개발: 코어 로직은 플러그인을 로드하고 실행하는 데 집중하며, 실제 KISA U-01(Root 접속 제한)이나 OWASP A03(공급망) 진단 로직은 각각 plugins/remote/와 plugins/static/ 하위에 개별 모듈로 구현합니다.
2. KISA 및 OWASP 2025 대응: DB 스키마의 tags 필드를 활용하여, 하나의 진단 결과가 KISA:U-01이면서 동시에 OWASP:2025:A07로 매핑될 수 있도록 유연성을 확보합니다.
3. 확장성: 초기 MVP는 정적 분석(의존성 스캔)과 원격 설정 진단(SSH)에 집중하고, 추후 Dynamic 엔진에 Heuristic 로직을 추가하는 순서로 개발을 진행합니다.
