STRIX-DYNAMIC: 외부 동적(Strix) 보안 스캔
• 중요도: 해당 없음(외부 스캐너 결과에 따름)
• 점검 목적: Strix CLI를 이용해 WEB_URL 대상의 동적 취약점 탐지 결과를 표준 Finding으로 변환한다.
• 보안 위협: Broken Access Control, IDOR/BOLA, 인증 우회 등 런타임 취약점 전반.

점검 대상 및 판단 기준
• 대상: WEB_URL
• 양호: `vulnerabilities.csv`가 없거나 빈 경우(발견 항목 없음)
• 취약: `vulnerabilities.csv`에 1건 이상 항목 존재
• 참고: severity는 Strix 값(CRITICAL/HIGH/...)을 표준 등급으로 매핑

---

## 구현 설계

### 플러그인 형태

• 채널: dynamic (HTTP 기반 동적 스캔)
• 대상: TargetType.WEB_URL
• 플러그인 위치: `plugins/dynamic/strix_scan/`
• 플러그인 ID: `dynamic_strix_scan`

### plugin.yml 설계(예시)

```yaml
id: "dynamic_strix_scan"
name: "Strix External Dynamic Scan"
version: "0.1.0"
type: "dynamic"
category: "external"
tags:
  - "STRIX"
description: "Run Strix dynamic scan and normalize results."
config_schema:
  properties:
    base_url:
      type: string
    auth_headers:
      type: object
      default: {}
    scan_mode:
      type: string
      enum: ["quick", "standard", "deep"]
    instruction:
      type: string
    instruction_file:
      type: string
    non_interactive:
      type: boolean
      default: true
    run_name:
      type: string
    timeout:
      type: integer
      default: 1800
      min: 1
entry_point: "main.py"
class_name: "StrixDynamicScan"
```

### 입력 매핑

• Target.connection_info.url → config.base_url 기본값  
• instruction/instruction_file로 인증정보, 스코프, 제외 경로 지시 가능  
• non_interactive 기본 true(`-n`)로 TUI 대신 로그 기반 실행

### 점검 흐름

1. Target 검증  
   • `context.target.type`이 WEB_URL이 아니면 오류.
2. 실행 준비  
   • `job_id` 기반 run_name 생성(없으면 기본값).
   • workdir: `storage/artifacts/{job_id}/strix/{run_name}/`
3. Strix 실행  
   • `strix -n --target <base_url> --scan-mode <mode> --instruction ... --run-name <run_name>`
4. 결과 수집  
   • Strix는 workdir 하위에 `strix_runs/<run_name>/` 생성.
5. 파싱/변환  
   • `vulnerabilities.csv` + `vulnerabilities/vuln-*.md`를 Finding으로 변환.
6. 저장  
   • Finding을 DB에 저장, tags는 STRIX + References에서 추출한 OWASP 등 추가.

### 파서 설계(요약)

• 입력 파일
  - `strix_runs/<run_name>/vulnerabilities.csv`
  - `strix_runs/<run_name>/vulnerabilities/vuln-*.md`
  - `penetration_test_report.md`는 evidence 경로로 기록
• CSV 컬럼: `id`, `title`, `severity`, `timestamp`, `file`
• Markdown 섹션
  - Description/Issue/Summary → description
  - Remediation/Fix/Mitigation → solution
  - Evidence/Artifacts → evidence.items/paths
  - References → OWASP 태그 추출

### 오류/부분 성공 처리

• CSV 없음: Markdown 단독 파싱 시도 → 실패 시 Raw-only Finding 생성  
• Markdown 누락/파싱 실패: Raw-only Finding 생성  
• 실행 실패 로그는 evidence에 경로 기록

---

## 테스트 계획

• 유닛:  
  - `vulnerabilities.csv` 행 파싱 테스트  
  - Markdown 섹션 파서 테스트(Description/Remediation/Evidence/References)

• 통합(로컬):  
  - `strix_runs/<run_name>/` 샘플을 `parse_strix_report()`로 변환 후 Findings 확인  
  - 보고서 생성(`report.json`) 후 대시보드 Report 페이지에서 렌더 확인

---

## 설정 예시 (가이드만 보고 테스트 가능)

### 1) Target 등록 예시 (WEB_URL)

```json
{
  "name": "demo-web",
  "type": "WEB_URL",
  "connection_info": {
    "url": "https://example.com"
  }
}
```

### 2) Job 실행 예시

```json
{
  "target_id": 1,
  "scan_scope": ["dynamic_strix_scan"],
  "scan_config": {
    "dynamic_strix_scan": {
      "scan_mode": "deep",
      "instruction": "Focus on IDOR in /api/users",
      "run_name": "job-1-strix-dynamic"
    }
  }
}
```

---

## 실제 환경 테스트 절차 (간단)

1) API 서버 실행
```bash
uv run uvicorn app.api.app:app --reload
```

2) Target 등록 → Job 실행  
3) Findings 확인: `GET /api/v1/jobs/{id}/findings`  
4) Report 생성: `POST /api/v1/jobs/{id}/report`
