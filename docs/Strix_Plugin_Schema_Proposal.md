# Strix Plugin Schema Proposal

## 목적
- Strix AI를 외부 도구로 통합하되, 현 프로젝트의 플러그인 계약을 유지한다.
- 사용자는 scan_scope에서 "blackbox/whitebox"를 선택하는 감각으로 실행한다.

## 통합 전략
- 플러그인 형태로 Strix 실행을 래핑한다.
- 단일 플러그인 + mode 또는 두 개 플러그인으로 분리.
- 본 제안은 "두 개 플러그인"을 권장한다.

## 권장 플러그인 ID
- external_strix_blackbox
- external_strix_whitebox

## plugin.yml 예시 (Blackbox)
```yaml
id: "external_strix_blackbox"
name: "Strix AI Blackbox"
version: "0.1.0"
type: "dynamic"
category: "external"
tags:
  - "OWASP:2025:A01"
description: "Run Strix AI blackbox scan and normalize results."
config_schema:
  properties:
    base_url:
      type: string
    auth_headers:
      type: object
      default: {}
    timeout:
      type: integer
      default: 60
    report_format:
      type: string
      default: "json"
    max_results:
      type: integer
      default: 200
entry_point: "main.py"
class_name: "StrixBlackbox"
```

## plugin.yml 예시 (Whitebox)
```yaml
id: "external_strix_whitebox"
name: "Strix AI Whitebox"
version: "0.1.0"
type: "static"
category: "external"
tags:
  - "OWASP:2025:A03"
description: "Run Strix AI whitebox scan and normalize results."
config_schema:
  properties:
    repo_url:
      type: string
    repo_ref:
      type: string
    repo_path:
      type: string
    timeout:
      type: integer
      default: 120
    report_format:
      type: string
      default: "json"
    max_results:
      type: integer
      default: 200
entry_point: "main.py"
class_name: "StrixWhitebox"
```

## 입력 매핑
### Blackbox
- Target.type: WEB_URL
- Target.connection_info.url → config.base_url 기본값
- config.auth_headers는 사용자 입력 JSON

### Whitebox
- Target.type: GIT_REPO
- Target.connection_info.url → config.repo_url 기본값
- config.repo_ref는 branch/tag

## 실행/출력 흐름
- 플러그인은 Strix 실행 결과를 수신한다.
- 원본 보고서는 artifacts에 저장한다.
  - storage/artifacts/{job_id}/strix/{run_id}/report.json
- Findings 표준화 규칙은 별도 문서에 따른다.

## Finding 생성 규칙(요약)
- Strix 결과 항목 1개 → Finding 1개
- severity 매핑: Strix severity → Critical/High/Medium/Low/Info
- tags에는 OWASP/KISA/Strix 분류 태그 포함
- evidence에 URL/파일/라인/요청/응답 요약 포함

## 오류/부분 성공 처리
- Strix 실행 실패 시
  - 단일 Finding("External tool failed") 생성
  - report 없음/로그만 evidence에 기록
- 파싱 실패 시
  - Raw report 경로만 담은 Info Finding 생성

## 구현 위치(예시)
- app/adapters/strix.py (CLI/API 래퍼)
- plugins/external/strix_blackbox/main.py
- plugins/external/strix_whitebox/main.py

