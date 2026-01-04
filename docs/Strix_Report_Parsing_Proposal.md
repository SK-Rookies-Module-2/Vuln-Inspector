# Strix Report Parsing Proposal

## 목적
- 외부 도구(Strix AI)의 보고서를 표준 Finding으로 변환한다.
- 불완전한 결과라도 Dashboard에 일관된 방식으로 표시한다.

## 보고서 입력 형식(가정)
- JSON 기반 리포트가 기본 포맷
- 필수 필드 예시
  - summary
  - findings[]
  - metadata

## 정규화 파이프라인
1) 원본 보고서 저장
   - storage/artifacts/{job_id}/strix/{run_id}/report.json
2) 파서가 JSON을 로드
3) findings[]를 표준 Finding으로 변환
4) 변환 실패 항목은 Raw-only Finding으로 처리

## Finding 매핑 규칙
- title: findings[].title 또는 rule_name
- vuln_id: findings[].id 또는 rule_id
- severity: severity 매핑 테이블 사용
- tags: findings[].tags + "STRIX" 태그
- description: findings[].description
- solution: findings[].remediation 또는 findings[].fix
- evidence:
  - url, endpoint, file_path, line, request/response 요약
  - raw_report_path 포함 가능

## Severity 매핑 예시
| Strix | 표준 |
|------|------|
| critical | Critical |
| high | High |
| medium | Medium |
| low | Low |
| info | Info |

## Raw-only Finding 규칙
- 조건: 파싱 실패, 필수 필드 없음, 구조 불일치
- 생성 내용
  - vuln_id: "STRIX-RAW-ONLY"
  - title: "Raw report only"
  - severity: Info
  - evidence:
    - report_path
    - error_message

## 결과 요약 규칙
- Job.summary는 변환된 Findings 기준으로 산출
- Raw-only만 있는 경우에도 summary 생성

## 예외 처리
- 보고서 파일 누락
  - 단일 Finding("Report missing") 생성
- JSON 파싱 실패
  - 단일 Finding("Report parse failed") 생성

## 구현 위치(예시)
- app/adapters/strix.py: 결과 수집 및 저장
- plugins/external/*/main.py: 파싱/변환 로직

