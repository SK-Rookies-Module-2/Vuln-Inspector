# Strix Report Parsing Proposal

## 목적
- Strix CLI 결과를 표준 Finding으로 변환한다.
- 불완전한 결과라도 Dashboard에 일관된 방식으로 표시한다.

## 보고서 입력 형식(현황/가정)
- `docs/strix_docs.md`에는 JSON 리포트 출력 옵션이 명시되어 있지 않다.
- 우선순위 기반 입력을 사용한다.
  1) Strix가 생성한 JSON 리포트 파일(지원 시)
  2) stdout에 포함된 JSON
  3) stdout/stderr 원문 로그

## 정규화 파이프라인
1) 원본 로그 저장
   - `storage/artifacts/{job_id}/strix/{run_name}/stdout.log`
   - `storage/artifacts/{job_id}/strix/{run_name}/stderr.log`
2) 리포트 소스 탐색
   - 명시적 report_path 또는 표준 위치 탐색
3) JSON 파싱 시도
4) findings[]를 표준 Finding으로 변환
5) 변환 실패 항목은 Raw-only Finding으로 처리

## Exit Code 처리
- 0: 취약점 없음, 정상 종료
- 2: 취약점 있음, 정상 종료(헤드리스 모드 기준)
- 그 외: 실행 실패로 간주

## Finding 매핑 규칙
- title: findings[].title 또는 rule_name
- vuln_id: findings[].id 또는 rule_id
- severity: 매핑 테이블 사용
- tags: findings[].tags + "STRIX" 태그
- description: findings[].description
- solution: findings[].remediation 또는 findings[].fix
- evidence:
  - url, endpoint, file_path, line, request/response 요약
  - raw_report_path, stdout/stderr 경로 포함 가능

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
    - stdout/stderr 경로

## 결과 요약 규칙
- Job.summary는 변환된 Findings 기준으로 산출
- Raw-only만 있는 경우에도 summary 생성

## 예외 처리
- 보고서 파일 누락
  - 단일 Finding("Report missing") 생성
- JSON 파싱 실패
  - 단일 Finding("Report parse failed") 생성

## 구현 위치(예시)
- `app/adapters/external/strix.py`: 결과 수집 및 저장
- `app/services/report_parsers/strix.py`: 파싱/변환 로직
