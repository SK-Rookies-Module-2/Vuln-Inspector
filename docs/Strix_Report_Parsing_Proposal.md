# Strix Report Parsing Proposal

## 목적
- Strix CLI 결과를 표준 Finding으로 변환한다.
- 불완전한 결과라도 Dashboard에 일관된 방식으로 표시한다.

## 보고서 입력 형식(현황/가정)
- `docs/strix_docs.md`에는 JSON 리포트 출력 옵션이 명시되어 있지 않다.
- 실제 실행 결과는 `strix_runs/<run_id>/` 아래 파일로 생성된다.
  - `penetration_test_report.md`
  - `vulnerabilities.csv`
  - `vulnerabilities/vuln-*.md`

## 정규화 파이프라인
1) 원본 로그 저장
   - `storage/artifacts/{job_id}/strix/{run_name}/stdout.log`
   - `storage/artifacts/{job_id}/strix/{run_name}/stderr.log`
2) 리포트 소스 탐색
   - Strix 실행 디렉터리 기준 `strix_runs/` 하위 탐색
   - 표준 위치 예시:
     - `storage/artifacts/{job_id}/strix/{run_name}/strix_runs/{run_id}/`
   - `run_id`가 없으면 최신 생성 디렉터리를 선택한다.
3) `vulnerabilities.csv` 로드
4) 각 행의 `file` 경로로 상세 Markdown(`vulnerabilities/vuln-*.md`)을 로드
5) CSV + Markdown을 결합해 Finding으로 변환
6) 변환 실패 항목은 Raw-only Finding으로 처리

## 리포트 탐색/파싱 규칙(권장)
- 실행 workdir는 artifacts 경로로 고정한다.
- `strix_runs/` 하위에서 리포트 파일을 찾는다.
  - 우선순위: `vulnerabilities.csv` → `vulnerabilities/*.md` → `penetration_test_report.md`
- `vulnerabilities.csv` 컬럼(실측):
  - `id`, `title`, `severity`, `timestamp`, `file`
- `file`은 run 디렉터리 기준 상대 경로이며, Markdown 상세 보고서로 연결된다.
- `penetration_test_report.md`는 요약 보고서로 evidence에 경로를 기록한다.

## 운영 처리(권장)
- API 요청 컨텍스트가 아닌 워커 프로세스에서 실행한다.
- 안전한 취소를 위해 프로세스 그룹을 사용한다.
- 실행 시작/종료 시각과 소요 시간을 기록한다.
- DB에는 아티팩트 경로만 저장하고 원본 대용량 데이터는 피한다.

## 실시간 로그/상태 처리(권장)
- stdout 로그를 주기적으로 tail하여 상태 정보를 추출한다.
- 추출 대상 예시
  - 상태 문구: `Running penetration test`
  - 카운트: `Vulnerabilities`
  - 메타: `Model`, `Agents`, `Input/Output`, `Cost`
- 상태는 파서가 아닌 별도 "progress parser"에서 처리한다.
- 최신 상태 스냅샷을 `status.json`으로 저장하고 대시보드에서 표시한다.

## Exit Code 처리
- 0: 취약점 없음, 정상 종료
- 2: 취약점 있음, 정상 종료(헤드리스 모드 기준)
- 그 외: 실행 실패로 간주
  - 실패 시에도 로그/리포트 경로를 evidence로 남긴다.

## Finding 매핑 규칙
- title: `vulnerabilities.csv`의 `title`
- vuln_id: `vulnerabilities.csv`의 `id` (예: `vuln-0001`)
- severity: `vulnerabilities.csv`의 `severity` 매핑
- tags: 기본 `"STRIX"` 태그 + 내용에서 추출한 레퍼런스(OWASP 등)
- description: Markdown의 `Description` 섹션 본문
- solution: Markdown의 `Remediation` 섹션 본문
- evidence:
  - Markdown의 `Evidence`/`Artifacts` 섹션 추출 결과
  - `penetration_test_report.md` 경로
  - `stdout.log`, `stderr.log` 경로

## Markdown 섹션 파서 규칙(구체)
- 대상 파일: `vulnerabilities/vuln-*.md`
- 헤더 인식 규칙
  - 섹션 헤더는 `## ` 또는 `### `로 시작하는 라인
  - 헤더 텍스트는 대소문자 무시하고 비교
- 섹션 매핑(허용 라벨)
  - Description: `Description`, `Issue`, `Summary`
  - Evidence: `Evidence`, `Unauthenticated evidence`, `Artifacts`
  - Remediation: `Remediation`, `Fix`, `Mitigation`
  - References: `References`
- 수집 범위
  - 각 섹션 헤더 이후 다음 헤더 전까지를 본문으로 수집
  - 빈 줄은 유지하되 과도한 연속 공백은 1줄로 축약
- 필드 추출 규칙
  - ID: `**ID:**` 라인에서 추출(없으면 CSV id 사용)
  - Severity: `**Severity:**` 라인에서 추출(없으면 CSV severity 사용)
  - Found: `**Found:**` 라인에서 추출(없으면 CSV timestamp 사용)
- Evidence/Artifacts 처리
  - `-`로 시작하는 목록은 그대로 유지하고 `evidence.items` 배열로 저장
  - `Artifacts` 섹션의 경로는 `evidence.paths`로 분리 저장
- References 처리
  - `References` 섹션의 라인은 `tags` 후보로 변환
  - 예: `OWASP Top 10 2021 A01` -> `OWASP:2021:A01`
- 예외 처리
  - 섹션이 없으면 전체 본문을 `description`으로 사용
  - 필요한 섹션이 비어 있으면 `None`으로 처리

## Severity 매핑 예시
| Strix | 표준 |
|------|------|
| critical | Critical |
| high | High |
| medium | Medium |
| low | Low |
| info | Info |

## Raw-only Finding 규칙
- 조건: CSV 누락, Markdown 누락, 파싱 실패
- 생성 내용
  - vuln_id: "STRIX-RAW-ONLY"
  - title: "Raw report only"
  - severity: Info
  - evidence:
    - report_path 또는 run_dir
    - error_message
    - stdout/stderr 경로

## 결과 요약 규칙
- Job.summary는 변환된 Findings 기준으로 산출
- Raw-only만 있는 경우에도 summary 생성

## 예외 처리
- `vulnerabilities.csv` 누락
  - `vulnerabilities/*.md`만으로 최소 Finding 생성 시도
  - 실패 시 단일 Finding("Report missing") 생성
- Markdown 파싱 실패
  - 단일 Finding("Report parse failed") 생성

## 구현 위치(예시)
- `app/adapters/external/strix.py`: 결과 수집 및 저장
- `app/services/report_parsers/strix.py`: 파싱/변환 로직
