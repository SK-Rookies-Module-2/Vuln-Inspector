# Strix Plugin Schema Proposal

## 목적
- Strix CLI를 외부 도구로 통합하되 기존 플러그인 계약을 유지한다.
- Static/Dynamic 채널로 분리해 Target 유형에 맞게 실행한다.

## 통합 전략
- 기존 플러그인 경로를 유지한다.
  - `plugins/static/strix_scan`
  - `plugins/dynamic/strix_scan`
- CLI 호출은 `app/adapters/external/strix.py`에서 담당한다.
- 결과 파싱은 `app/services/report_parsers/strix.py`에서 수행한다.
- 실행 결과/로그는 artifacts에 저장한다.
  - `storage/artifacts/{job_id}/strix/{run_name}/`

## 실행 패턴(권장)
- API 서버는 작업만 등록하고 실행은 워커 프로세스에서 수행한다.
- 실행마다 run_id(run_name)를 부여해 아티팩트를 분리한다.
- stdout/stderr는 실행 중 파일로 스트리밍 저장한다.
- 러너 레벨에서 타임아웃을 적용하고 소요 시간을 기록한다.
- exit code는 참고 신호로만 사용하고 최종 성공 여부는 리포트 파싱으로 판단한다.
- 명령 인자는 리스트로 전달해 쉘 인젝션을 방지한다.

## 권장 플러그인 ID
- `static_strix_scan`
- `dynamic_strix_scan`

## plugin.yml 예시 (Dynamic)
```yaml
id: "dynamic_strix_scan"
name: "Strix External Dynamic Scan"
version: "0.1.0"
type: "dynamic"
category: "external"
tags:
  - "OWASP:2025:A01"
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
      default: "deep"
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

## plugin.yml 예시 (Static)
```yaml
id: "static_strix_scan"
name: "Strix External Static Scan"
version: "0.1.0"
type: "static"
category: "external"
tags:
  - "OWASP:2025:A03"
description: "Run Strix static scan and normalize results."
config_schema:
  properties:
    repo_url:
      type: string
    repo_ref:
      type: string
    repo_path:
      type: string
    scan_mode:
      type: string
      enum: ["quick", "standard", "deep"]
      default: "deep"
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
class_name: "StrixStaticScan"
```

## 입력 매핑
### Dynamic
- Target.type: `WEB_URL`
- `Target.connection_info.url` → `config.base_url` 기본값
- `instruction`/`instruction_file`로 인증 정보/스코프 전달

### Static
- Target.type: `GIT_REPO`
- `Target.connection_info.url` → `config.repo_url` 기본값
- `Target.connection_info.path` → `config.repo_path` 기본값

## CLI 매핑(핵심 옵션)
```bash
strix -n --target <target> \
  --scan-mode <quick|standard|deep> \
  --instruction "<text>" \
  --instruction-file <file> \
  --run-name <job_id>
```
- `-n/--non-interactive`는 기본 활성화한다.
- `--run-name`에는 `job_id` 또는 `job_id + plugin_id` 조합을 사용한다.
- 장시간 실행이므로 워커에서 실행하고 상태를 주기적으로 갱신한다.

## 실행/출력 흐름
1. 플러그인이 config/target을 취합한다.
2. `StrixRunner`가 CLI 커맨드를 구성/실행한다.
3. stdout/stderr를 파일로 저장한다.
4. 가능한 경우(지원 시) JSON 리포트를 저장한다.
5. 파서가 Finding으로 변환한다.

## Finding 생성 규칙(요약)
- Strix 결과 항목 1개 → Finding 1개
- severity 매핑: Strix severity → Critical/High/Medium/Low/Info
- tags에는 OWASP/KISA/Strix 분류 태그 포함
- evidence에 URL/파일/라인/요청/응답 요약 포함

## 오류/부분 성공 처리
- Strix 실행 실패 시
  - 단일 Finding("External tool failed") 생성
  - stdout/stderr 로그 경로를 evidence에 기록
- 파싱 실패 시
  - Raw report 경로만 담은 Info Finding 생성

## 보안 고려사항
- `instruction`에 자격증명 포함 가능 → 로그/DB 저장 시 마스킹 고려
- instruction 파일 경로는 허용 경로만 사용

## 구현 위치(예시)
- `app/adapters/external/strix.py` (CLI 래퍼)
- `app/services/report_parsers/strix.py` (파서)
- `plugins/static/strix_scan/main.py`
- `plugins/dynamic/strix_scan/main.py`
