<!-- app/data/mappings/README.md: 매핑 데이터 설명 문서 -->
# 매핑 데이터 안내

이 디렉터리는 KISA U-코드와 OWASP 2025 카테고리의 매핑을 정의합니다. 플러그인 결과 태그에 `KISA:U-01` 같은 코드가 포함되면, 매핑을 통해 `OWASP:2025:A07` 같은 태그가 자동 확장됩니다.

## 파일 구조
- `kisa_owasp.yml`: KISA → OWASP 매핑 정의 파일.

## 추가 방법
- `mappings` 리스트에 항목을 추가합니다.
- 태그 형식은 대문자로 통일합니다.
  - KISA: `KISA:U-01`, `KISA:U-12` 등
  - OWASP: `OWASP:2025:A01` ~ `OWASP:2025:A10`

## 예시
```
- kisa: "KISA:U-03"
  owasp:
    - "OWASP:2025:A02"
  title: "Example Title"
  note: "Add references if needed"
```
