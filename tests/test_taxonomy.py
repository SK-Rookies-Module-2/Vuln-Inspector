"""이 파일은 .py 테스트 모듈로 매핑 태그 확장을 검증합니다."""

from app.core.taxonomy import TaxonomyIndex


def test_mapping_expands_kisa_to_owasp() -> None:
    index = TaxonomyIndex.from_default()
    expanded = index.expand_tags(["KISA:U-01"])
    assert "OWASP:2025:A07" in expanded
