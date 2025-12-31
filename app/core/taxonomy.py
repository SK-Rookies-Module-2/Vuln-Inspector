"""이 파일은 .py 택소노미 모듈로 KISA→OWASP 매핑과 태그 확장을 담당합니다."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

import yaml

from .config import DEFAULT_MAPPING_FILE

KISA_CODE_PATTERN = re.compile(r"^KISA:U-\d{2,3}$")
OWASP_CODE_PATTERN = re.compile(r"^OWASP:2025:A\d{2}$")


def normalize_tag(tag: Optional[str]) -> str:
    # None/공백을 처리하고 대문자 표준화한다.
    if not tag:
        return ""
    return tag.strip().upper()


@dataclass(frozen=True)
class MappingEntry:
    # YAML 매핑 레코드의 단위(향후 확장 대비용).
    kisa: str
    owasp: List[str]
    title: Optional[str] = None
    note: Optional[str] = None


class TaxonomyIndex:
    def __init__(self, kisa_to_owasp: Dict[str, Set[str]]):
        # KISA 코드 -> OWASP 코드 리스트 매핑 테이블이다.
        self.kisa_to_owasp = kisa_to_owasp

    @classmethod
    def from_file(cls, path: Path) -> "TaxonomyIndex":
        # YAML 파일을 읽어 매핑 테이블을 구성한다.
        data = yaml.safe_load(path.read_text()) or {}
        mapping: Dict[str, Set[str]] = {}

        for item in data.get("mappings", []):
            # KISA 코드를 정규화하고, 대응되는 OWASP 태그를 수집한다.
            kisa = normalize_tag(item.get("kisa"))
            if not kisa:
                continue
            owasp_tags = [normalize_tag(tag) for tag in item.get("owasp", [])]
            mapping.setdefault(kisa, set()).update(tag for tag in owasp_tags if tag)

        return cls(mapping)

    @classmethod
    def from_default(cls) -> "TaxonomyIndex":
        # 기본 매핑 파일이 있으면 로드하고 없으면 빈 매핑을 사용한다.
        if DEFAULT_MAPPING_FILE.exists():
            return cls.from_file(DEFAULT_MAPPING_FILE)
        return cls({})

    def resolve_kisa_to_owasp(self, kisa_code: str) -> List[str]:
        # KISA 코드에 대응되는 OWASP 태그 목록을 반환한다.
        normalized = normalize_tag(kisa_code)
        return sorted(self.kisa_to_owasp.get(normalized, set()))

    def expand_tags(self, tags: Iterable[str]) -> List[str]:
        # 입력된 태그를 정규화하고 KISA 태그는 OWASP로 확장한다.
        expanded: List[str] = []
        seen: Set[str] = set()

        for tag in tags:
            normalized = normalize_tag(tag)
            if not normalized or normalized in seen:
                continue
            expanded.append(normalized)
            seen.add(normalized)

            # KISA 패턴이면 매핑된 OWASP 태그를 뒤에 붙인다.
            if KISA_CODE_PATTERN.match(normalized):
                for mapped in self.kisa_to_owasp.get(normalized, set()):
                    if mapped not in seen:
                        expanded.append(mapped)
                        seen.add(mapped)

        return expanded
