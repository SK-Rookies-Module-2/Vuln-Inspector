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
    if not tag:
        return ""
    return tag.strip().upper()


@dataclass(frozen=True)
class MappingEntry:
    kisa: str
    owasp: List[str]
    title: Optional[str] = None
    note: Optional[str] = None


class TaxonomyIndex:
    def __init__(self, kisa_to_owasp: Dict[str, Set[str]]):
        self.kisa_to_owasp = kisa_to_owasp

    @classmethod
    def from_file(cls, path: Path) -> "TaxonomyIndex":
        data = yaml.safe_load(path.read_text()) or {}
        mapping: Dict[str, Set[str]] = {}

        for item in data.get("mappings", []):
            kisa = normalize_tag(item.get("kisa"))
            if not kisa:
                continue
            owasp_tags = [normalize_tag(tag) for tag in item.get("owasp", [])]
            mapping.setdefault(kisa, set()).update(tag for tag in owasp_tags if tag)

        return cls(mapping)

    @classmethod
    def from_default(cls) -> "TaxonomyIndex":
        if DEFAULT_MAPPING_FILE.exists():
            return cls.from_file(DEFAULT_MAPPING_FILE)
        return cls({})

    def resolve_kisa_to_owasp(self, kisa_code: str) -> List[str]:
        normalized = normalize_tag(kisa_code)
        return sorted(self.kisa_to_owasp.get(normalized, set()))

    def expand_tags(self, tags: Iterable[str]) -> List[str]:
        expanded: List[str] = []
        seen: Set[str] = set()

        for tag in tags:
            normalized = normalize_tag(tag)
            if not normalized or normalized in seen:
                continue
            expanded.append(normalized)
            seen.add(normalized)

            if KISA_CODE_PATTERN.match(normalized):
                for mapped in self.kisa_to_owasp.get(normalized, set()):
                    if mapped not in seen:
                        expanded.append(mapped)
                        seen.add(mapped)

        return expanded
