"""Strix report parser."""

from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from app.core.types import Finding


_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

_DESC_HEADERS = {"description", "issue", "summary"}
_EVIDENCE_HEADERS = {"evidence", "unauthenticated evidence", "artifacts"}
_REMEDIATION_HEADERS = {"remediation", "fix", "mitigation"}
_REFERENCE_HEADERS = {"references"}


def parse_strix_report(run_dir: Path) -> List[Finding]:
    run_dir = Path(run_dir)
    csv_path = run_dir / "vulnerabilities.csv"
    vuln_dir = run_dir / "vulnerabilities"
    report_path = run_dir / "penetration_test_report.md"

    findings: List[Finding] = []
    if csv_path.exists():
        for row in _read_csv(csv_path):
            findings.append(
                _build_finding_from_row(
                    row=row,
                    run_dir=run_dir,
                    report_path=report_path if report_path.exists() else None,
                )
            )
    else:
        for md_path in sorted(vuln_dir.glob("vuln-*.md")):
            findings.append(
                _build_finding_from_markdown(
                    md_path,
                    run_dir=run_dir,
                    report_path=report_path if report_path.exists() else None,
                )
            )

    if not findings:
        findings.append(
            Finding(
                vuln_id="STRIX-RAW-ONLY",
                title="Raw report only",
                severity="Info",
                evidence={"report_dir": str(run_dir)},
                tags=["STRIX"],
                description="No Strix findings could be parsed.",
                solution="Check Strix outputs and parser configuration.",
            )
        )
    return findings


def _read_csv(csv_path: Path) -> Iterable[Dict[str, str]]:
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            yield {key: (value or "").strip() for key, value in row.items()}


def _build_finding_from_row(
    *,
    row: Dict[str, str],
    run_dir: Path,
    report_path: Optional[Path],
) -> Finding:
    vuln_id = row.get("id") or "STRIX-UNKNOWN"
    title = row.get("title") or "Strix finding"
    severity = _normalize_severity(row.get("severity"))
    timestamp = row.get("timestamp")
    file_path = row.get("file")
    md_path = run_dir / file_path if file_path else None

    detail = _parse_markdown(md_path) if md_path and md_path.exists() else {}
    description = detail.get("description")
    solution = detail.get("solution")
    tags = _merge_tags(detail.get("tags"), ["STRIX"])

    evidence: Dict[str, Any] = {
        "run_dir": str(run_dir),
        "vulnerability_path": str(md_path) if md_path else None,
        "timestamp": timestamp or None,
    }
    if report_path:
        evidence["penetration_report_path"] = str(report_path)
    if detail.get("evidence"):
        evidence["evidence"] = detail["evidence"]

    raw_data = {
        "row": row,
        "metadata": detail.get("metadata"),
    }

    return Finding(
        vuln_id=vuln_id,
        title=detail.get("title") or title,
        severity=severity,
        evidence=evidence,
        tags=tags,
        description=description,
        solution=solution,
        raw_data=raw_data,
    )


def _build_finding_from_markdown(
    md_path: Path,
    run_dir: Path,
    report_path: Optional[Path],
) -> Finding:
    detail = _parse_markdown(md_path) if md_path.exists() else {}
    metadata = detail.get("metadata") or {}
    vuln_id = metadata.get("id") or md_path.stem
    severity = _normalize_severity(metadata.get("severity"))
    tags = _merge_tags(detail.get("tags"), ["STRIX"])

    evidence: Dict[str, Any] = {
        "run_dir": str(run_dir),
        "vulnerability_path": str(md_path),
    }
    if report_path:
        evidence["penetration_report_path"] = str(report_path)
    if detail.get("evidence"):
        evidence["evidence"] = detail["evidence"]

    return Finding(
        vuln_id=vuln_id,
        title=detail.get("title") or "Strix finding",
        severity=severity,
        evidence=evidence,
        tags=tags,
        description=detail.get("description"),
        solution=detail.get("solution"),
        raw_data={"metadata": metadata},
    )


def _parse_markdown(md_path: Optional[Path]) -> Dict[str, Any]:
    if md_path is None:
        return {}
    text = md_path.read_text(encoding="utf-8")
    title = _extract_title(text)
    metadata = _extract_metadata(text)
    sections = _split_sections(text)

    description = _first_section(sections, _DESC_HEADERS)
    solution = _first_section(sections, _REMEDIATION_HEADERS)
    evidence_texts = _collect_sections(sections, _EVIDENCE_HEADERS)
    references = _first_section(sections, _REFERENCE_HEADERS)

    evidence = _build_evidence(evidence_texts)
    tags = _extract_tags(references)

    return {
        "title": title,
        "metadata": metadata,
        "description": description,
        "solution": solution,
        "evidence": evidence,
        "tags": tags,
    }


def _extract_title(text: str) -> Optional[str]:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("# "):
            return stripped[2:].strip()
    return None


def _extract_metadata(text: str) -> Dict[str, Optional[str]]:
    metadata: Dict[str, Optional[str]] = {}
    for line in text.splitlines():
        if line.startswith("**ID:**"):
            metadata["id"] = line.split("**ID:**", 1)[1].strip()
        elif line.startswith("**Severity:**"):
            metadata["severity"] = line.split("**Severity:**", 1)[1].strip()
        elif line.startswith("**Found:**"):
            metadata["found"] = line.split("**Found:**", 1)[1].strip()
    return metadata


def _split_sections(text: str) -> Dict[str, str]:
    sections: Dict[str, List[str]] = {}
    current: Optional[str] = None

    for line in text.splitlines():
        header = _parse_header(line)
        if header is not None:
            current = header
            sections.setdefault(current, [])
            continue
        if current is None:
            continue
        sections[current].append(line)

    return {key: _normalize_section("\n".join(lines)) for key, lines in sections.items()}


def _parse_header(line: str) -> Optional[str]:
    stripped = line.strip()
    match = re.match(r"^(#{2,3})\s+(.*)$", stripped)
    if not match:
        for header in (
            "description",
            "issue",
            "summary",
            "evidence",
            "unauthenticated evidence",
            "artifacts",
            "remediation",
            "fix",
            "mitigation",
            "references",
        ):
            if stripped.lower().startswith(header) and stripped.endswith(":"):
                return header
        return None
    return match.group(2).strip().lower()


def _normalize_section(text: str) -> str:
    lines = [line.rstrip() for line in text.splitlines()]
    normalized = "\n".join(lines).strip()
    return _collapse_blank_lines(normalized)


def _collapse_blank_lines(text: str) -> str:
    lines = []
    blank = False
    for line in text.splitlines():
        if line.strip():
            lines.append(line)
            blank = False
        else:
            if not blank:
                lines.append("")
            blank = True
    return "\n".join(lines).strip()


def _first_section(sections: Dict[str, str], headers: set[str]) -> Optional[str]:
    for key, value in sections.items():
        if key in headers and value:
            return value
    return None


def _collect_sections(sections: Dict[str, str], headers: set[str]) -> List[str]:
    collected = []
    for key, value in sections.items():
        if key in headers and value:
            collected.append(value)
    return collected


def _build_evidence(chunks: List[str]) -> Optional[Dict[str, Any]]:
    if not chunks:
        return None
    items: List[str] = []
    paths: List[str] = []
    for chunk in chunks:
        for line in chunk.splitlines():
            stripped = line.strip()
            if stripped.startswith("-"):
                item = stripped.lstrip("-").strip()
                if item:
                    items.append(item)
                    if "/" in item or item.endswith((".hdr", ".html", ".log", ".txt")):
                        paths.append(item)
    return {
        "summary": "\n\n".join(chunks).strip(),
        "items": items or None,
        "paths": paths or None,
    }


def _extract_tags(reference_text: Optional[str]) -> List[str]:
    if not reference_text:
        return []
    tags: List[str] = []
    for line in reference_text.splitlines():
        match = re.search(r"OWASP.*?(20\d{2}).*?A(\d{2})", line, re.IGNORECASE)
        if match:
            tags.append(f"OWASP:{match.group(1)}:A{match.group(2)}")
    return tags


def _normalize_severity(value: Optional[str]) -> str:
    if not value:
        return "Info"
    key = value.strip().lower()
    return _SEVERITY_MAP.get(key, value.title())


def _merge_tags(extra: Optional[List[str]], base: List[str]) -> List[str]:
    tags = list(base)
    for tag in extra or []:
        if tag and tag not in tags:
            tags.append(tag)
    return tags
