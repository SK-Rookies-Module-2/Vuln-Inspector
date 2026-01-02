import re
from typing import Dict, Iterable

def strip_comments(lines: list[str]) -> list[str]:
    stripped = []
    for line in lines:
        line = line.strip()
        
        if not line or line.startswith("#"):
            continue
        line = re.split(r'\s+#', line, maxsplit=1)[0].strip()
        stripped.append(line)
    return stripped

def parse_kv_lines(lines: Iterable[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}

    for line in lines:
        # key=value 형식
        m = re.match(r'^([A-Za-z0-9_.-]+)\s*=\s*(.+)$', line)
        if m:
            out[m.group(1)] = m.group(2).strip()
            continue
        
        # key value 형식
        m = re.match(r'^([A-Za-z0-9_.-]+)\s+(.+)$', line)
        if m:
            out[m.group(1)] = m.group(2).strip()
            continue
    return out