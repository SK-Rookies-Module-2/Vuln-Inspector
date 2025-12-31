"""이 파일은 .py 플러그인 설정 스키마 검증 모듈입니다."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .errors import PluginConfigError


_TYPE_MAP = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "object": dict,
    "array": list,
}


def apply_config_schema(schema: Optional[Dict[str, Any]], config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not schema:
        return config or {}
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise PluginConfigError("Plugin config must be an object")

    props = schema.get("properties", {})
    required = schema.get("required", [])
    errors = []
    result = dict(config)

    for key in required:
        if key not in result:
            default = props.get(key, {}).get("default")
            if default is not None:
                result[key] = default
            else:
                errors.append(f"Missing required config: {key}")

    for key, spec in props.items():
        if key not in result and "default" in spec:
            result[key] = spec["default"]

    for key, value in result.items():
        spec = props.get(key)
        if not spec:
            continue
        expected = spec.get("type")
        if expected:
            expected_type = _TYPE_MAP.get(expected)
            if expected_type is None:
                errors.append(f"Unsupported type in schema: {expected}")
            else:
                if expected == "integer" and isinstance(value, bool):
                    errors.append(f"Config '{key}' must be integer")
                elif not isinstance(value, expected_type):
                    errors.append(f"Config '{key}' must be {expected}")
        if "enum" in spec and value not in spec["enum"]:
            errors.append(f"Config '{key}' must be one of {spec['enum']}")
        if isinstance(value, (int, float)):
            if "min" in spec and value < spec["min"]:
                errors.append(f"Config '{key}' must be >= {spec['min']}")
            if "max" in spec and value > spec["max"]:
                errors.append(f"Config '{key}' must be <= {spec['max']}")
        if isinstance(value, str):
            if "min_length" in spec and len(value) < spec["min_length"]:
                errors.append(f"Config '{key}' length must be >= {spec['min_length']}")
            if "max_length" in spec and len(value) > spec["max_length"]:
                errors.append(f"Config '{key}' length must be <= {spec['max_length']}")
            if "pattern" in spec:
                pattern = re.compile(spec["pattern"])
                if not pattern.search(value):
                    errors.append(f"Config '{key}' does not match pattern")

    if errors:
        raise PluginConfigError("; ".join(errors))

    return result
