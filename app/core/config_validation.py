"""이 파일은 .py 플러그인 설정 스키마 검증 모듈입니다."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .errors import PluginConfigError


_TYPE_MAP = {
    # JSON 스키마 타입을 파이썬 타입으로 매핑한다.
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "object": dict,
    "array": list,
}


def apply_config_schema(schema: Optional[Dict[str, Any]], config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    # 스키마가 없으면 전달된 설정을 그대로 반환한다.
    if not schema:
        return config or {}
    # 설정이 없으면 빈 딕셔너리로 시작한다.
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise PluginConfigError("Plugin config must be an object")

    # properties/required를 읽어 기본값과 필수값을 처리한다.
    props = schema.get("properties", {})
    required = schema.get("required", [])
    errors = []
    result = dict(config)

    for key in required:
        # 필수 필드가 없으면 default를 주입하거나 오류로 수집한다.
        if key not in result:
            default = props.get(key, {}).get("default")
            if default is not None:
                result[key] = default
            else:
                errors.append(f"Missing required config: {key}")

    for key, spec in props.items():
        # default가 명시된 항목은 값이 없을 때 자동 주입한다.
        if key not in result and "default" in spec:
            result[key] = spec["default"]

    for key, value in result.items():
        # 각 항목에 대해 타입/범위/패턴을 검증한다.
        spec = props.get(key)
        if not spec:
            continue
        expected = spec.get("type")
        if expected:
            expected_type = _TYPE_MAP.get(expected)
            if expected_type is None:
                errors.append(f"Unsupported type in schema: {expected}")
            else:
                # bool은 int의 하위 타입이므로 integer 검증에서 예외 처리한다.
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
                # 정규식을 사용해 패턴 유효성을 검사한다.
                pattern = re.compile(spec["pattern"])
                if not pattern.search(value):
                    errors.append(f"Config '{key}' does not match pattern")

    if errors:
        # 누적된 오류를 하나의 예외로 전달한다.
        raise PluginConfigError("; ".join(errors))

    # 기본값/검증이 반영된 설정을 반환한다.
    return result
