"""이 파일은 .py 테스트 모듈로 플러그인 설정 스키마를 검증합니다."""

from app.core.config_validation import apply_config_schema
from app.core.errors import PluginConfigError


def test_apply_config_schema_defaults() -> None:
    schema = {
        "properties": {
            "path": {"type": "string", "default": "requirements.txt"},
        }
    }
    result = apply_config_schema(schema, {})
    assert result["path"] == "requirements.txt"


def test_apply_config_schema_type_error() -> None:
    schema = {"properties": {"port": {"type": "integer"}}}
    try:
        apply_config_schema(schema, {"port": "not-int"})
    except PluginConfigError as exc:
        assert "port" in str(exc)
    else:
        raise AssertionError("PluginConfigError not raised")


def test_apply_config_schema_min_validation() -> None:
    schema = {"properties": {"timeout": {"type": "integer", "min": 1}}}
    try:
        apply_config_schema(schema, {"timeout": 0})
    except PluginConfigError as exc:
        assert "timeout" in str(exc)
    else:
        raise AssertionError("PluginConfigError not raised")
