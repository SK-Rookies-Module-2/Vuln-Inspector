"""이 파일은 .py 공통 예외 모듈로 오류 유형을 표준화합니다."""


class PluginConfigError(ValueError):
    """플러그인 설정 검증 실패 시 사용합니다."""


class AdapterError(RuntimeError):
    """외부 어댑터 실행 오류에 사용합니다."""


class ScanExecutionError(RuntimeError):
    """스캔 실행 중 발생한 오류를 감싸는 예외입니다."""
