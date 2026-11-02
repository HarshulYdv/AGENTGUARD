"""Unit tests for centralized logging."""

import logging
from backend.core.config import Settings
from backend.core.logging import JSONFormatter, get_logger, setup_logging


def test_get_logger_prefix() -> None:
    """Verify logger names are properly namespaced under agentguard."""
    logger1 = get_logger("core")
    assert logger1.name == "agentguard.core"

    logger2 = get_logger("agentguard.security")
    assert logger2.name == "agentguard.security"


def test_setup_logging_console() -> None:
    """Verify setup_logging configures root logger without error."""
    settings = Settings(log_level="DEBUG", log_format="console")
    setup_logging(settings)
    root = logging.getLogger()
    assert root.level == logging.DEBUG


def test_json_formatter() -> None:
    """Verify JSONFormatter outputs valid JSON."""
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test_path.py",
        lineno=42,
        msg="Test log message",
        args=(),
        exc_info=None,
    )
    formatted = formatter.format(record)
    assert '"level": "INFO"' in formatted
    assert '"message": "Test log message"' in formatted

