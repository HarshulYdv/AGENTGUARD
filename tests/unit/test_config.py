"""Unit tests for configuration management."""

import pytest
from pydantic import ValidationError
from backend.core.config import Settings


def test_default_settings() -> None:
    """Verify default settings instantiation."""
    settings = Settings()
    assert settings.app_name == "AGENTGUARD"
    assert settings.app_env in {"development", "testing", "production"}
    assert settings.port == 8000
    assert settings.log_level == "INFO"
    assert isinstance(settings.cors_origins, list)


def test_cors_origins_parsing() -> None:
    """Verify comma-delimited string parsing for CORS origins."""
    settings = Settings(cors_origins="http://example.com, https://agentguard.io")
    assert settings.cors_origins == ["http://example.com", "https://agentguard.io"]


def test_invalid_log_level() -> None:
    """Ensure invalid log levels raise validation error."""
    with pytest.raises(ValidationError):
        Settings(log_level="SUPER_CRITICAL")

