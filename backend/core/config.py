"""Configuration management for AGENTGUARD using Pydantic Settings."""

import json
from functools import lru_cache
from typing import List, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable fallback and validation."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Core Application Settings
    app_name: str = Field(default="AGENTGUARD", description="Human-readable application name")
    app_env: str = Field(default="development", description="Environment mode: development, testing, production")
    debug: bool = Field(default=True, description="Debug mode flag")
    api_v1_prefix: str = Field(default="/api/v1", description="Prefix for API version 1 routes")

    # Networking
    host: str = Field(default="127.0.0.1", description="Host interface to bind")
    port: int = Field(default=8000, ge=1, le=65535, description="Port number to bind")

    # Logging
    log_level: str = Field(default="INFO", description="Log verbosity level (DEBUG, INFO, WARNING, ERROR, CRITICAL)")
    log_format: str = Field(default="console", description="Logging output format (console, json)")

    # Database
    database_url: str = Field(
        default="sqlite:///./data/agentguard.db",
        description="Database connection string (SQLite by default)",
    )

    # CORS Settings (Accepts JSON array or comma-separated string)
    cors_origins: Union[List[str], str] = Field(
        default_factory=lambda: [
            "http://localhost:8501",
            "http://127.0.0.1:8501",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ],
        description="Allowed CORS origins",
    )

    @field_validator("cors_origins")
    @classmethod
    def assemble_cors_origins(cls, value: Union[str, List[str]]) -> List[str]:
        """Parse comma-separated origin string or validate existing list."""
        if isinstance(value, str):
            value = value.strip()
            if value.startswith("[") and value.endswith("]"):
                try:
                    parsed = json.loads(value)
                    if isinstance(parsed, list):
                        return [str(origin).strip() for origin in parsed if str(origin).strip()]
                except Exception:
                    pass
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        if isinstance(value, list):
            return [str(origin).strip() for origin in value if str(origin).strip()]
        return []

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        """Ensure provided log level is valid."""
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper_val = value.upper()
        if upper_val not in allowed:
            raise ValueError(f"Invalid log_level '{value}'. Allowed: {sorted(allowed)}")
        return upper_val


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retrieve cached application settings instance."""
    return Settings()
