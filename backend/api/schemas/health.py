"""Pydantic schemas for health check and system diagnostic endpoints."""

from datetime import datetime, timezone
from typing import Dict, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Schema representing the health status and diagnostics of the service."""

    status: str = Field(default="ok", description="Overall service status (e.g., 'ok', 'degraded')")
    app_name: str = Field(description="Name of the service")
    version: str = Field(description="Running version of the application")
    environment: str = Field(description="Deployment environment name")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Current UTC timestamp of the health report",
    )
    database: str = Field(
        default="connected",
        description="Database connectivity status: 'connected', 'unreachable', or 'disabled'",
    )
    details: Optional[Dict[str, str]] = Field(
        default=None,
        description="Optional diagnostic metadata or subsystem checks",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "status": "ok",
                "app_name": "AGENTGUARD",
                "version": "0.1.0",
                "environment": "development",
                "timestamp": "2026-11-03T02:00:00Z",
                "database": "connected",
                "details": {
                    "database_backend": "sqlite",
                },
            }
        }
    }

