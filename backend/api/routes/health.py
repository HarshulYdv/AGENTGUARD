"""Health check and diagnostic route handlers."""

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend import __version__
from backend.api.schemas.health import HealthResponse
from backend.core.config import Settings, get_settings
from backend.core.logging import get_logger
from backend.database.session import get_db

logger = get_logger("api.health")
router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service Health Check",
    description="Returns the runtime health status, version information, and database connectivity.",
)
def get_health(
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> HealthResponse | JSONResponse:
    """Evaluate application health and subsystem connectivity."""
    db_status = "connected"
    overall_status = "ok"

    try:
        # Perform quick non-blocking verification of database connectivity
        db.execute(text("SELECT 1"))
    except Exception as exc:
        logger.error(f"Database health check probe failed: {exc}", exc_info=True)
        db_status = "unreachable"
        overall_status = "degraded"

    response_data = HealthResponse(
        status=overall_status,
        app_name=settings.app_name,
        version=__version__,
        environment=settings.app_env,
        database=db_status,
        details={
            "database_url": settings.database_url.split("@")[-1] if "@" in settings.database_url else settings.database_url.split("///")[-1],
        },
    )

    if overall_status != "ok":
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=response_data.model_dump(mode="json"),
        )

    return response_data

