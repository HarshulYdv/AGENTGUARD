"""FastAPI application entrypoint for AGENTGUARD."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend import __version__
from backend.api.router import api_v1_router, health_router
from backend.core.config import Settings, get_settings
from backend.core.logging import get_logger, setup_logging
from backend.database.session import init_db

logger = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown lifecycle events."""
    settings = get_settings()
    setup_logging(settings)
    logger.info(f"Starting {settings.app_name} v{__version__} [{settings.app_env}]")

    # Initialize database tables
    try:
        init_db()
    except Exception as exc:
        logger.error(f"Failed to initialize database during startup: {exc}", exc_info=True)

    yield

    logger.info(f"Shutting down {settings.app_name}...")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory for AGENTGUARD FastAPI service."""
    if settings is None:
        settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        description="Task-aware runtime security and reliability framework for autonomous AI agents",
        version=__version__,
        debug=settings.debug,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url=f"{settings.api_v1_prefix}/openapi.json",
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Root probe endpoint for container orchestrators and load balancers
    app.include_router(health_router)

    # Versioned API routes
    app.include_router(api_v1_router, prefix=settings.api_v1_prefix)

    @app.get("/", tags=["Root"], include_in_schema=False)
    def root() -> JSONResponse:
        """Root landing endpoint providing service metadata."""
        return JSONResponse(
            content={
                "name": settings.app_name,
                "version": __version__,
                "docs_url": "/docs",
                "health_url": "/health",
                "api_v1_prefix": settings.api_v1_prefix,
            }
        )

    return app


app = create_app()

if __name__ == "__main__":
    current_settings = get_settings()
    uvicorn.run(
        "backend.main:app",
        host=current_settings.host,
        port=current_settings.port,
        reload=current_settings.debug,
    )

