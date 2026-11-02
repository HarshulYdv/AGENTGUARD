"""Main API routing aggregation."""

from fastapi import APIRouter
from backend.api.routes.health import router as health_router

# Version 1 Router
api_v1_router = APIRouter()
api_v1_router.include_router(health_router)

__all__ = ["api_v1_router", "health_router"]

