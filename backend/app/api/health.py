"""Liveness endpoint."""

from fastapi import APIRouter

from app import __version__
from app.core.config import get_settings

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict[str, str]:
    settings = get_settings()
    return {
        "status": "ok",
        "service": "api-security-scanner",
        "version": __version__,
        "environment": settings.environment,
    }
