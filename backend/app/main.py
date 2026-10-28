"""FastAPI application entry point."""

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api import health
from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.errors import register_error_handlers

logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """On startup, fail any scan a previous process left queued or running."""
    from app.db.session import get_sessionmaker
    from app.services.scan_runner import recover_interrupted_scans

    try:
        recovered = recover_interrupted_scans(get_sessionmaker())
        if recovered:
            logger.warning("Marked %d interrupted scan(s) as failed", recovered)
    except Exception:  # noqa: BLE001 - e.g. database not migrated yet
        logger.exception("Could not recover interrupted scans")
    yield


app = FastAPI(title=settings.app_name, version=__version__, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def security_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


register_error_handlers(app)
app.include_router(health.router, prefix="/api")
app.include_router(api_router, prefix="/api/v1")
