"""Aggregates all v1 routers."""

from fastapi import APIRouter

from app.api.v1.endpoints import auth, findings, scanner, scans, targets

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(targets.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(scanner.router)
