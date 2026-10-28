"""Scan configuration with hard upper bounds (validated on the server, never trusted from UI)."""

import uuid

from pydantic import BaseModel, Field, field_validator

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _relative_path(value: str) -> str:
    if not value.startswith("/") or "://" in value or value.startswith("//"):
        raise ValueError("path must be relative to the target base URL and start with '/'")
    if any(ord(c) < 32 or c in " \\" for c in value):
        raise ValueError("path contains invalid characters")
    if len(value) > 1024:
        raise ValueError("path is too long")
    return value


class SqliSettings(BaseModel):
    max_endpoints: int = Field(default=25, ge=1, le=100)
    max_parameters: int = Field(default=5, ge=1, le=10)


class RateLimitSettings(BaseModel):
    requests: int = Field(default=30, ge=5, le=100)
    concurrency: int = Field(default=5, ge=1, le=10)
    path: str | None = Field(default=None, description="GET path to probe; defaults to a safe GET")

    @field_validator("path")
    @classmethod
    def _path_ok(cls, value: str | None) -> str | None:
        return _relative_path(value) if value else None


class BolaObject(BaseModel):
    """A known object and the test account that owns it."""

    path: str
    owner: uuid.UUID = Field(description="Auth profile id of the owner")

    @field_validator("path")
    @classmethod
    def _path_ok(cls, value: str) -> str:
        return _relative_path(value)


class BflaRule(BaseModel):
    """Expected permission for one operation."""

    method: str = "GET"
    path: str
    allowed: list[uuid.UUID] = Field(default_factory=list, max_length=10)
    forbidden: list[uuid.UUID] = Field(min_length=1, max_length=10)

    @field_validator("method")
    @classmethod
    def _method_ok(cls, value: str) -> str:
        value = value.upper()
        if value not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("unsupported HTTP method")
        return value

    @field_validator("path")
    @classmethod
    def _path_ok(cls, value: str) -> str:
        return _relative_path(value)


class ScanSettings(BaseModel):
    timeout_seconds: float = Field(default=10.0, ge=1, le=30)
    max_requests: int = Field(default=300, ge=10, le=2000)
    max_concurrency: int = Field(default=3, ge=1, le=10)
    max_duration_seconds: int = Field(default=600, ge=30, le=3600)
    max_endpoints: int = Field(default=200, ge=1, le=500)
    max_endpoints_per_module: int = Field(default=40, ge=1, le=200)
    allow_unsafe_methods: bool = Field(
        default=False, description="Allow state-changing methods (only BFLA rules use them)."
    )
    verify_tls: bool = True
    sqli: SqliSettings = SqliSettings()
    rate_limit: RateLimitSettings = RateLimitSettings()
    bola_objects: list[BolaObject] = Field(default_factory=list, max_length=25)
    bfla_rules: list[BflaRule] = Field(default_factory=list, max_length=25)
