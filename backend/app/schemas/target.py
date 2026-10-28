"""Schemas for scan targets and target-API authentication profiles."""

import re
import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from app.models.enums import AuthType

_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")
_FORBIDDEN_HEADERS = frozenset(
    {"host", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer"}
)
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def _no_control_chars(value: str, field: str) -> str:
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(f"{field} must not contain control characters")
    return value


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    base_url: str = Field(min_length=1, max_length=2048)
    api_spec_url: str | None = Field(default=None, max_length=2048)
    authorization_confirmed: bool = Field(
        description=(
            "Must be true: confirms you own the target or have written permission to test it."
        )
    )
    authorization_note: str | None = Field(default=None, max_length=1000)
    allow_local_lab: bool = False

    @field_validator("name")
    @classmethod
    def _name_clean(cls, value: str) -> str:
        value = _no_control_chars(value.strip(), "name")
        if not value:
            raise ValueError("name must not be blank")
        return value

    @field_validator("api_spec_url")
    @classmethod
    def _blank_spec_is_none(cls, value: str | None) -> str | None:
        return value.strip() or None if value else None


class TargetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    base_url: str
    api_spec_url: str | None
    authorization_confirmed_at: datetime
    authorization_note: str | None
    allow_local_lab: bool
    created_at: datetime
    updated_at: datetime


# ---- Target-API credentials -------------------------------------------------------------


class NoAuthConfig(BaseModel):
    type: Literal["none"]


class BearerConfig(BaseModel):
    type: Literal["bearer"]
    token: SecretStr = Field(min_length=1, max_length=4096)

    @field_validator("token")
    @classmethod
    def _token_clean(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if raw != raw.strip() or any(ch.isspace() for ch in raw):
            raise ValueError("token must not contain whitespace")
        _no_control_chars(raw, "token")
        return value


class ApiKeyConfig(BaseModel):
    type: Literal["api_key"]
    name: str = Field(description="Header or query-parameter name, e.g. X-API-Key")
    location: Literal["header", "query"] = "header"
    value: SecretStr = Field(min_length=1, max_length=4096)

    @field_validator("name")
    @classmethod
    def _name_valid(cls, value: str) -> str:
        if not _HEADER_NAME_RE.fullmatch(value):
            raise ValueError("invalid header or parameter name")
        if value.lower() in _FORBIDDEN_HEADERS:
            raise ValueError("this header name is not allowed")
        return value

    @field_validator("value")
    @classmethod
    def _value_clean(cls, value: SecretStr) -> SecretStr:
        _no_control_chars(value.get_secret_value(), "value")
        return value


class AccountLoginConfig(BaseModel):
    type: Literal["test_account"]
    username: str = Field(min_length=1, max_length=254)
    password: SecretStr = Field(min_length=1, max_length=256)
    # Optional: how to obtain a bearer token for this account (relative to the target base URL).
    login_path: str | None = Field(default=None, max_length=512)
    username_field: str = Field(default="username", max_length=64)
    password_field: str = Field(default="password", max_length=64)
    token_field: str = Field(default="access_token", max_length=64, description="Dotted JSON path")

    @field_validator("login_path")
    @classmethod
    def _login_path_ok(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.startswith("/") or value.startswith("//") or "://" in value:
            raise ValueError("login_path must be a path starting with '/'")
        return _no_control_chars(value, "login_path")


AuthConfig = Annotated[
    NoAuthConfig | BearerConfig | ApiKeyConfig | AccountLoginConfig, Field(discriminator="type")
]


class AuthProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    role_label: str | None = Field(
        default=None, description="Label used by BOLA/BFLA checks, e.g. user_a, user_b, admin"
    )
    config: AuthConfig

    @field_validator("name")
    @classmethod
    def _name_clean(cls, value: str) -> str:
        value = _no_control_chars(value.strip(), "name")
        if not value:
            raise ValueError("name must not be blank")
        return value

    @field_validator("role_label")
    @classmethod
    def _label_valid(cls, value: str | None) -> str | None:
        if value is not None and not _LABEL_RE.fullmatch(value):
            raise ValueError("role_label may contain letters, digits, '.', '_' and '-'")
        return value


class AuthProfileRead(BaseModel):
    """Secrets are never returned."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_id: uuid.UUID
    name: str
    auth_type: AuthType
    role_label: str | None
    has_credentials: bool
    created_at: datetime
