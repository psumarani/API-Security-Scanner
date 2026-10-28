"""Request/response schemas for application-user authentication."""

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.core.security import MAX_PASSWORD_BYTES
from app.models.enums import UserRole

_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,31}$")


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)

    @field_validator("username")
    @classmethod
    def _username_format(cls, value: str) -> str:
        value = value.strip().lower()
        if not _USERNAME_RE.fullmatch(value):
            raise ValueError(
                "username may contain letters, digits, '.', '_' and '-' and must start with "
                "a letter or digit"
            )
        return value

    @field_validator("email")
    @classmethod
    def _email_lowercase(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("password")
    @classmethod
    def _password_policy(cls, value: str) -> str:
        if len(value.encode("utf-8")) > MAX_PASSWORD_BYTES:
            raise ValueError(f"password must be at most {MAX_PASSWORD_BYTES} bytes")
        if not value.strip():
            raise ValueError("password must not be blank")
        if len(set(value)) < 5:
            raise ValueError("password is too repetitive")
        return value


class LoginRequest(BaseModel):
    identifier: str = Field(min_length=1, max_length=254, description="Username or email")
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105
    expires_at: datetime


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime


class SessionRead(BaseModel):
    id: uuid.UUID
    created_at: datetime
    expires_at: datetime
    current: bool
