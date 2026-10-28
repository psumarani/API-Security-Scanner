"""Shared FastAPI dependencies: database session and authenticated user."""

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.errors import AuthenticationError, PermissionDenied
from app.db.session import get_db
from app.models.enums import UserRole
from app.models.user import User, UserSession
from app.scanner.scope_validator import Resolver, system_resolver
from app.services import auth_service

_bearer = HTTPBearer(auto_error=False, description="Access token from POST /auth/login")

DbSession = Annotated[Session, Depends(get_db)]


@dataclass
class AuthContext:
    user: User
    session: UserSession


def get_auth_context(
    db: DbSession,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> AuthContext:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise AuthenticationError()
    user, session = auth_service.resolve_token(db, credentials.credentials)
    return AuthContext(user=user, session=session)


def get_current_user(ctx: Annotated[AuthContext, Depends(get_auth_context)]) -> User:
    return ctx.user


CurrentUser = Annotated[User, Depends(get_current_user)]
CurrentAuth = Annotated[AuthContext, Depends(get_auth_context)]


def require_admin(user: CurrentUser) -> User:
    if user.role != UserRole.ADMIN:
        raise PermissionDenied("Administrator role required")
    return user


def get_resolver() -> Resolver:
    """DNS resolver used for scope validation (overridable in tests)."""
    return system_resolver
