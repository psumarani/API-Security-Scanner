"""Registration, login, session lifecycle and token verification."""

import hmac
import uuid
from datetime import UTC, datetime

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AuthenticationError, ConflictError, RateLimitExceeded
from app.core.rate_limit import limiter
from app.core.security import (
    TokenError,
    create_access_token,
    decode_access_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.models.enums import UserRole
from app.models.mixins import as_utc
from app.models.user import User, UserSession
from app.schemas.auth import LoginRequest, RegisterRequest

_dummy_hash: str | None = None


def _dummy_password_hash() -> str:
    """A valid hash to compare against when the user does not exist (equalizes timing)."""
    global _dummy_hash  # noqa: PLW0603
    if _dummy_hash is None:
        _dummy_hash = hash_password("not-a-real-password-for-timing-only")
    return _dummy_hash


def register_user(db: Session, data: RegisterRequest) -> User:
    """Create a normal user. The role is never taken from the request."""
    exists = db.scalar(
        select(User.id).where(or_(User.username == data.username, User.email == data.email))
    )
    if exists is not None:
        raise ConflictError("Username or email is already registered")
    user = User(
        username=data.username,
        email=data.email,
        password_hash=hash_password(data.password),
        role=UserRole.USER,
        is_active=True,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:  # lost a race with a concurrent registration
        db.rollback()
        raise ConflictError("Username or email is already registered") from exc
    db.refresh(user)
    return user


def authenticate(db: Session, data: LoginRequest) -> User:
    """Verify credentials. Failures are indistinguishable and throttled per identifier."""
    settings = get_settings()
    identifier = data.identifier.strip().lower()
    fail_key = f"login-fail:{identifier}"
    window = settings.auth_failed_login_window_seconds

    if limiter.count(fail_key, window) >= settings.auth_max_failed_logins:
        raise RateLimitExceeded(
            "Too many failed login attempts. Try again later.",
            headers={"Retry-After": str(limiter.retry_after(fail_key, window))},
        )

    user = db.scalar(select(User).where(or_(User.username == identifier, User.email == identifier)))
    password_ok = verify_password(
        data.password, user.password_hash if user else _dummy_password_hash()
    )
    if user is None or not password_ok or not user.is_active:
        limiter.hit(fail_key, settings.auth_max_failed_logins, window)
        raise AuthenticationError("Invalid credentials")

    limiter.reset(fail_key)
    return user


def create_session(db: Session, user: User) -> tuple[str, datetime]:
    """Create a session and return (access_token, expires_at). Only the token hash is stored."""
    session_id = uuid.uuid4()
    token, expires_at = create_access_token(user.id, session_id)
    db.add(
        UserSession(
            id=session_id, user_id=user.id, token_hash=hash_token(token), expires_at=expires_at
        )
    )
    db.commit()
    return token, expires_at


def revoke_session(db: Session, session: UserSession) -> None:
    if session.revoked_at is None:
        session.revoked_at = datetime.now(UTC)
        db.commit()


def resolve_token(db: Session, token: str) -> tuple[User, UserSession]:
    """Validate a bearer token against the signature, the session row and the user state."""
    try:
        claims = decode_access_token(token)
    except TokenError as exc:
        raise AuthenticationError("Invalid or expired token") from exc

    session = db.get(UserSession, claims.session_id)
    if (
        session is None
        or session.user_id != claims.user_id
        or not hmac.compare_digest(session.token_hash, hash_token(token))
        or session.revoked_at is not None
        or as_utc(session.expires_at) <= datetime.now(UTC)
    ):
        raise AuthenticationError("Invalid or expired token")

    user = db.get(User, claims.user_id)
    if user is None or not user.is_active:
        raise AuthenticationError("Invalid or expired token")
    return user, session


def list_active_sessions(db: Session, user: User, current_id: uuid.UUID) -> list[dict]:
    now = datetime.now(UTC)
    rows = db.scalars(
        select(UserSession)
        .where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
        .order_by(UserSession.created_at.desc())
    ).all()
    return [
        {
            "id": s.id,
            "created_at": s.created_at,
            "expires_at": s.expires_at,
            "current": s.id == current_id,
        }
        for s in rows
        if as_utc(s.expires_at) > now
    ]


def revoke_user_session(db: Session, user: User, session_id: uuid.UUID) -> None:
    from app.core.errors import NotFoundError

    session = db.scalar(
        select(UserSession).where(UserSession.id == session_id, UserSession.user_id == user.id)
    )
    if session is None:
        raise NotFoundError("Session not found")
    revoke_session(db, session)
