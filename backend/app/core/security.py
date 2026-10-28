"""Password hashing, access-token (JWT) handling and token hashing."""

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt

from app.core.config import Settings, get_settings

MAX_PASSWORD_BYTES = 72  # bcrypt ignores/rejects anything longer
_REQUIRED_CLAIMS = ["exp", "iat", "sub", "sid", "iss"]


class TokenError(Exception):
    """Raised when a token is missing, malformed, expired or otherwise invalid."""


def hash_password(password: str, rounds: int | None = None) -> str:
    """Hash a password with bcrypt. Callers must enforce the 72-byte limit beforehand."""
    raw = password.encode("utf-8")
    if len(raw) > MAX_PASSWORD_BYTES:
        raise ValueError("password exceeds bcrypt's 72-byte limit")
    cost = rounds if rounds is not None else get_settings().bcrypt_rounds
    return bcrypt.hashpw(raw, bcrypt.gensalt(rounds=cost)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time verification. Returns False for malformed hashes or oversized input."""
    raw = password.encode("utf-8")
    if len(raw) > MAX_PASSWORD_BYTES:
        return False
    try:
        return bcrypt.checkpw(raw, password_hash.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        return False


def hash_token(token: str) -> str:
    """SHA-256 of an access token; only this hash is persisted."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TokenClaims:
    user_id: uuid.UUID
    session_id: uuid.UUID
    expires_at: datetime


def create_access_token(
    user_id: uuid.UUID,
    session_id: uuid.UUID,
    *,
    settings: Settings | None = None,
    now: datetime | None = None,
    expires_delta: timedelta | None = None,
) -> tuple[str, datetime]:
    """Return (token, expires_at)."""
    cfg = settings or get_settings()
    issued = now or datetime.now(UTC)
    expires = issued + (expires_delta or timedelta(minutes=cfg.access_token_expire_minutes))
    payload = {
        "sub": str(user_id),
        "sid": str(session_id),
        "iss": cfg.jwt_issuer,
        "iat": int(issued.timestamp()),
        "exp": int(expires.timestamp()),
    }
    return jwt.encode(payload, cfg.jwt_secret_key, algorithm=cfg.jwt_algorithm), expires


def decode_access_token(token: str, *, settings: Settings | None = None) -> TokenClaims:
    """Validate signature, expiry, issuer and required claims.

    The algorithm list is pinned, so "alg: none" and algorithm-confusion tokens are rejected.
    """
    cfg = settings or get_settings()
    try:
        payload = jwt.decode(
            token,
            cfg.jwt_secret_key,
            algorithms=[cfg.jwt_algorithm],
            issuer=cfg.jwt_issuer,
            options={"require": _REQUIRED_CLAIMS},
        )
        return TokenClaims(
            user_id=uuid.UUID(payload["sub"]),
            session_id=uuid.UUID(payload["sid"]),
            expires_at=datetime.fromtimestamp(payload["exp"], tz=UTC),
        )
    except (jwt.PyJWTError, ValueError, KeyError, TypeError) as exc:
        raise TokenError("invalid token") from exc
