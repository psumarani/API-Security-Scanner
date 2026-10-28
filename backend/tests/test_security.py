import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.config import get_settings
from app.core.security import (
    TokenError,
    create_access_token,
    decode_access_token,
    hash_password,
    hash_token,
    verify_password,
)


def test_password_hash_roundtrip_and_salting() -> None:
    h1, h2 = hash_password("s3cret-passphrase"), hash_password("s3cret-passphrase")
    assert h1 != h2  # salted
    assert h1.startswith("$2")
    assert verify_password("s3cret-passphrase", h1)
    assert not verify_password("wrong", h1)


def test_password_over_72_bytes_is_rejected_not_truncated() -> None:
    with pytest.raises(ValueError):
        hash_password("a" * 73)
    assert not verify_password("a" * 73, hash_password("a" * 72))


def test_verify_password_handles_malformed_hash() -> None:
    assert not verify_password("x", "not-a-bcrypt-hash")


def test_token_roundtrip() -> None:
    uid, sid = uuid.uuid4(), uuid.uuid4()
    token, expires = create_access_token(uid, sid)
    claims = decode_access_token(token)
    assert (claims.user_id, claims.session_id) == (uid, sid)
    assert abs((claims.expires_at - expires).total_seconds()) < 2


def test_expired_token_rejected() -> None:
    token, _ = create_access_token(
        uuid.uuid4(),
        uuid.uuid4(),
        now=datetime.now(UTC) - timedelta(hours=3),
        expires_delta=timedelta(minutes=5),
    )
    with pytest.raises(TokenError):
        decode_access_token(token)


def test_tampered_signature_rejected() -> None:
    token, _ = create_access_token(uuid.uuid4(), uuid.uuid4())
    head, payload, sig = token.split(".")
    flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
    with pytest.raises(TokenError):
        decode_access_token(f"{head}.{payload}.{flipped}")


def test_wrong_secret_and_alg_none_rejected() -> None:
    payload = {
        "sub": str(uuid.uuid4()),
        "sid": str(uuid.uuid4()),
        "iss": get_settings().jwt_issuer,
        "iat": int(datetime.now(UTC).timestamp()),
        "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
    }
    forged = jwt.encode(payload, "another-secret-another-secret-another!!", algorithm="HS256")
    with pytest.raises(TokenError):
        decode_access_token(forged)
    unsigned = jwt.encode(payload, key=None, algorithm="none")
    with pytest.raises(TokenError):
        decode_access_token(unsigned)


@pytest.mark.parametrize("missing", ["sub", "sid", "exp", "iss", "iat"])
def test_missing_required_claim_rejected(missing: str) -> None:
    payload = {
        "sub": str(uuid.uuid4()),
        "sid": str(uuid.uuid4()),
        "iss": get_settings().jwt_issuer,
        "iat": int(datetime.now(UTC).timestamp()),
        "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
    }
    del payload[missing]
    token = jwt.encode(payload, get_settings().jwt_secret_key, algorithm="HS256")
    with pytest.raises(TokenError):
        decode_access_token(token)


def test_wrong_issuer_and_garbage_rejected() -> None:
    payload = {
        "sub": str(uuid.uuid4()),
        "sid": str(uuid.uuid4()),
        "iss": "someone-else",
        "iat": int(datetime.now(UTC).timestamp()),
        "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
    }
    token = jwt.encode(payload, get_settings().jwt_secret_key, algorithm="HS256")
    with pytest.raises(TokenError):
        decode_access_token(token)
    for junk in ["", "abc", "a.b.c", "Bearer x"]:
        with pytest.raises(TokenError):
            decode_access_token(junk)


def test_hash_token_is_stable_and_not_the_token() -> None:
    assert hash_token("abc") == hash_token("abc")
    assert hash_token("abc") != "abc"
    assert len(hash_token("abc")) == 64
