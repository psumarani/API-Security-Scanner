from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.core.security import hash_token
from app.models.user import User, UserSession
from tests.conftest import PASSWORD

REGISTER = "/api/v1/auth/register"
LOGIN = "/api/v1/auth/login"


def _register(client, username="alice", password=PASSWORD, **extra):
    return client.post(
        REGISTER,
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password,
            **extra,
        },
    )


def test_register_returns_user_without_secrets(client) -> None:
    r = _register(client)
    assert r.status_code == 201
    body = r.json()
    assert body["username"] == "alice" and body["role"] == "user"
    assert "password" not in body and "password_hash" not in body


def test_register_cannot_choose_role(client, db_session) -> None:
    assert _register(client, role="admin").status_code == 201
    assert db_session.scalar(select(User)).role == "user"


def test_register_normalizes_case_and_blocks_duplicates(client) -> None:
    assert _register(client, "Alice").status_code == 201
    dup_user = _register(client, "alice")
    assert dup_user.status_code == 409
    dup_email = client.post(
        REGISTER, json={"username": "bob", "email": "ALICE@example.com", "password": PASSWORD}
    )
    assert dup_email.status_code == 409
    assert dup_user.json()["error"]["message"] == dup_email.json()["error"]["message"]


def test_register_validation_does_not_echo_password(client) -> None:
    r = _register(client, password="short")
    assert r.status_code == 422
    assert "short" not in r.text
    assert r.json()["error"]["code"] == "validation_error"
    assert _register(client, password="a" * 12).status_code == 422  # too repetitive
    assert _register(client, password="x" * 73 + "yz1!").status_code == 422  # > 72 bytes
    assert _register(client, username="bad name!").status_code == 422


def test_login_by_username_and_email(client) -> None:
    _register(client)
    for identifier in ("alice", "Alice@Example.com"):
        r = client.post(LOGIN, json={"identifier": identifier, "password": PASSWORD})
        assert r.status_code == 200
        assert r.json()["token_type"] == "bearer"


def test_login_failures_are_indistinguishable(client) -> None:
    _register(client)
    wrong_pw = client.post(LOGIN, json={"identifier": "alice", "password": "nope-nope-nope"})
    no_user = client.post(LOGIN, json={"identifier": "ghost", "password": "nope-nope-nope"})
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.json() == no_user.json()
    assert wrong_pw.headers["www-authenticate"] == "Bearer"


def test_only_token_hash_is_stored(client, db_session) -> None:
    _register(client)
    token = client.post(LOGIN, json={"identifier": "alice", "password": PASSWORD}).json()[
        "access_token"
    ]
    session = db_session.scalar(select(UserSession))
    assert session.token_hash == hash_token(token)
    assert token not in session.token_hash and session.token_hash != token


def test_me_requires_valid_token(client, auth_headers) -> None:
    assert client.get("/api/v1/auth/me").status_code == 401
    assert (
        client.get("/api/v1/auth/me", headers={"Authorization": "Bearer junk"}).status_code == 401
    )
    assert client.get("/api/v1/auth/me", headers={"Authorization": "Basic abc"}).status_code == 401
    r = client.get("/api/v1/auth/me", headers=auth_headers)
    assert r.status_code == 200 and r.json()["username"] == "alice"


def test_logout_revokes_the_session(client, auth_headers, db_session) -> None:
    assert client.post("/api/v1/auth/logout", headers=auth_headers).status_code == 204
    assert client.get("/api/v1/auth/me", headers=auth_headers).status_code == 401
    assert db_session.scalar(select(UserSession)).revoked_at is not None
    # revoked token cannot be reused for logout either
    assert client.post("/api/v1/auth/logout", headers=auth_headers).status_code == 401


def test_each_login_is_its_own_session(client) -> None:
    _register(client)
    t1 = client.post(LOGIN, json={"identifier": "alice", "password": PASSWORD}).json()
    t2 = client.post(LOGIN, json={"identifier": "alice", "password": PASSWORD}).json()
    h1 = {"Authorization": f"Bearer {t1['access_token']}"}
    h2 = {"Authorization": f"Bearer {t2['access_token']}"}
    client.post("/api/v1/auth/logout", headers=h1)
    assert client.get("/api/v1/auth/me", headers=h1).status_code == 401
    assert client.get("/api/v1/auth/me", headers=h2).status_code == 200


def test_expired_session_row_is_rejected(client, auth_headers, db_session) -> None:
    session = db_session.scalar(select(UserSession))
    session.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db_session.commit()
    assert client.get("/api/v1/auth/me", headers=auth_headers).status_code == 401


def test_deactivated_user_loses_access_and_cannot_login(client, auth_headers, db_session) -> None:
    user = db_session.scalar(select(User))
    user.is_active = False
    db_session.commit()
    assert client.get("/api/v1/auth/me", headers=auth_headers).status_code == 401
    r = client.post(LOGIN, json={"identifier": "alice", "password": PASSWORD})
    assert r.status_code == 401


def test_token_for_missing_session_is_rejected(client, auth_headers, db_session) -> None:
    db_session.delete(db_session.scalar(select(UserSession)))
    db_session.commit()
    assert client.get("/api/v1/auth/me", headers=auth_headers).status_code == 401


def test_account_lockout_after_repeated_failures(client) -> None:
    _register(client)
    for _ in range(5):
        assert (
            client.post(
                LOGIN, json={"identifier": "alice", "password": "bad-bad-bad-bad"}
            ).status_code
            == 401
        )
    r = client.post(LOGIN, json={"identifier": "alice", "password": PASSWORD})
    assert r.status_code == 429
    assert "retry-after" in r.headers
    assert r.json()["error"]["code"] == "rate_limited"


def test_login_ip_rate_limit(client) -> None:
    for i in range(10):
        r = client.post(LOGIN, json={"identifier": f"user{i}", "password": "whatever-whatever"})
        assert r.status_code == 401
    assert client.post(LOGIN, json={"identifier": "user99", "password": "x"}).status_code == 429


def test_register_rate_limit(client) -> None:
    for i in range(5):
        assert _register(client, f"user{i}").status_code == 201
    assert _register(client, "user5").status_code == 429


def test_error_shape_is_consistent(client) -> None:
    for r in (client.get("/api/v1/auth/me"), client.get("/api/v1/nope")):
        body = r.json()
        assert set(body) == {"error"} and {"code", "message"} <= set(body["error"])
