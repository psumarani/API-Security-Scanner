"""Shared test fixtures.

Tests are hermetic: settings come from environment variables set here (they take priority over
any real .env). By default an in-memory SQLite database is used. Set TEST_DATABASE_URL to a
PostgreSQL database whose name ends with "_test" to run the same tests on PostgreSQL. All tables
in that database are dropped and recreated by the tests.
"""

import os

from cryptography.fernet import Fernet

os.environ["JWT_SECRET_KEY"] = "test-secret-key-test-secret-key-test-secret-key"
os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["BCRYPT_ROUNDS"] = "4"
os.environ["ENVIRONMENT"] = "test"
os.environ.pop("DATABASE_URL", None)
os.environ["ALLOW_LOCAL_LAB_TARGETS"] = "false"

from collections.abc import Callable, Iterator  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import Engine, create_engine, event  # noqa: E402
from sqlalchemy.engine import make_url  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402

import app.models  # noqa: E402,F401
from app.api.deps import get_resolver  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.core.rate_limit import limiter  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.scanner.scope_validator import ScopeViolation  # noqa: E402

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")
if TEST_DATABASE_URL:
    _db_name = make_url(TEST_DATABASE_URL).database or ""
    if not _db_name.endswith("_test"):
        pytest.exit(
            "TEST_DATABASE_URL must point to a database whose name ends with '_test' "
            "(the tests drop all tables).",
            returncode=2,
        )

DEFAULT_DNS: dict[str, list[str]] = {
    "api.example.com": ["93.184.216.34"],
    "other.example.com": ["93.184.216.35"],
    "lab.example.test": ["127.0.0.1"],
    "internal.example.com": ["10.0.0.5"],
    "meta.example.com": ["169.254.169.254"],
    "mixed.example.com": ["93.184.216.34", "10.0.0.5"],
}


def make_engine(db_file: str) -> Engine:
    if TEST_DATABASE_URL:
        return create_engine(TEST_DATABASE_URL)
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False, "timeout": 30},
    )

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_connection, _record):  # noqa: ANN001
        dbapi_connection.execute("PRAGMA foreign_keys=ON")
        dbapi_connection.execute("PRAGMA journal_mode=WAL")

    return engine


@pytest.fixture(autouse=True)
def _reset_state() -> Iterator[None]:
    limiter.reset()
    get_settings.cache_clear()
    yield
    limiter.reset()
    get_settings.cache_clear()


@pytest.fixture
def engine(tmp_path) -> Iterator[Engine]:  # noqa: ANN001
    eng = make_engine(str(tmp_path / "test.db"))
    Base.metadata.drop_all(eng)
    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)
    eng.dispose()


@pytest.fixture
def db_session(engine: Engine) -> Iterator[Session]:
    with sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)() as session:
        yield session


@pytest.fixture
def fake_dns() -> dict[str, list[str]]:
    return dict(DEFAULT_DNS)


@pytest.fixture
def client(engine: Engine, fake_dns: dict[str, list[str]]) -> Iterator[TestClient]:
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def _get_db() -> Iterator[Session]:
        with factory() as session:
            yield session

    def _resolver(host: str, port: int) -> list[str]:  # noqa: ARG001
        try:
            return fake_dns[host]
        except KeyError as exc:
            raise ScopeViolation(f"host {host!r} could not be resolved") from exc

    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides[get_resolver] = lambda: _resolver
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def enable_local_lab(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALLOW_LOCAL_LAB_TARGETS", "true")
    get_settings.cache_clear()


PASSWORD = "correct horse battery staple"


@pytest.fixture
def make_user(client: TestClient) -> Callable[..., dict[str, str]]:
    """Register + log in a user; returns Authorization headers."""

    def _make(username: str = "alice", password: str = PASSWORD) -> dict[str, str]:
        r = client.post(
            "/api/v1/auth/register",
            json={"username": username, "email": f"{username}@example.com", "password": password},
        )
        assert r.status_code == 201, r.text
        r = client.post("/api/v1/auth/login", json={"identifier": username, "password": password})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    return _make


@pytest.fixture
def auth_headers(make_user: Callable[..., dict[str, str]]) -> dict[str, str]:
    return make_user("alice")


# ---- deliberately vulnerable lab app (loopback only) ----------------------------------------

import lab.vuln_lab as vuln_lab  # noqa: E402


@pytest.fixture(scope="module")
def lab_port() -> Iterator[int]:
    server, port = vuln_lab.start()
    yield port
    server.shutdown()
    server.server_close()


@pytest.fixture
def lab(lab_port: int) -> int:
    vuln_lab.reset()
    return lab_port


LAB_HOST = "lab.example.test"


def lab_resolver(host: str, port: int) -> list[str]:  # noqa: ARG001
    if host == LAB_HOST:
        return ["127.0.0.1"]
    raise ScopeViolation(f"host {host!r} could not be resolved")
