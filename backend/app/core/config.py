"""Application settings loaded from environment variables and the root .env file."""

from functools import lru_cache
from pathlib import Path

from cryptography.fernet import Fernet
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL

ROOT_DIR = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    """Typed configuration. Secrets have no defaults so a misconfigured app fails fast."""

    model_config = SettingsConfigDict(
        env_file=ROOT_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "API Security Scanner"
    environment: str = "development"
    cors_origins: list[str] = ["http://localhost:5173"]

    # Database. Either set DATABASE_URL, or the POSTGRES_* parts are combined.
    database_url: str | None = None
    postgres_user: str = "apisec"
    postgres_password: str = ""
    postgres_db: str = "apisec"
    postgres_host: str = "localhost"
    postgres_port: int = 5433

    # Application-user authentication
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "api-security-scanner"
    access_token_expire_minutes: int = 60
    bcrypt_rounds: int = 12

    # Encryption of target-API credentials at rest (Fernet key, urlsafe base64, 32 bytes)
    encryption_key: str

    # Rate limits for sensitive authentication endpoints (in-memory, per process)
    auth_rate_limit_login_per_minute: int = 10
    auth_rate_limit_register_per_minute: int = 5
    auth_max_failed_logins: int = 5
    auth_failed_login_window_seconds: int = 900

    # Scanner safety. Server-wide switch: targets can only opt in to loopback/private
    # destinations ("local lab") when this is true. Keep false on shared deployments.
    allow_local_lab_targets: bool = False
    max_concurrent_scans: int = 2

    @field_validator("jwt_secret_key")
    @classmethod
    def _jwt_secret_strong_enough(cls, value: str) -> str:
        if len(value) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters")
        return value

    @field_validator("jwt_algorithm")
    @classmethod
    def _jwt_algorithm_allowed(cls, value: str) -> str:
        if value not in {"HS256", "HS384", "HS512"}:
            raise ValueError("JWT_ALGORITHM must be one of HS256, HS384, HS512")
        return value

    @field_validator("encryption_key")
    @classmethod
    def _encryption_key_valid(cls, value: str) -> str:
        try:
            Fernet(value.encode())
        except (ValueError, TypeError) as exc:
            raise ValueError("ENCRYPTION_KEY must be a valid Fernet key") from exc
        return value

    @property
    def sqlalchemy_url(self) -> str:
        """Database URL for SQLAlchemy and Alembic."""
        if self.database_url:
            return self.database_url
        return URL.create(
            "postgresql+psycopg",
            username=self.postgres_user,
            password=self.postgres_password,
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        ).render_as_string(hide_password=False)


@lru_cache
def get_settings() -> Settings:
    """Return the cached settings instance."""
    return Settings()
