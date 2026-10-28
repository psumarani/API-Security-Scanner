"""Authorized scan targets and the credentials used against them."""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import AuthType
from app.models.mixins import CreatedAt, UpdatedAt, UUIDPrimaryKey
from app.models.types import enum_column


class ScanTarget(UUIDPrimaryKey, CreatedAt, UpdatedAt, Base):
    __tablename__ = "scan_targets"
    __table_args__ = (UniqueConstraint("user_id", "name", name="uq_scan_targets_user_id_name"),)

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    api_spec_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    # Explicit authorization: the owner confirmed they may test this target.
    authorization_confirmed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    authorization_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Narrow opt-in for loopback/private destinations (also needs the server-side switch).
    allow_local_lab: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    user: Mapped["User"] = relationship(back_populates="targets")  # noqa: F821
    auth_profiles: Mapped[list["AuthProfile"]] = relationship(
        back_populates="target", cascade="all, delete-orphan", passive_deletes=True
    )
    scans: Mapped[list["Scan"]] = relationship(  # noqa: F821
        back_populates="target", cascade="all, delete-orphan", passive_deletes=True
    )


class AuthProfile(UUIDPrimaryKey, CreatedAt, UpdatedAt, Base):
    """Credentials for authenticating *to the target API* (not to this application)."""

    __tablename__ = "auth_profiles"
    __table_args__ = (
        UniqueConstraint("target_id", "name", name="uq_auth_profiles_target_id_name"),
    )

    target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scan_targets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    auth_type: Mapped[AuthType] = mapped_column(enum_column(AuthType, "auth_type"), nullable=False)
    # Label used by BOLA/BFLA checks, e.g. "user_a", "user_b", "admin".
    role_label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Fernet-encrypted JSON. NULL when auth_type is "none".
    encrypted_config: Mapped[str | None] = mapped_column(Text, nullable=True)

    target: Mapped[ScanTarget] = relationship(back_populates="auth_profiles")

    @property
    def has_credentials(self) -> bool:
        return self.encrypted_config is not None
