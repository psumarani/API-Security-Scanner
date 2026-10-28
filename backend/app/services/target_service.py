"""Business logic for scan targets and their authentication profiles.

Every query is filtered by the owning user. Records belonging to someone else are reported as
"not found" so their existence is not disclosed.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.crypto import decrypt_json, encrypt_json
from app.core.errors import ConflictError, NotFoundError, ScopeViolationError, ValidationFailed
from app.models.enums import AuthType
from app.models.target import AuthProfile, ScanTarget
from app.models.user import User
from app.scanner.scope_validator import (
    Resolver,
    ScopeViolation,
    system_resolver,
    validate_target_urls,
)
from app.schemas.target import AuthProfileCreate, TargetCreate

MAX_PROFILES_PER_TARGET = 10


def create_target(
    db: Session, user: User, data: TargetCreate, resolver: Resolver = system_resolver
) -> ScanTarget:
    if not data.authorization_confirmed:
        raise ValidationFailed(
            "You must confirm that you own this target or have explicit permission to test it"
        )
    if data.allow_local_lab and not get_settings().allow_local_lab_targets:
        raise ScopeViolationError("Local-lab targets are disabled on this server")

    try:
        validated = validate_target_urls(
            data.base_url,
            data.api_spec_url,
            allow_local_lab=data.allow_local_lab,
            resolver=resolver,
        )
    except ScopeViolation as exc:
        raise ScopeViolationError(f"Target rejected: {exc}") from exc

    if db.scalar(
        select(ScanTarget.id).where(ScanTarget.user_id == user.id, ScanTarget.name == data.name)
    ):
        raise ConflictError("You already have a target with this name")

    target = ScanTarget(
        user_id=user.id,
        name=data.name,
        base_url=validated.base_url,
        api_spec_url=validated.api_spec_url,
        authorization_confirmed_at=datetime.now(UTC),
        authorization_note=data.authorization_note,
        allow_local_lab=data.allow_local_lab,
    )
    db.add(target)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError("You already have a target with this name") from exc
    db.refresh(target)
    return target


def list_targets(db: Session, user: User, limit: int, offset: int) -> tuple[list[ScanTarget], int]:
    total = db.scalar(
        select(func.count()).select_from(ScanTarget).where(ScanTarget.user_id == user.id)
    )
    items = db.scalars(
        select(ScanTarget)
        .where(ScanTarget.user_id == user.id)
        .order_by(ScanTarget.created_at.desc(), ScanTarget.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return list(items), total or 0


def get_target(db: Session, user: User, target_id: uuid.UUID) -> ScanTarget:
    target = db.scalar(
        select(ScanTarget).where(ScanTarget.id == target_id, ScanTarget.user_id == user.id)
    )
    if target is None:
        raise NotFoundError("Target not found")
    return target


def delete_target(db: Session, user: User, target_id: uuid.UUID) -> None:
    """Deletes the target together with its auth profiles, scans, findings and evidence."""
    db.delete(get_target(db, user, target_id))
    db.commit()


# ---- Auth profiles ----------------------------------------------------------------------


def _secret_payload(config: Any) -> dict[str, Any] | None:
    if config.type == "none":
        return None
    payload = config.model_dump(exclude={"type"})
    return {k: v.get_secret_value() if isinstance(v, SecretStr) else v for k, v in payload.items()}


def create_auth_profile(
    db: Session, user: User, target_id: uuid.UUID, data: AuthProfileCreate
) -> AuthProfile:
    target = get_target(db, user, target_id)
    count = db.scalar(
        select(func.count()).select_from(AuthProfile).where(AuthProfile.target_id == target.id)
    )
    if (count or 0) >= MAX_PROFILES_PER_TARGET:
        raise ValidationFailed(f"A target can have at most {MAX_PROFILES_PER_TARGET} auth profiles")
    if db.scalar(
        select(AuthProfile.id).where(
            AuthProfile.target_id == target.id, AuthProfile.name == data.name
        )
    ):
        raise ConflictError("An auth profile with this name already exists for the target")

    payload = _secret_payload(data.config)
    profile = AuthProfile(
        target_id=target.id,
        name=data.name,
        auth_type=AuthType(data.config.type),
        role_label=data.role_label,
        encrypted_config=encrypt_json(payload) if payload is not None else None,
    )
    db.add(profile)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError("An auth profile with this name already exists for the target") from exc
    db.refresh(profile)
    return profile


def list_auth_profiles(db: Session, user: User, target_id: uuid.UUID) -> list[AuthProfile]:
    target = get_target(db, user, target_id)
    return list(
        db.scalars(
            select(AuthProfile)
            .where(AuthProfile.target_id == target.id)
            .order_by(AuthProfile.created_at, AuthProfile.id)
        ).all()
    )


def delete_auth_profile(
    db: Session, user: User, target_id: uuid.UUID, profile_id: uuid.UUID
) -> None:
    target = get_target(db, user, target_id)
    profile = db.scalar(
        select(AuthProfile).where(AuthProfile.id == profile_id, AuthProfile.target_id == target.id)
    )
    if profile is None:
        raise NotFoundError("Auth profile not found")
    db.delete(profile)
    db.commit()


def load_profile_credentials(profile: AuthProfile) -> dict[str, Any]:
    """Decrypt a profile's credentials for use by the scanner. Never log the result."""
    return decrypt_json(profile.encrypted_config) if profile.encrypted_config else {}
