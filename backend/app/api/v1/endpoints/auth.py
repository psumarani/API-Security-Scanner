"""Application-user authentication endpoints."""

import uuid

from fastapi import APIRouter, Depends, status

from app.api.deps import CurrentAuth, CurrentUser, DbSession
from app.core.rate_limit import login_rate_limit, register_rate_limit
from app.schemas.auth import LoginRequest, RegisterRequest, SessionRead, TokenResponse, UserRead
from app.services import auth_service

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(register_rate_limit)],
)
def register(data: RegisterRequest, db: DbSession) -> UserRead:
    return UserRead.model_validate(auth_service.register_user(db, data))


@router.post("/login", response_model=TokenResponse, dependencies=[Depends(login_rate_limit)])
def login(data: LoginRequest, db: DbSession) -> TokenResponse:
    user = auth_service.authenticate(db, data)
    token, expires_at = auth_service.create_session(db, user)
    return TokenResponse(access_token=token, expires_at=expires_at)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(ctx: CurrentAuth, db: DbSession) -> None:
    auth_service.revoke_session(db, ctx.session)


@router.get("/me", response_model=UserRead)
def me(user: CurrentUser) -> UserRead:
    return UserRead.model_validate(user)


@router.get("/sessions", response_model=list[SessionRead])
def sessions(ctx: CurrentAuth, db: DbSession) -> list[SessionRead]:
    rows = auth_service.list_active_sessions(db, ctx.user, ctx.session.id)
    return [SessionRead(**row) for row in rows]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_session(session_id: uuid.UUID, ctx: CurrentAuth, db: DbSession) -> None:
    auth_service.revoke_user_session(db, ctx.user, session_id)
