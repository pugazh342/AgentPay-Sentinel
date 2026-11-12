"""Operator authentication endpoints (single-operator demo boundary)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import (
    get_auth_rate_limiter,
    require_authenticated_operator,
    require_csrf_for_unsafe,
)
from app.config import Settings
from app.domain.errors import AuthenticationFailure, RateLimitFailure, ValidationFailure
from app.security.auth import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    create_csrf_token,
    create_session_token,
    verify_password,
)

router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class AuthStatusResponse(BaseModel):
    authenticated: bool
    operator: str | None = None


def _settings(request: Request) -> Settings:
    return request.app.state.settings


def _client_key(request: Request, username: str) -> str:
    host = request.client.host if request.client else "unknown"
    return f"{host}:{username}"


def _set_auth_cookies(response: Response, request: Request, username: str) -> None:
    settings = _settings(request)
    secret = settings.operator_session_secret_value
    assert secret is not None
    ttl = settings.operator_session_ttl_seconds
    secure = settings.operator_cookie_secure
    session_token = create_session_token(username=username, secret=secret, ttl_seconds=ttl)
    csrf_token = create_csrf_token(secret)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=session_token,
        max_age=ttl,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        key=CSRF_COOKIE,
        value=csrf_token,
        max_age=ttl,
        httponly=False,
        secure=secure,
        samesite="lax",
        path="/",
    )


def _clear_auth_cookies(response: Response, request: Request) -> None:
    secure = _settings(request).operator_cookie_secure
    response.delete_cookie(SESSION_COOKIE, path="/", secure=secure, samesite="lax")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=secure, samesite="lax")


@router.post("/login", status_code=status.HTTP_200_OK, response_model=AuthStatusResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    limiter=Depends(get_auth_rate_limiter),
) -> AuthStatusResponse:
    settings = _settings(request)
    if not settings.operator_auth_configured:
        raise AuthenticationFailure("Operator authentication is not configured.")

    key = _client_key(request, payload.username.strip())
    if not limiter.allow(key):
        raise RateLimitFailure("Too many login attempts. Try again later.")

    expected_user = settings.operator_username_value or ""
    expected_hash = settings.operator_password_hash_value or ""
    if payload.username.strip() != expected_user or not verify_password(payload.password, expected_hash):
        raise AuthenticationFailure("Invalid credentials.")

    limiter.reset(key)
    _set_auth_cookies(response, request, expected_user)
    return AuthStatusResponse(authenticated=True, operator=expected_user)


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    response_model=AuthStatusResponse,
    dependencies=[Depends(require_authenticated_operator), Depends(require_csrf_for_unsafe)],
)
def logout(request: Request, response: Response) -> AuthStatusResponse:
    _clear_auth_cookies(response, request)
    return AuthStatusResponse(authenticated=False, operator=None)


@router.get(
    "/session",
    status_code=status.HTTP_200_OK,
    response_model=AuthStatusResponse,
    dependencies=[Depends(require_authenticated_operator)],
)
def session_status(request: Request) -> AuthStatusResponse:
    principal = getattr(request.state, "operator", None)
    return AuthStatusResponse(authenticated=True, operator=principal)