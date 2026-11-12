from __future__ import annotations

import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.security.auth import CSRF_COOKIE, SESSION_COOKIE, create_session_token, hash_password
from tests.conftest import TEST_HMAC_SECRET, TEST_OPERATOR_SESSION_SECRET, MutableClock


def _settings(tmp_path, **overrides) -> Settings:
    base = dict(
        _env_file=None,
        hmac_secret=TEST_HMAC_SECRET,
        database_url=f"sqlite:///{(tmp_path / 'auth.db').as_posix()}",
        environment="test",
        log_level="WARNING",
        operator_username="operator",
        operator_password_hash=hash_password("correct-password"),
        operator_session_secret=TEST_OPERATOR_SESSION_SECRET,
        operator_cookie_secure=False,
        auth_enabled=True,
        operator_session_ttl_seconds=3600,
    )
    base.update(overrides)
    return Settings(**base)


def _app(tmp_path, clock: MutableClock | None = None, **overrides) -> FastAPI:
    clk = clock or MutableClock(__import__("datetime").datetime(2026, 1, 15, 12, 0, 0, tzinfo=__import__("datetime").UTC))
    return create_app(settings=_settings(tmp_path, **overrides), clock=clk)


def _csrf_headers(client: TestClient) -> dict[str, str]:
    token = client.cookies.get(CSRF_COOKIE)
    return {"X-CSRF-Token": token} if token else {}


def test_unauthenticated_protected_api_returns_401(tmp_path):
    with TestClient(_app(tmp_path)) as client:
        r = client.get("/api/v1/intents")
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "UNAUTHORIZED"


def test_login_success_and_session_access(tmp_path):
    with TestClient(_app(tmp_path)) as client:
        r = client.post("/api/v1/auth/login", json={"username": "operator", "password": "correct-password"})
        assert r.status_code == 200
        assert r.json()["authenticated"] is True
        assert SESSION_COOKIE in r.cookies
        assert CSRF_COOKIE in r.cookies
        s = client.get("/api/v1/auth/session")
        assert s.status_code == 200
        assert s.json()["operator"] == "operator"
        i = client.get("/api/v1/intents")
        assert i.status_code == 200


def test_invalid_credentials_rejected(tmp_path):
    with TestClient(_app(tmp_path)) as client:
        r = client.post("/api/v1/auth/login", json={"username": "operator", "password": "wrong"})
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "UNAUTHORIZED"


def test_expired_session_rejected(tmp_path):
    with TestClient(_app(tmp_path, operator_session_ttl_seconds=300)) as client:
        token = create_session_token(username="operator", secret=TEST_OPERATOR_SESSION_SECRET, ttl_seconds=-10)
        client.cookies.set(SESSION_COOKIE, token)
        client.cookies.set(CSRF_COOKIE, "bad")
        r = client.get("/api/v1/intents")
        assert r.status_code == 401


def test_forged_session_rejected(tmp_path):
    with TestClient(_app(tmp_path)) as client:
        token = create_session_token(username="operator", secret="wrong-secret-0123456789abcdef0123456789", ttl_seconds=3600)
        client.cookies.set(SESSION_COOKIE, token)
        r = client.get("/api/v1/intents")
        assert r.status_code == 401


def test_logout_invalidates_session_cookie(tmp_path):
    with TestClient(_app(tmp_path)) as client:
        client.post("/api/v1/auth/login", json={"username": "operator", "password": "correct-password"})
        r = client.post("/api/v1/auth/logout", headers=_csrf_headers(client))
        assert r.status_code == 200
        assert r.json()["authenticated"] is False
        # simulate cleared cookie
        client.cookies.clear()
        s = client.get("/api/v1/auth/session")
        assert s.status_code == 401


def test_csrf_rejected_for_state_changing_request(tmp_path):
    with TestClient(_app(tmp_path)) as client:
        client.post("/api/v1/auth/login", json={"username": "operator", "password": "correct-password"})
        # POST without CSRF header
        r = client.post("/api/v1/intents", json={
            "user_id": "u1", "purpose": "p", "merchant_id": "m", "product_category": "software",
            "max_amount": "10.00", "currency": "USD", "max_quantity": 1,
            "require_approval": True, "expires_at": "2030-01-01T00:00:00Z"
        })
        assert r.status_code == 403
        assert r.json()["error"]["code"] in {"CSRF_INVALID", "FORBIDDEN"}


def test_webhook_exempt_from_operator_auth(tmp_path):
    with TestClient(_app(tmp_path)) as client:
        # no login; invalid/missing signature should be rejected by webhook verification logic, not by operator auth
        r = client.post("/api/v1/paypal/webhooks", json={"id": "e1", "event_type": "X"}, headers={})
        assert r.status_code != 401
        assert r.json().get("error", {}).get("code") != "UNAUTHORIZED"


def test_login_rate_limited(tmp_path):
    with TestClient(_app(tmp_path)) as client:
        for _ in range(5):
            client.post("/api/v1/auth/login", json={"username": "operator", "password": "wrong"})
        r = client.post("/api/v1/auth/login", json={"username": "operator", "password": "wrong"})
        assert r.status_code == 429
        assert r.json()["error"]["code"] == "RATE_LIMITED"