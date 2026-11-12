"""SQLite persistence and fail-closed configuration tests."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.config import Settings
from app.domain.entities import PurchaseIntent
from app.domain.errors import ConfigurationFailure
from app.main import create_app
from app.security.fingerprint import FingerprintService
from tests.conftest import (
    MutableClock,
    TEST_HMAC_SECRET,
    TEST_OPERATOR_PASSWORD,
    TEST_OPERATOR_PASSWORD_HASH,
    TEST_OPERATOR_SESSION_SECRET,
    TEST_OPERATOR_USERNAME,
)


def _login_and_enable_csrf(test_client: TestClient) -> None:
    response = test_client.post(
        "/api/v1/auth/login",
        json={"username": TEST_OPERATOR_USERNAME, "password": TEST_OPERATOR_PASSWORD},
    )
    assert response.status_code == 200, response.text
    original_request = test_client.request

    def request_with_csrf(method, url, **kwargs):
        if str(method).upper() not in {"GET", "HEAD", "OPTIONS"}:
            csrf = test_client.cookies.get("aps_csrf")
            if csrf:
                headers = dict(kwargs.get("headers") or {})
                headers.setdefault("X-CSRF-Token", csrf)
                kwargs["headers"] = headers
        return original_request(method, url, **kwargs)

    test_client.request = request_with_csrf  # type: ignore[assignment]


def test_intent_and_transaction_survive_app_restart(
    settings: Settings,
    clock: MutableClock,
    intent_payload: dict,
) -> None:
    clock = MutableClock(clock.now())
    first_app = create_app(settings=settings, clock=clock)
    with TestClient(first_app) as first_client:
        _login_and_enable_csrf(first_client)
        created_resp = first_client.post("/api/v1/intents", json=intent_payload)
        assert created_resp.status_code == 201, created_resp.text
        created = created_resp.json()
        decision_resp = first_client.post(
            "/api/v1/transactions/evaluate",
            json={
                "user_id": created["user_id"],
                "intent_id": created["intent_id"],
                "merchant_id": created["merchant_id"],
                "product_category": created["product_category"],
                "amount": "800.00",
                "currency": "USD",
                "quantity": 1,
                "request_id": "req_persistence_1",
            },
        )
        assert decision_resp.status_code == 200, decision_resp.text
        decision = decision_resp.json()

    second_app = create_app(settings=settings, clock=clock)
    with TestClient(second_app) as second_client:
        _login_and_enable_csrf(second_client)
        intent_response = second_client.get(
            f"/api/v1/intents/{created['intent_id']}"
        )
        transaction_response = second_client.get(
            f"/api/v1/transactions/{decision['transaction_id']}"
        )
        events_response = second_client.get("/api/v1/security/events")

    assert intent_response.status_code == 200
    assert intent_response.json() == created
    assert transaction_response.status_code == 200
    assert transaction_response.json()["decision"]["decision"] == "ALLOW_FOR_APPROVAL"
    assert events_response.json()["count"] == 2


def test_money_is_persisted_as_exact_decimal_string(
    app,
    client: TestClient,
    intent_factory,
    evaluate,
) -> None:
    intent = intent_factory(max_amount="10.10")
    evaluate(intent, amount="10.10")

    with app.state.db.engine.connect() as connection:
        intent_row = connection.execute(
            text(
                "SELECT max_amount, fingerprint FROM purchase_intents "
                "WHERE intent_id = :intent_id"
            ),
            {"intent_id": intent["intent_id"]},
        ).one()
        transaction_row = connection.execute(
            text(
                "SELECT amount FROM transaction_evaluations "
                "WHERE intent_id = :intent_id"
            ),
            {"intent_id": intent["intent_id"]},
        ).one()

    assert intent_row.max_amount == "10.10"
    assert isinstance(intent_row.max_amount, str)
    assert transaction_row.amount == "10.10"
    assert isinstance(transaction_row.amount, str)
    assert len(intent_row.fingerprint) == 64


def test_database_persists_security_events(
    app,
    client: TestClient,
    intent_factory,
    evaluate,
) -> None:
    intent = intent_factory()
    decision = evaluate(intent).json()

    with app.state.db.engine.connect() as connection:
        count = connection.execute(
            text("SELECT COUNT(*) FROM security_events")
        ).scalar_one()
        event = connection.execute(
            text(
                "SELECT event_type, decision, reason_codes FROM security_events "
                "WHERE transaction_id = :transaction_id"
            ),
            {"transaction_id": decision["transaction_id"]},
        ).one()

    assert count == 2
    assert event.event_type == "TRANSACTION_EVALUATED"
    assert event.decision == "ALLOW_FOR_APPROVAL"


def test_missing_hmac_secret_fails_closed(
    tmp_path, clock: MutableClock, intent_payload: dict
) -> None:
    settings = Settings(
        _env_file=None,
        hmac_secret=None,
        database_url=f"sqlite:///{(tmp_path / 'missing-secret.db').as_posix()}",
        environment="test",
        log_level="WARNING",
        operator_username=TEST_OPERATOR_USERNAME,
        operator_password_hash=TEST_OPERATOR_PASSWORD_HASH,
        operator_session_secret=TEST_OPERATOR_SESSION_SECRET,
        operator_cookie_secure=False,
        auth_enabled=True,
    )
    app = create_app(settings=settings, clock=clock)

    with TestClient(app) as client:
        _login_and_enable_csrf(client)
        health = client.get("/health")
        create_intent = client.post("/api/v1/intents", json=intent_payload)
        evaluate = client.post(
            "/api/v1/transactions/evaluate",
            json={
                "user_id": "user_123",
                "intent_id": "00000000-0000-4000-8000-000000000000",
                "merchant_id": "merchant_shoes",
                "product_category": "footwear",
                "amount": "10.00",
                "currency": "USD",
                "quantity": 1,
                "request_id": "req_fail_closed",
            },
        )
        events = client.get("/api/v1/security/events")
        openapi = client.get("/openapi.json")

    assert health.status_code == 503
    assert health.json()["status"] == "degraded"
    assert health.json()["checks"]["hmac_configuration"] == "invalid"

    for response in (create_intent, evaluate, events):
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "SECURITY_CONFIGURATION_INVALID"

    assert TEST_HMAC_SECRET not in openapi.text


def test_short_hmac_secret_fails_closed(tmp_path, clock: MutableClock) -> None:
    settings = Settings(
        _env_file=None,
        hmac_secret="too-short",
        database_url=f"sqlite:///{(tmp_path / 'short-secret.db').as_posix()}",
        environment="test",
        log_level="WARNING",
        operator_username=TEST_OPERATOR_USERNAME,
        operator_password_hash=TEST_OPERATOR_PASSWORD_HASH,
        operator_session_secret=TEST_OPERATOR_SESSION_SECRET,
        operator_cookie_secure=False,
        auth_enabled=True,
    )
    app = create_app(settings=settings, clock=clock)

    with TestClient(app) as client:
        _login_and_enable_csrf(client)
        health = client.get("/health")
        events = client.get("/api/v1/security/events")

    assert health.status_code == 503
    assert events.status_code == 503
    assert app.state.fingerprints.configured is False


def test_direct_service_use_fails_closed_without_secret() -> None:
    service = FingerprintService(None)
    intent = PurchaseIntent(
        intent_id=uuid4(),
        user_id="user_1",
        purpose="test",
        merchant_id="merchant_1",
        product_category="footwear",
        max_amount=Decimal("10.00"),
        currency="USD",
        max_quantity=1,
        require_approval=True,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        expires_at=datetime(2026, 1, 2, tzinfo=UTC),
    )

    assert service.configured is False
    assert service.configuration_error == "HMAC secret is not configured"
    with pytest.raises(ConfigurationFailure):
        service.verify_intent(intent)
