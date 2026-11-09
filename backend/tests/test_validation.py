"""Validation tests for malformed and hostile API input."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.schemas.intent import IntentCreateRequest
from app.schemas.transaction import TransactionEvaluationRequest


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("amount", "-1.00"),
        ("amount", "0"),
        ("amount", "0.00"),
        ("amount", "not-a-number"),
        ("amount", "1.001"),
        ("amount", "NaN"),
        ("amount", "Infinity"),
        ("amount", "1e30"),
        ("currency", "XYZ"),
        ("currency", "US"),
        ("quantity", 0),
        ("quantity", -1),
        ("quantity", 1.5),
        ("quantity", True),
        ("user_id", ""),
        ("user_id", "bad id!"),
        ("user_id", "../../etc/passwd"),
        ("merchant_id", "merchant<script>"),
        ("request_id", ""),
        ("request_id", "bad request id"),
        ("intent_id", "not-a-uuid"),
        ("product_category", ""),
        ("product_category", "bad$category"),
    ],
)
def test_invalid_transaction_inputs_return_422(
    client: TestClient,
    intent_factory,
    evaluate,
    field: str,
    value: object,
) -> None:
    intent = intent_factory()
    response = evaluate(intent, **{field: value})

    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_missing_required_transaction_field_returns_422(
    client: TestClient,
    intent_factory,
) -> None:
    intent = intent_factory()
    payload = {
        "user_id": intent["user_id"],
        "intent_id": intent["intent_id"],
        "merchant_id": intent["merchant_id"],
        "product_category": intent["product_category"],
        "amount": "10.00",
        "currency": "USD",
        "quantity": 1,
    }

    response = client.post("/api/v1/transactions/evaluate", json=payload)

    assert response.status_code == 422
    fields = [detail["field"] for detail in response.json()["error"]["details"]]
    assert "request_id" in fields


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_amount", "-5.00"),
        ("max_amount", "0"),
        ("max_amount", "0.001"),
        ("max_amount", "123456789012345678901"),
        ("currency", "JPY"),
        ("max_quantity", 0),
        ("max_quantity", -3),
        ("max_quantity", 1.2),
        ("max_quantity", False),
        ("user_id", "bad user"),
        ("merchant_id", "bad/merchant"),
        ("purpose", ""),
        ("expires_at", "not-a-date"),
    ],
)
def test_invalid_intent_inputs_return_422(
    client: TestClient,
    intent_payload: dict,
    field: str,
    value: object,
) -> None:
    payload = dict(intent_payload)
    payload[field] = value

    response = client.post("/api/v1/intents", json=payload)

    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_unknown_fields_are_rejected_on_intent_creation(
    client: TestClient,
    intent_payload: dict,
) -> None:
    payload = dict(intent_payload)
    payload["approved"] = True

    response = client.post("/api/v1/intents", json=payload)

    assert response.status_code == 422
    fields = [detail["field"] for detail in response.json()["error"]["details"]]
    assert "approved" in fields


def test_expiry_cannot_precede_created_time(
    client: TestClient,
    intent_payload: dict,
    clock,
) -> None:
    payload = dict(intent_payload)
    payload["expires_at"] = (clock.now() - timedelta(hours=1)).isoformat()

    response = client.post("/api/v1/intents", json=payload)

    assert response.status_code == 422


def test_schema_rejects_float_money() -> None:
    with pytest.raises(ValidationError):
        TransactionEvaluationRequest(
            user_id="user_1",
            intent_id="00000000-0000-4000-8000-000000000000",
            merchant_id="merchant_1",
            product_category="footwear",
            amount=800.25,
            currency="USD",
            quantity=1,
            request_id="req_1",
        )


def test_schema_rejects_nan_money() -> None:
    with pytest.raises(ValidationError):
        IntentCreateRequest(
            user_id="user_1",
            purpose="test",
            merchant_id="merchant_1",
            product_category="footwear",
            max_amount="NaN",
            currency="USD",
            max_quantity=1,
            require_approval=True,
            expires_at="2026-12-31T00:00:00Z",
        )


def test_malformed_json_returns_422(client: TestClient) -> None:
    response = client.post(
        "/api/v1/transactions/evaluate",
        content="{not-json",
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_security_events_limit_bounds(client: TestClient) -> None:
    assert client.get("/api/v1/security/events?limit=0").status_code == 422
    assert client.get("/api/v1/security/events?limit=201").status_code == 422
    assert client.get("/api/v1/security/events?event_type=INVALID").status_code == 422
