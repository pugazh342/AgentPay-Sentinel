"""API contract, intent lifecycle and documentation tests."""

from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import MutableClock, TEST_HMAC_SECRET


def test_health_ok(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "agentpay-sentinel"
    assert body["checks"] == {
        "database": "ok",
        "hmac_configuration": "configured",
    }
    assert "X-Request-ID" in response.headers


def test_swagger_ui_available(client: TestClient) -> None:
    response = client.get("/docs")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_openapi_documents_all_required_endpoints(client: TestClient) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200
    paths = response.json()["paths"]
    assert "/health" in paths
    assert "/api/v1/intents" in paths
    assert "/api/v1/intents/{intent_id}" in paths
    assert "/api/v1/transactions/evaluate" in paths
    assert "/api/v1/transactions/{transaction_id}" in paths
    assert "/api/v1/security/events" in paths


def test_openapi_does_not_expose_hmac_secret(client: TestClient) -> None:
    openapi = client.get("/openapi.json").text

    assert TEST_HMAC_SECRET not in openapi
    assert "AGENTPAY_HMAC_SECRET" not in openapi


def test_create_and_retrieve_intent(
    client: TestClient,
    intent_payload: dict,
    clock: MutableClock,
) -> None:
    create_response = client.post("/api/v1/intents", json=intent_payload)
    assert create_response.status_code == 201, create_response.text

    created = create_response.json()
    assert created["purpose"] == intent_payload["purpose"]
    assert created["max_amount"] == "800.00"
    assert created["currency"] == "USD"
    assert created["require_approval"] is True
    assert "fingerprint" not in created
    assert "hmac" not in create_response.text.lower()
    assert created["created_at"] == clock.now().isoformat().replace("+00:00", "Z")

    retrieve_response = client.get(f"/api/v1/intents/{created['intent_id']}")
    assert retrieve_response.status_code == 200
    assert retrieve_response.json() == created


def test_intent_normalizes_currency_and_category(
    client: TestClient,
    intent_payload: dict,
) -> None:
    payload = dict(intent_payload)
    payload["currency"] = "usd"
    payload["product_category"] = "  FootWear  "
    payload["max_amount"] = "800"

    response = client.post("/api/v1/intents", json=payload)

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["currency"] == "USD"
    assert body["product_category"] == "footwear"
    assert body["max_amount"] == "800.00"


def test_intents_have_no_update_endpoints(
    client: TestClient,
    intent_factory,
) -> None:
    intent = intent_factory()

    for method in ("put", "patch", "delete"):
        if method == "delete":
            response = client.delete(f"/api/v1/intents/{intent['intent_id']}")
        else:
            response = getattr(client, method)(
                f"/api/v1/intents/{intent['intent_id']}", json={}
            )
        assert response.status_code == 405
        assert response.json()["error"]["code"] == "METHOD_NOT_ALLOWED"


def test_unknown_intent_returns_404(client: TestClient) -> None:
    response = client.get("/api/v1/intents/00000000-0000-4000-8000-000000000000")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


def test_malformed_intent_id_returns_422(client: TestClient) -> None:
    response = client.get("/api/v1/intents/not-a-uuid")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_expiry_must_be_in_future(
    client: TestClient,
    intent_payload: dict,
    clock: MutableClock,
) -> None:
    payload = dict(intent_payload)
    payload["expires_at"] = (clock.now() - timedelta(seconds=1)).isoformat()

    response = client.post("/api/v1/intents", json=payload)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_expiry_must_be_timezone_aware(
    client: TestClient,
    intent_payload: dict,
) -> None:
    payload = dict(intent_payload)
    payload["expires_at"] = "2026-12-31T23:59:59"

    response = client.post("/api/v1/intents", json=payload)

    assert response.status_code == 422


def test_unknown_transaction_returns_404(client: TestClient) -> None:
    response = client.get(
        "/api/v1/transactions/00000000-0000-4000-8000-000000000000"
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


def test_settings_repr_hides_secret(settings) -> None:
    assert TEST_HMAC_SECRET not in repr(settings)
    assert TEST_HMAC_SECRET not in str(settings)


def test_app_factory_accepts_clock(settings, clock: MutableClock) -> None:
    app = create_app(settings=settings, clock=clock)

    assert app.state.clock is clock
    assert app.state.fingerprints.configured is True
