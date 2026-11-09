"""End-to-end transaction policy tests through the REST API."""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

from tests.conftest import MutableClock


def test_valid_800_transaction_returns_allow_for_approval(
    client: TestClient,
    intent_factory,
    evaluate,
    clock: MutableClock,
) -> None:
    intent = intent_factory(max_amount="800.00", max_quantity=1)
    response = evaluate(intent, amount="800.00", quantity=1)

    assert response.status_code == 200
    decision = response.json()
    assert decision["decision"] == "ALLOW_FOR_APPROVAL"
    assert decision["reason_codes"] == ["ALL_CHECKS_PASSED"]
    assert decision["risk_level"] == "LOW"
    assert decision["intent_id"] == intent["intent_id"]
    assert decision["evaluated_at"] == clock.now().isoformat().replace("+00:00", "Z")
    assert "does not authorize, capture or settle a payment" in decision["explanation"]

    transaction_response = client.get(
        f"/api/v1/transactions/{decision['transaction_id']}"
    )
    assert transaction_response.status_code == 200
    transaction = transaction_response.json()
    assert transaction["decision"]["decision_id"] == decision["decision_id"]
    assert transaction["amount"] == "800.00"
    assert transaction["request_id"].startswith("req_test_")


def test_1200_amount_manipulation_blocks(
    client: TestClient,
    intent_factory,
    evaluate,
) -> None:
    intent = intent_factory(max_amount="800.00")
    response = evaluate(intent, amount="1200.00")

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "BLOCK"
    assert body["reason_codes"] == ["AMOUNT_EXCEEDS_MAXIMUM"]
    assert body["risk_level"] == "HIGH"


def test_one_cent_over_maximum_blocks(
    client: TestClient,
    intent_factory,
    evaluate,
) -> None:
    intent = intent_factory(max_amount="800.00")
    response = evaluate(intent, amount="800.01")

    assert response.json()["decision"] == "BLOCK"
    assert response.json()["reason_codes"] == ["AMOUNT_EXCEEDS_MAXIMUM"]


def test_merchant_substitution_blocks(
    client: TestClient,
    intent_factory,
    evaluate,
) -> None:
    intent = intent_factory()
    response = evaluate(intent, merchant_id="merchant_attacker")

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "BLOCK"
    assert body["reason_codes"] == ["MERCHANT_MISMATCH"]


def test_currency_manipulation_blocks(
    client: TestClient,
    intent_factory,
    evaluate,
) -> None:
    intent = intent_factory(currency="USD")
    response = evaluate(intent, currency="EUR")

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "BLOCK"
    assert body["reason_codes"] == ["CURRENCY_MISMATCH"]


def test_quantity_manipulation_blocks(
    client: TestClient,
    intent_factory,
    evaluate,
) -> None:
    intent = intent_factory(max_quantity=1)
    response = evaluate(intent, quantity=2)

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "BLOCK"
    assert body["reason_codes"] == ["QUANTITY_EXCEEDS_MAXIMUM"]


def test_expired_intent_blocks(
    client: TestClient,
    intent_factory,
    evaluate,
    clock: MutableClock,
) -> None:
    intent = intent_factory()
    clock.advance(hours=2)

    response = evaluate(intent)

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "BLOCK"
    assert body["reason_codes"] == ["INTENT_EXPIRED"]


def test_unknown_intent_blocks_not_404(
    client: TestClient,
    intent_factory,
    evaluate,
) -> None:
    intent = intent_factory()
    known_transaction_id = None

    response = evaluate(intent, intent_id=str(uuid4()))
    body = response.json()

    assert response.status_code == 200
    assert body["decision"] == "BLOCK"
    assert body["reason_codes"] == ["UNKNOWN_INTENT"]
    known_transaction_id = body["transaction_id"]

    persisted = client.get(f"/api/v1/transactions/{known_transaction_id}")
    assert persisted.status_code == 200
    assert persisted.json()["decision"]["decision"] == "BLOCK"


def test_wrong_user_blocks(
    client: TestClient,
    intent_factory,
    evaluate,
) -> None:
    intent = intent_factory(user_id="owner_1")
    response = evaluate(intent, user_id="attacker_2")

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "BLOCK"
    assert body["reason_codes"] == ["USER_MISMATCH"]


def test_product_category_mismatch_requires_review(
    client: TestClient,
    intent_factory,
    evaluate,
) -> None:
    intent = intent_factory(product_category="footwear")
    response = evaluate(intent, product_category="electronics")

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "REVIEW_REQUIRED"
    assert body["reason_codes"] == ["PRODUCT_CATEGORY_MISMATCH"]
    assert body["risk_level"] == "MEDIUM"
    assert "Human review is required" in body["explanation"]


def test_intent_fingerprint_tampering_in_database_is_detected(
    app: FastAPI,
    client: TestClient,
    intent_factory,
    evaluate,
) -> None:
    intent = intent_factory(max_amount="800.00")

    with app.state.db.session() as session:
        session.execute(
            text(
                "UPDATE purchase_intents SET max_amount = :amount "
                "WHERE intent_id = :intent_id"
            ),
            {"amount": "1200.00", "intent_id": intent["intent_id"]},
        )
        session.commit()

    response = evaluate(intent, amount="800.00")

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "BLOCK"
    assert body["reason_codes"] == ["INVALID_INTENT_FINGERPRINT"]


def test_fingerprint_column_tampering_is_detected(
    app: FastAPI,
    client: TestClient,
    intent_factory,
    evaluate,
) -> None:
    intent = intent_factory()

    with app.state.db.session() as session:
        session.execute(
            text(
                "UPDATE purchase_intents SET fingerprint = :fingerprint "
                "WHERE intent_id = :intent_id"
            ),
            {"fingerprint": "0" * 64, "intent_id": intent["intent_id"]},
        )
        session.commit()

    response = evaluate(intent)

    assert response.json()["decision"] == "BLOCK"
    assert response.json()["reason_codes"] == ["INVALID_INTENT_FINGERPRINT"]


def test_decimal_precision_is_exact(
    client: TestClient,
    intent_factory,
    evaluate,
) -> None:
    intent = intent_factory(max_amount="10.10")

    allowed = evaluate(intent, amount="10.10")
    assert allowed.json()["decision"] == "ALLOW_FOR_APPROVAL"

    too_precise = evaluate(intent, amount="10.100")
    assert too_precise.status_code == 422

    over_by_fraction = evaluate(intent, amount="10.1001")
    assert over_by_fraction.status_code == 422

    over = evaluate(intent, amount="10.11")
    assert over.status_code == 200
    assert over.json()["reason_codes"] == ["AMOUNT_EXCEEDS_MAXIMUM"]


def test_evaluation_never_modifies_the_intent(
    app: FastAPI,
    client: TestClient,
    intent_factory,
    evaluate,
) -> None:
    intent = intent_factory(max_amount="800.00")
    before = client.get(f"/api/v1/intents/{intent['intent_id']}").json()

    with app.state.db.engine.connect() as connection:
        row_before = connection.execute(
            text(
                "SELECT user_id, merchant_id, product_category, max_amount, "
                "currency, max_quantity, fingerprint, expires_at "
                "FROM purchase_intents WHERE intent_id = :intent_id"
            ),
            {"intent_id": intent["intent_id"]},
        ).one()

    evaluate(intent, amount="800.00")

    after = client.get(f"/api/v1/intents/{intent['intent_id']}").json()
    with app.state.db.engine.connect() as connection:
        row_after = connection.execute(
            text(
                "SELECT user_id, merchant_id, product_category, max_amount, "
                "currency, max_quantity, fingerprint, expires_at "
                "FROM purchase_intents WHERE intent_id = :intent_id"
            ),
            {"intent_id": intent["intent_id"]},
        ).one()

    assert before == after
    assert tuple(row_before) == tuple(row_after)


@pytest.mark.parametrize(
    "injected_field",
    ["risk_score", "approval_status", "is_approved", "decision", "policy_override"],
)
def test_client_cannot_inject_authorization_signals(
    client: TestClient,
    intent_factory,
    evaluate,
    injected_field: str,
) -> None:
    intent = intent_factory()
    response = evaluate(intent, **{injected_field: 0})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    fields = [detail["field"] for detail in response.json()["error"]["details"]]
    assert injected_field in fields
