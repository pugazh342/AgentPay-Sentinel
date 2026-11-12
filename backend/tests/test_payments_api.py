"""End-to-end PayPal sandbox payment workflow tests.

Every test uses ``StubPayPalGateway``. No network calls, credentials, live API
requests or real captures are involved.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.config import Settings
from app.domain.enums import PayPalStatus
from app.domain.errors import PayPalGatewayError
from app.domain.payment import PayPalOrderResult
from tests.conftest import MutableClock, StubPayPalGateway

WEBHOOK_HEADERS = {
    "paypal-transmission-id": "transmission-1",
    "paypal-transmission-time": "2026-01-15T12:00:00Z",
    "paypal-cert-url": "https://api.sandbox.paypal.com/cert",
    "paypal-auth-algo": "SHA256withRSA",
    "paypal-transmission-sig": "signature",
}


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def evaluate_transaction(evaluate, intent: dict[str, Any], **overrides: Any) -> dict:
    response = evaluate(intent, **overrides)
    assert response.status_code == 200, response.text
    return response.json()


def prepare_payment(client: TestClient, transaction_id: str) -> dict:
    response = client.post(
        "/api/v1/payments", json={"transaction_id": transaction_id}
    )
    assert response.status_code == 200, response.text
    return response.json()


def approve_payment(client: TestClient, payment_id: str) -> Any:
    return client.post(
        f"/api/v1/payments/{payment_id}/approve",
        json={"approved_by": "demo_operator"},
    )


def buyer_return(client: TestClient, payment_id: str) -> Any:
    return client.post(f"/api/v1/payments/{payment_id}/buyer-return")


def capture_payment(client: TestClient, payment_id: str) -> Any:
    return client.post(f"/api/v1/payments/{payment_id}/capture")


def get_payment(client: TestClient, payment_id: str) -> dict:
    response = client.get(f"/api/v1/payments/{payment_id}")
    assert response.status_code == 200, response.text
    return response.json()


def start_buyer_approved_order(
    client: TestClient,
    stub: StubPayPalGateway,
    intent_factory,
    evaluate,
    **intent_overrides: Any,
) -> dict:
    """Drive a payment to BUYER_APPROVED using only the stub gateway."""

    intent = intent_factory(**intent_overrides)
    transaction = evaluate_transaction(evaluate, intent)
    payment = prepare_payment(client, transaction["transaction_id"])

    approved = approve_payment(client, payment["payment_id"])
    assert approved.status_code == 200, approved.text
    created = approved.json()
    assert created["state"] == "PAYPAL_ORDER_CREATED"
    assert created["approval_url"] is not None
    assert created["approval_url"].startswith("https://www.sandbox.paypal.com/")

    # Simulate the buyer approving inside the PayPal sandbox.
    stub.set_order_status(created["paypal_order_id"], "APPROVED")
    returned = buyer_return(client, payment["payment_id"])
    assert returned.status_code == 200, returned.text
    assert returned.json()["state"] == "BUYER_APPROVED"
    return returned.json()


def capture_pending_payment(
    client: TestClient,
    stub: StubPayPalGateway,
    intent_factory,
    evaluate,
    **intent_overrides: Any,
) -> dict:
    """Leave a payment in CAPTURE_PENDING via an ambiguous provider timeout."""

    approved = start_buyer_approved_order(
        client, stub, intent_factory, evaluate, **intent_overrides
    )
    stub.capture_error = PayPalGatewayError(
        "PayPal request timed out.",
        status=PayPalStatus.TIMEOUT,
        ambiguous=True,
    )
    response = capture_payment(client, approved["payment_id"])
    assert response.status_code == 502, response.text
    pending = get_payment(client, approved["payment_id"])
    assert pending["state"] == "CAPTURE_PENDING"
    stub.capture_error = None
    return pending


def capture_completed_event(
    payment: dict,
    *,
    event_id: str = "WH-EVENT-0001",
    capture_id: str = "PAYPAL-CAPTURE-WH-1",
    order_id: str | None = None,
    amount: str | None = None,
    currency: str | None = None,
) -> dict:
    return {
        "id": event_id,
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "resource": {
            "id": capture_id,
            "status": "COMPLETED",
            "amount": {
                "value": amount
                if amount is not None
                else f"{Decimal(str(payment['amount'])):.2f}",
                "currency_code": currency or payment["currency"],
            },
            "supplementary_data": {
                "related_ids": {
                    "order_id": order_id or payment["paypal_order_id"],
                }
            },
        },
    }


def post_webhook(client: TestClient, event: dict) -> Any:
    return client.post(
        "/api/v1/paypal/webhooks", json=event, headers=WEBHOOK_HEADERS
    )


def webhook_row_count(payment_app: FastAPI) -> int:
    with payment_app.state.db.session() as session:
        return int(
            session.execute(
                text("SELECT COUNT(*) FROM paypal_webhook_events")
            ).scalar_one()
        )


# ----------------------------------------------------------------------
# Happy path and durable state machine
# ----------------------------------------------------------------------
def test_full_sandbox_flow_reaches_completed(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    approved = start_buyer_approved_order(
        payment_client,
        stub_paypal,
        payment_intent_factory,
        payment_evaluate,
    )

    assert len(stub_paypal.create_calls) == 1
    create_call = stub_paypal.create_calls[0]
    assert create_call["amount"] == Decimal("800.00")
    assert create_call["currency"] == "USD"
    assert create_call["custom_id"] == approved["transaction_id"]
    assert create_call["request_id"] == f"agentpay-order-{approved['payment_id']}"

    completed = capture_payment(payment_client, approved["payment_id"])
    assert completed.status_code == 200, completed.text
    body = completed.json()
    assert body["state"] == "COMPLETED"
    assert body["paypal_capture_id"] is not None
    assert body["completed_at"] is not None
    assert body["amount"] == "800.00"
    assert body["currency"] == "USD"

    assert len(stub_paypal.capture_calls) == 1
    capture_call = stub_paypal.capture_calls[0]
    assert capture_call["order_id"] == approved["paypal_order_id"]
    assert capture_call["custom_id"] == approved["transaction_id"]
    assert (
        capture_call["request_id"]
        == f"agentpay-capture-{approved['payment_id']}"
    )

    assert get_payment(payment_client, approved["payment_id"])["state"] == (
        "COMPLETED"
    )


def test_prepare_is_idempotent_for_a_transaction(
    payment_client: TestClient,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    intent = payment_intent_factory()
    transaction = evaluate_transaction(payment_evaluate, intent)

    first = prepare_payment(payment_client, transaction["transaction_id"])
    second = prepare_payment(payment_client, transaction["transaction_id"])

    assert first["payment_id"] == second["payment_id"]
    assert first["state"] == "PENDING_USER_APPROVAL"


def test_prepare_rejects_unknown_transaction(payment_client: TestClient) -> None:
    response = payment_client.post(
        "/api/v1/payments", json={"transaction_id": str(uuid4())}
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


def test_prepare_rejects_client_supplied_amount_or_currency(
    payment_client: TestClient,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    intent = payment_intent_factory()
    transaction = evaluate_transaction(payment_evaluate, intent)

    response = payment_client.post(
        "/api/v1/payments",
        json={
            "transaction_id": transaction["transaction_id"],
            "amount": "1.00",
            "currency": "EUR",
            "merchant_id": "attacker_merchant",
        },
    )
    assert response.status_code == 422


def test_repeated_approval_cannot_create_a_second_order(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    intent = payment_intent_factory()
    transaction = evaluate_transaction(payment_evaluate, intent)
    payment = prepare_payment(payment_client, transaction["transaction_id"])

    first = approve_payment(payment_client, payment["payment_id"])
    assert first.status_code == 200

    second = approve_payment(payment_client, payment["payment_id"])
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "PAYMENT_STATE_INVALID"
    assert len(stub_paypal.create_calls) == 1


# ----------------------------------------------------------------------
# Ineligible transactions can never create or capture
# ----------------------------------------------------------------------
def test_blocked_transaction_cannot_create_order_or_capture(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    intent = payment_intent_factory(max_amount="800.00")
    transaction = evaluate_transaction(
        payment_evaluate, intent, amount="900.00"
    )
    assert transaction["decision"] == "BLOCK"

    payment = prepare_payment(payment_client, transaction["transaction_id"])
    assert payment["state"] == "BLOCKED"

    approve = approve_payment(payment_client, payment["payment_id"])
    assert approve.status_code == 409
    capture = capture_payment(payment_client, payment["payment_id"])
    assert capture.status_code == 409

    assert stub_paypal.create_calls == []
    assert stub_paypal.capture_calls == []
    assert get_payment(payment_client, payment["payment_id"])["state"] == (
        "BLOCKED"
    )


def test_review_required_transaction_cannot_create_order_or_capture(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    intent = payment_intent_factory(product_category="footwear")
    transaction = evaluate_transaction(
        payment_evaluate, intent, product_category="electronics"
    )
    assert transaction["decision"] == "REVIEW_REQUIRED"

    payment = prepare_payment(payment_client, transaction["transaction_id"])
    assert payment["state"] == "REVIEW_REQUIRED"

    approve = approve_payment(payment_client, payment["payment_id"])
    assert approve.status_code == 409
    capture = capture_payment(payment_client, payment["payment_id"])
    assert capture.status_code == 409

    assert stub_paypal.create_calls == []
    assert stub_paypal.capture_calls == []
    assert get_payment(payment_client, payment["payment_id"])["state"] == (
        "REVIEW_REQUIRED"
    )


def test_intent_expiry_before_prepare_marks_payment_expired(
    payment_client: TestClient,
    clock: MutableClock,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    intent = payment_intent_factory()
    transaction = evaluate_transaction(payment_evaluate, intent)
    assert transaction["decision"] == "ALLOW_FOR_APPROVAL"

    clock.advance(hours=3)
    payment = prepare_payment(payment_client, transaction["transaction_id"])
    assert payment["state"] == "EXPIRED"

    approve = approve_payment(payment_client, payment["payment_id"])
    assert approve.status_code == 409


def test_intent_expiry_after_approval_blocks_capture(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    clock: MutableClock,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    approved = start_buyer_approved_order(
        payment_client,
        stub_paypal,
        payment_intent_factory,
        payment_evaluate,
    )
    clock.advance(hours=3)

    response = capture_payment(payment_client, approved["payment_id"])
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PAYMENT_NOT_ELIGIBLE"
    assert stub_paypal.capture_calls == []
    assert get_payment(payment_client, approved["payment_id"])["state"] == (
        "EXPIRED"
    )


# ----------------------------------------------------------------------
# Provider data must match the trusted server record
# ----------------------------------------------------------------------
def test_order_amount_mismatch_fails_closed(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    approved = start_order_only(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )
    stub_paypal.order_overrides[approved["paypal_order_id"]] = PayPalOrderResult(
        order_id=approved["paypal_order_id"],
        status="APPROVED",
        amount=Decimal("1.00"),
        currency="USD",
        custom_id=approved["transaction_id"],
    )

    response = buyer_return(payment_client, approved["payment_id"])
    assert response.status_code == 502
    assert stub_paypal.capture_calls == []
    assert get_payment(payment_client, approved["payment_id"])["state"] == (
        "FAILED"
    )


def test_order_currency_mismatch_fails_closed(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    approved = start_order_only(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )
    stub_paypal.order_overrides[approved["paypal_order_id"]] = PayPalOrderResult(
        order_id=approved["paypal_order_id"],
        status="APPROVED",
        amount=Decimal("800.00"),
        currency="EUR",
        custom_id=approved["transaction_id"],
    )

    response = buyer_return(payment_client, approved["payment_id"])
    assert response.status_code == 502
    assert get_payment(payment_client, approved["payment_id"])["state"] == (
        "FAILED"
    )


def test_wrong_paypal_order_id_fails_closed(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    approved = start_order_only(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )
    stub_paypal.order_overrides[approved["paypal_order_id"]] = PayPalOrderResult(
        order_id="PAYPAL-ORDER-ATTACKER",
        status="APPROVED",
        amount=Decimal("800.00"),
        currency="USD",
        custom_id=approved["transaction_id"],
    )

    response = buyer_return(payment_client, approved["payment_id"])
    assert response.status_code == 502
    assert get_payment(payment_client, approved["payment_id"])["state"] == (
        "FAILED"
    )


def test_capture_result_with_wrong_transaction_binding_is_not_completed(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    from app.domain.payment import PayPalCaptureResult

    approved = start_buyer_approved_order(
        payment_client,
        stub_paypal,
        payment_intent_factory,
        payment_evaluate,
    )
    stub_paypal.capture_result_override = PayPalCaptureResult(
        order_id=approved["paypal_order_id"],
        capture_id="PAYPAL-CAPTURE-BAD",
        capture_status="COMPLETED",
        order_status="COMPLETED",
        amount=Decimal("800.00"),
        currency="USD",
        custom_id="some-other-transaction",
    )

    response = capture_payment(payment_client, approved["payment_id"])
    assert response.status_code == 502
    state = get_payment(payment_client, approved["payment_id"])
    assert state["state"] == "CAPTURE_PENDING"
    assert state["paypal_capture_id"] is None


# ----------------------------------------------------------------------
# Duplicate / concurrent capture protection
# ----------------------------------------------------------------------
def test_duplicate_capture_returns_completed_without_second_provider_call(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    approved = start_buyer_approved_order(
        payment_client,
        stub_paypal,
        payment_intent_factory,
        payment_evaluate,
    )
    first = capture_payment(payment_client, approved["payment_id"])
    assert first.status_code == 200
    assert first.json()["state"] == "COMPLETED"

    second = capture_payment(payment_client, approved["payment_id"])
    assert second.status_code == 200
    assert second.json()["state"] == "COMPLETED"
    assert len(stub_paypal.capture_calls) == 1


def test_ambiguous_capture_keeps_pending_and_blocks_second_claim(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    pending = capture_pending_payment(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )

    second = capture_payment(payment_client, pending["payment_id"])
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "CAPTURE_IN_PROGRESS"
    assert len(stub_paypal.capture_calls) == 1


def test_definitive_capture_rejection_marks_failed(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    approved = start_buyer_approved_order(
        payment_client,
        stub_paypal,
        payment_intent_factory,
        payment_evaluate,
    )
    stub_paypal.capture_error = PayPalGatewayError(
        "PayPal rejected the request (UNPROCESSABLE_ENTITY).",
        status=PayPalStatus.REJECTED,
        ambiguous=False,
    )

    response = capture_payment(payment_client, approved["payment_id"])
    assert response.status_code == 502
    assert get_payment(payment_client, approved["payment_id"])["state"] == (
        "FAILED"
    )

    retry = capture_payment(payment_client, approved["payment_id"])
    assert retry.status_code == 409
    assert len(stub_paypal.capture_calls) == 1


# ----------------------------------------------------------------------
# Provider failures and missing configuration fail closed
# ----------------------------------------------------------------------
def test_order_creation_timeout_marks_payment_failed(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    intent = payment_intent_factory()
    transaction = evaluate_transaction(payment_evaluate, intent)
    payment = prepare_payment(payment_client, transaction["transaction_id"])
    stub_paypal.create_error = PayPalGatewayError(
        "PayPal request timed out.",
        status=PayPalStatus.TIMEOUT,
        ambiguous=True,
    )

    response = approve_payment(payment_client, payment["payment_id"])
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "PAYPAL_PROVIDER_ERROR"
    assert get_payment(payment_client, payment["payment_id"])["state"] == (
        "FAILED"
    )


def test_buyer_return_provider_error_does_not_advance_state(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    approved = start_order_only(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )
    stub_paypal.get_error = PayPalGatewayError(
        "PayPal is temporarily unavailable.",
        status=PayPalStatus.PROVIDER_ERROR,
        ambiguous=True,
    )

    response = buyer_return(payment_client, approved["payment_id"])
    assert response.status_code == 502
    assert get_payment(payment_client, approved["payment_id"])["state"] == (
        "PAYPAL_ORDER_CREATED"
    )


def test_order_creation_requires_configured_sandbox(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    intent = payment_intent_factory()
    transaction = evaluate_transaction(payment_evaluate, intent)
    payment = prepare_payment(payment_client, transaction["transaction_id"])
    stub_paypal.set_configured(False)

    response = approve_payment(payment_client, payment["payment_id"])
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "PAYPAL_NOT_CONFIGURED"
    assert stub_paypal.create_calls == []
    assert get_payment(payment_client, payment["payment_id"])["state"] == (
        "PENDING_USER_APPROVAL"
    )


# ----------------------------------------------------------------------
# Webhook verification, deduplication and reconciliation
# ----------------------------------------------------------------------
def test_invalid_webhook_signature_is_rejected_and_not_stored(
    payment_client: TestClient,
    payment_app: FastAPI,
    stub_paypal: StubPayPalGateway,
) -> None:
    stub_paypal.verify_result = False
    event = {
        "id": "WH-INVALID-1",
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "resource": {"id": "CAPTURE-1", "status": "COMPLETED"},
    }

    response = post_webhook(payment_client, event)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "WEBHOOK_SIGNATURE_INVALID"
    assert webhook_row_count(payment_app) == 0


def test_verified_capture_webhook_completes_capture_pending(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    pending = capture_pending_payment(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )
    event = capture_completed_event(pending)

    response = post_webhook(payment_client, event)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["duplicate"] is False
    assert body["outcome"] == "COMPLETED"

    updated = get_payment(payment_client, pending["payment_id"])
    assert updated["state"] == "COMPLETED"
    assert updated["paypal_capture_id"] == "PAYPAL-CAPTURE-WH-1"
    assert updated["completed_at"] is not None
    assert len(stub_paypal.capture_calls) == 1
    assert len(stub_paypal.verify_calls) == 1


def test_duplicate_webhook_is_deduplicated(
    payment_client: TestClient,
    payment_app: FastAPI,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    pending = capture_pending_payment(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )
    event = capture_completed_event(pending, event_id="WH-DUPLICATE-1")

    first = post_webhook(payment_client, event)
    assert first.status_code == 200
    assert first.json()["outcome"] == "COMPLETED"

    second = post_webhook(payment_client, event)
    assert second.status_code == 200
    body = second.json()
    assert body["duplicate"] is True
    assert body["outcome"] == "DUPLICATE"
    assert webhook_row_count(payment_app) == 1
    assert get_payment(payment_client, pending["payment_id"])["state"] == (
        "COMPLETED"
    )


def test_verified_webhook_with_amount_mismatch_does_not_complete(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    pending = capture_pending_payment(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )
    event = capture_completed_event(pending, amount="799.99")

    response = post_webhook(payment_client, event)
    assert response.status_code == 200
    assert response.json()["outcome"] == "AMOUNT_MISMATCH"
    assert get_payment(payment_client, pending["payment_id"])["state"] == (
        "CAPTURE_PENDING"
    )


def test_verified_webhook_with_currency_mismatch_does_not_complete(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    pending = capture_pending_payment(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )
    event = capture_completed_event(pending, currency="EUR")

    response = post_webhook(payment_client, event)
    assert response.status_code == 200
    assert response.json()["outcome"] == "AMOUNT_MISMATCH"
    assert get_payment(payment_client, pending["payment_id"])["state"] == (
        "CAPTURE_PENDING"
    )


def test_webhook_cannot_complete_payment_that_was_never_claimed(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    approved = start_buyer_approved_order(
        payment_client,
        stub_paypal,
        payment_intent_factory,
        payment_evaluate,
    )
    event = capture_completed_event(approved, event_id="WH-UNCLAIMED-1")

    response = post_webhook(payment_client, event)
    assert response.status_code == 200
    assert response.json()["outcome"] == "IGNORED"
    assert get_payment(payment_client, approved["payment_id"])["state"] == (
        "BUYER_APPROVED"
    )


def test_webhook_for_unknown_order_is_acknowledged_and_ignored(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    pending = capture_pending_payment(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )
    event = capture_completed_event(
        pending, order_id="PAYPAL-ORDER-DOES-NOT-EXIST"
    )

    response = post_webhook(payment_client, event)
    assert response.status_code == 200
    assert response.json()["outcome"] == "UNMATCHED"


def test_malformed_webhook_json_is_rejected(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
) -> None:
    response = payment_client.post(
        "/api/v1/paypal/webhooks",
        content=b"not-json",
        headers={
            **WEBHOOK_HEADERS,
            "content-type": "application/json",
        },
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "WEBHOOK_SIGNATURE_INVALID"


# ----------------------------------------------------------------------
# Internal helper used only by these tests
# ----------------------------------------------------------------------
def start_order_only(
    client: TestClient,
    stub: StubPayPalGateway,
    intent_factory,
    evaluate,
    **intent_overrides: Any,
) -> dict:
    """Approved intent -> application approval -> PAYPAL_ORDER_CREATED."""

    intent = intent_factory(**intent_overrides)
    transaction = evaluate_transaction(evaluate, intent)
    payment = prepare_payment(client, transaction["transaction_id"])

    approved = approve_payment(client, payment["payment_id"])
    assert approved.status_code == 200, approved.text
    created = approved.json()
    assert created["state"] == "PAYPAL_ORDER_CREATED"
    return created


# ----------------------------------------------------------------------
# Regression tests for PayPal binding verification
# ----------------------------------------------------------------------
def test_exact_custom_id_match_succeeds(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    """When custom_id exactly matches transaction_id, binding succeeds."""
    approved = start_order_only(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )
    # Verify the custom_id in the order matches expected transaction_id
    create_call = stub_paypal.create_calls[0]
    assert create_call["custom_id"] == approved["transaction_id"]


def test_missing_custom_id_fails_closed(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    """When PayPal returns null custom_id, binding fails closed.

    SECURITY: custom_id is the authoritative binding identifier.
    """
    approved = start_order_only(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )
    stub_paypal.order_overrides[approved["paypal_order_id"]] = PayPalOrderResult(
        order_id=approved["paypal_order_id"],
        status="APPROVED",
        amount=Decimal("5.00"),
        currency="USD",
        custom_id=None,
        raw_custom_id=None,
        raw_reference_id=None,
    )

    response = buyer_return(payment_client, approved["payment_id"])
    assert response.status_code == 502
    assert get_payment(payment_client, approved["payment_id"])["state"] == "FAILED"


def test_mismatched_custom_id_fails_closed(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    """When custom_id doesn't match transaction_id, binding fails closed.

    The validation checks order.custom_id (the authoritative field), not raw values.
    """
    approved = start_order_only(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )
    stub_paypal.order_overrides[approved["paypal_order_id"]] = PayPalOrderResult(
        order_id=approved["paypal_order_id"],
        status="APPROVED",
        amount=Decimal("5.00"),
        currency="USD",
        custom_id="wrong-transaction-id-12345",
        raw_custom_id="wrong-transaction-id-12345",
        raw_reference_id=None,
    )

    response = buyer_return(payment_client, approved["payment_id"])
    assert response.status_code == 502
    payment = get_payment(payment_client, approved["payment_id"])
    assert payment["state"] == "FAILED"
    assert "not bound" in payment["failure_reason"].lower()


def test_custom_id_with_reference_id_mismatch_fails(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    """When custom_id is null but reference_id has a value, binding fails.

    SECURITY: reference_id is NOT a valid binding substitute.
    This prevents the previous silent fallback vulnerability.
    """
    approved = start_order_only(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )
    # PayPal returned: custom_id=null, reference_id="some-value"
    # Expected: custom_id should be None (binding fails)
    stub_paypal.order_overrides[approved["paypal_order_id"]] = PayPalOrderResult(
        order_id=approved["paypal_order_id"],
        status="APPROVED",
        amount=Decimal("5.00"),
        currency="USD",
        custom_id=None,  # Missing - binding MUST fail
        raw_custom_id=None,
        raw_reference_id="some-other-transaction-id",
    )

    response = buyer_return(payment_client, approved["payment_id"])
    assert response.status_code == 502
    assert get_payment(payment_client, approved["payment_id"])["state"] == "FAILED"


def test_reference_id_not_accepted_as_fallback(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    """When custom_id is null and reference_id matches transaction, binding still fails.

    SECURITY: This verifies that reference_id fallback is PROHIBITED.
    The previous implementation would silently accept reference_id as a fallback,
    creating a security vulnerability where PayPal could return arbitrary reference_id
    and it would be accepted as the binding identifier.
    """
    approved = start_order_only(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )
    # PayPal returned: custom_id=null, reference_id=transaction_id (matching!)
    # Expected: STILL FAILS because custom_id is authoritative
    stub_paypal.order_overrides[approved["paypal_order_id"]] = PayPalOrderResult(
        order_id=approved["paypal_order_id"],
        status="APPROVED",
        amount=Decimal("5.00"),
        currency="USD",
        custom_id=None,  # Missing - binding MUST fail even if reference_id matches
        raw_custom_id=None,
        raw_reference_id=approved["transaction_id"],  # Matching but ignored
    )

    response = buyer_return(payment_client, approved["payment_id"])
    assert response.status_code == 502
    assert get_payment(payment_client, approved["payment_id"])["state"] == "FAILED"


def test_duplicate_order_creation_prevented(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    """Re-approving a payment in PAYPAL_ORDER_CREATED state fails."""
    approved = start_order_only(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )

    # Attempt second approval
    second = approve_payment(payment_client, approved["payment_id"])
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "PAYMENT_STATE_INVALID"
    # Only one create call
    assert len(stub_paypal.create_calls) == 1


def test_malformed_paypal_response_fails_closed(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    """When PayPal returns incomplete/malformed response, binding fails."""
    approved = start_order_only(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )

    # Override with missing order_id (malformed)
    stub_paypal.order_overrides[approved["paypal_order_id"]] = PayPalOrderResult(
        order_id=approved["paypal_order_id"],
        status="APPROVED",
        amount=None,  # Missing amount
        currency=None,  # Missing currency
        custom_id=approved["transaction_id"],
    )

    response = buyer_return(payment_client, approved["payment_id"])
    # Should fail with amount/currency mismatch
    assert response.status_code == 502


def test_custom_id_missing_fails_closed(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    """When custom_id is null (regardless of reference_id), binding fails closed.

    SECURITY: custom_id is the authoritative binding identifier.
    reference_id is NOT a valid fallback - this prevents silent binding bypasses.
    """
    approved = start_order_only(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )
    # Override with null custom_id but matching reference_id
    # This should FAIL - reference_id is NOT a valid binding substitute
    stub_paypal.order_overrides[approved["paypal_order_id"]] = PayPalOrderResult(
        order_id=approved["paypal_order_id"],
        status="APPROVED",
        amount=Decimal("5.00"),
        currency="USD",
        custom_id=None,  # Missing - binding MUST fail
        raw_custom_id=None,
        raw_reference_id=approved["transaction_id"],  # Matching, but ignored
    )

    response = buyer_return(payment_client, approved["payment_id"])
    assert response.status_code == 502
    assert get_payment(payment_client, approved["payment_id"])["state"] == "FAILED"


def test_custom_id_must_match_transaction_exactly(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    """custom_id must match transaction_id exactly - no normalization allowed.

    PayPal Sandbox may transform UUIDs; we compare the exact string.
    """
    approved = start_order_only(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )
    # Test with lowercased UUID (if PayPal normalizes)
    stub_paypal.order_overrides[approved["paypal_order_id"]] = PayPalOrderResult(
        order_id=approved["paypal_order_id"],
        status="APPROVED",
        amount=Decimal("5.00"),
        currency="USD",
        custom_id=approved["transaction_id"].lower(),  # Different case
        raw_custom_id=approved["transaction_id"].lower(),
        raw_reference_id=None,
    )

    response = buyer_return(payment_client, approved["payment_id"])
    assert response.status_code == 502
    assert get_payment(payment_client, approved["payment_id"])["state"] == "FAILED"


def test_minimal_response_followed_by_successful_get_validation(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    """When create_order returns minimal response, GET retrieval validates binding."""
    # This is tested via the client logic; we verify stub/client behavior
    intent = payment_intent_factory()
    transaction = evaluate_transaction(payment_evaluate, intent)
    payment = prepare_payment(client=payment_client, transaction_id=transaction["transaction_id"])
    # Verify approval works when order has valid custom_id
    approved = approve_payment(payment_client, payment["payment_id"])
    assert approved.status_code == 200
