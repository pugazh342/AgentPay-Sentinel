"""Independent verification tests for Phase 3M.2 payments listing.

These tests are additive and use the shared isolated fixtures from
``tests/conftest.py`` (temporary SQLite file, stub PayPal gateway). They never
touch ``backend/agentpay.db`` and never perform a network call.

They encode the Phase 3M.2 acceptance criteria, not the current behaviour, so a
failing test is a reported defect rather than a test bug.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

from tests.conftest import MutableClock, StubPayPalGateway


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _prepare(client: TestClient, transaction_id: str) -> dict[str, Any]:
    response = client.post(
        "/api/v1/payments", json={"transaction_id": transaction_id}
    )
    assert response.status_code == 200, response.text
    return response.json()


def _new_payment(
    client: TestClient,
    intent_factory,
    evaluate,
    **intent_overrides: Any,
) -> dict[str, Any]:
    intent = intent_factory(**intent_overrides)
    transaction = evaluate(intent)
    assert transaction.status_code == 200, transaction.text
    return _prepare(client, transaction.json()["transaction_id"])


def _completed_payment(
    client: TestClient,
    stub: StubPayPalGateway,
    intent_factory,
    evaluate,
    **intent_overrides: Any,
) -> dict[str, Any]:
    payment = _new_payment(client, intent_factory, evaluate, **intent_overrides)

    approved = client.post(
        f"/api/v1/payments/{payment['payment_id']}/approve",
        json={"approved_by": "demo_operator"},
    )
    assert approved.status_code == 200, approved.text
    created = approved.json()
    stub.set_order_status(created["paypal_order_id"], "APPROVED")

    returned = client.post(
        f"/api/v1/payments/{payment['payment_id']}/buyer-return"
    )
    assert returned.status_code == 200, returned.text
    assert returned.json()["state"] == "BUYER_APPROVED"

    captured = client.post(
        f"/api/v1/payments/{payment['payment_id']}/capture"
    )
    assert captured.status_code == 200, captured.text
    assert captured.json()["state"] == "COMPLETED"
    return captured.json()


def _db_digest(app: FastAPI) -> tuple[int, str]:
    """Hash every row of every table so a read can prove it wrote nothing."""

    with app.state.db.session() as session:
        tables = [
            row[0]
            for row in session.execute(
                text(
                    "select name from sqlite_master "
                    "where type='table' order by name"
                )
            )
        ]
        digest = hashlib.sha256()
        rows_total = 0
        for table in tables:
            rows = session.execute(
                text(f'select * from "{table}" order by rowid')
            ).mappings().all()
            rows_total += len(rows)
            digest.update(table.encode())
            for row in rows:
                digest.update(
                    json.dumps(dict(row), sort_keys=True, default=str).encode()
                )
    return rows_total, digest.hexdigest()


SAFE_KEYS = {
    "payment_id",
    "transaction_id",
    "intent_id",
    "amount",
    "currency",
    "merchant_id",
    "product_category",
    "state",
    "paypal_order_id",
    "paypal_capture_id",
    "paypal_status",
    "approved_by",
    "approved_at",
    "buyer_approved_at",
    "completed_at",
    "failure_reason",
    "created_at",
    "updated_at",
}


# ----------------------------------------------------------------------
# 1. Empty list
# ----------------------------------------------------------------------
def test_empty_payment_list(payment_client: TestClient) -> None:
    response = payment_client.get("/api/v1/payments")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["results"] == []
    assert body["total_count"] == 0
    assert body["limit"] == 100
    assert body["offset"] == 0


# ----------------------------------------------------------------------
# 2. Completed payment visibility
# ----------------------------------------------------------------------
def test_completed_payment_is_visible_with_capture_id(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    completed = _completed_payment(
        payment_client,
        stub_paypal,
        payment_intent_factory,
        payment_evaluate,
        max_amount="5.00",
    )

    response = payment_client.get("/api/v1/payments?state=COMPLETED")
    assert response.status_code == 200, response.text
    results = response.json()["results"]
    match = [r for r in results if r["payment_id"] == completed["payment_id"]]
    assert len(match) == 1, "completed payment must appear in the list"

    payment = match[0]
    assert payment["state"] == "COMPLETED"
    assert payment["amount"] == "5.00"
    assert payment["currency"] == "USD"
    assert payment["paypal_capture_id"] == completed["paypal_capture_id"]
    assert payment["completed_at"] is not None


# ----------------------------------------------------------------------
# 3. Multiple records
# ----------------------------------------------------------------------
def test_multiple_payments_are_listed(
    payment_client: TestClient,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    created = [
        _new_payment(payment_client, payment_intent_factory, payment_evaluate)
        for _ in range(3)
    ]

    response = payment_client.get("/api/v1/payments")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total_count"] == 3
    assert len(body["results"]) == 3
    listed = {r["payment_id"] for r in body["results"]}
    assert listed == {p["payment_id"] for p in created}


# ----------------------------------------------------------------------
# 4. Pagination (total_count must describe the whole filtered set)
# ----------------------------------------------------------------------
def test_pagination_page_and_total_count(
    payment_client: TestClient,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    created = [
        _new_payment(payment_client, payment_intent_factory, payment_evaluate)
        for _ in range(5)
    ]

    first = payment_client.get("/api/v1/payments?limit=2&offset=0")
    second = payment_client.get("/api/v1/payments?limit=2&offset=2")
    last = payment_client.get("/api/v1/payments?limit=2&offset=4")

    assert first.status_code == second.status_code == last.status_code == 200

    first_body, second_body, last_body = (
        first.json(),
        second.json(),
        last.json(),
    )
    assert len(first_body["results"]) == 2
    assert len(second_body["results"]) == 2
    assert len(last_body["results"]) == 1

    # total_count describes the filtered dataset, not the current page.
    assert first_body["total_count"] == 5
    assert second_body["total_count"] == 5
    assert last_body["total_count"] == 5

    paged = {
        r["payment_id"]
        for r in (
            first_body["results"] + second_body["results"] + last_body["results"]
        )
    }
    assert paged == {p["payment_id"] for p in created}


def test_pagination_offset_beyond_end_is_empty(
    payment_client: TestClient,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    _new_payment(payment_client, payment_intent_factory, payment_evaluate)
    response = payment_client.get("/api/v1/payments?offset=10")
    assert response.status_code == 200, response.text
    assert response.json()["results"] == []


# ----------------------------------------------------------------------
# 5. State filter
# ----------------------------------------------------------------------
def test_state_filter(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    pending = _new_payment(
        payment_client, payment_intent_factory, payment_evaluate
    )
    completed = _completed_payment(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )

    response = payment_client.get("/api/v1/payments?state=PENDING_USER_APPROVAL")
    assert response.status_code == 200, response.text
    ids = {r["payment_id"] for r in response.json()["results"]}
    assert pending["payment_id"] in ids
    assert completed["payment_id"] not in ids

    response = payment_client.get("/api/v1/payments?state=COMPLETED")
    ids = {r["payment_id"] for r in response.json()["results"]}
    assert ids == {completed["payment_id"]}


# ----------------------------------------------------------------------
# 6. Intent filter
# ----------------------------------------------------------------------
def test_intent_filter(
    payment_client: TestClient,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    intent_a = payment_intent_factory()
    tx_a = payment_evaluate(intent_a).json()
    payment_a = _prepare(payment_client, tx_a["transaction_id"])

    payment_b = _new_payment(
        payment_client, payment_intent_factory, payment_evaluate
    )

    response = payment_client.get(
        f"/api/v1/payments?intent_id={intent_a['intent_id']}"
    )
    assert response.status_code == 200, response.text
    ids = {r["payment_id"] for r in response.json()["results"]}
    assert ids == {payment_a["payment_id"]}
    assert payment_b["payment_id"] not in ids


# ----------------------------------------------------------------------
# 7. Transaction filter
# ----------------------------------------------------------------------
def test_transaction_filter(
    payment_client: TestClient,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    intent = payment_intent_factory()
    transaction = payment_evaluate(intent).json()
    payment = _prepare(payment_client, transaction["transaction_id"])
    _new_payment(payment_client, payment_intent_factory, payment_evaluate)

    response = payment_client.get(
        f"/api/v1/payments?transaction_id={transaction['transaction_id']}"
    )
    assert response.status_code == 200, response.text
    ids = {r["payment_id"] for r in response.json()["results"]}
    assert ids == {payment["payment_id"]}


# ----------------------------------------------------------------------
# 8. Invalid filters and invalid pagination
# ----------------------------------------------------------------------
def test_invalid_state_filter_is_422(payment_client: TestClient) -> None:
    response = payment_client.get("/api/v1/payments?state=NOT_A_STATE")
    assert response.status_code == 422, response.text


def test_limit_above_maximum_is_rejected(payment_client: TestClient) -> None:
    # Acceptable designs: reject with 422 or clamp to 1000. The spec says the
    # effective maximum is 1000; this implementation rejects.
    response = payment_client.get("/api/v1/payments?limit=5000")
    assert response.status_code == 422, response.text


def test_limit_zero_is_422(payment_client: TestClient) -> None:
    response = payment_client.get("/api/v1/payments?limit=0")
    assert response.status_code == 422, response.text


def test_negative_offset_is_422(payment_client: TestClient) -> None:
    response = payment_client.get("/api/v1/payments?offset=-1")
    assert response.status_code == 422, response.text


def test_invalid_intent_uuid_is_422(payment_client: TestClient) -> None:
    response = payment_client.get("/api/v1/payments?intent_id=not-a-uuid")
    assert response.status_code == 422, response.text


def test_invalid_transaction_uuid_is_422(payment_client: TestClient) -> None:
    response = payment_client.get(
        "/api/v1/payments?transaction_id=not-a-uuid"
    )
    assert response.status_code == 422, response.text


# ----------------------------------------------------------------------
# 9. Sensitive-field exclusion
# ----------------------------------------------------------------------
def test_listing_excludes_sensitive_fields(
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    # Approve so the stored payment definitely has an approval_url.
    payment = _new_payment(
        payment_client, payment_intent_factory, payment_evaluate
    )
    approved = payment_client.post(
        f"/api/v1/payments/{payment['payment_id']}/approve",
        json={"approved_by": "demo_operator"},
    )
    assert approved.status_code == 200, approved.text

    response = payment_client.get("/api/v1/payments")
    assert response.status_code == 200, response.text
    raw = response.text
    body = response.json()

    forbidden_keys = {
        "approval_url",
        "user_id",
        "fingerprint",
        "hmac",
        "hmac_secret",
        "access_token",
        "client_secret",
        "client_id",
        "authorization",
        "raw_custom_id",
        "raw_reference_id",
        "raw_response",
        "provider_payload",
        "token",
    }
    for item in body["results"]:
        assert set(item) == SAFE_KEYS, (
            f"unexpected listing keys: {set(item) ^ SAFE_KEYS}"
        )
        assert not (set(item) & forbidden_keys)

    lowered = raw.lower()
    for marker in (
        "approval_url",
        "checkoutnow",
        "access_token",
        "client_secret",
        "bearer ",
    ):
        assert marker not in lowered, f"listing leaked {marker!r}"


# ----------------------------------------------------------------------
# 10. Listing does not mutate database state
# ----------------------------------------------------------------------
def test_listing_does_not_mutate_database(
    payment_app: FastAPI,
    payment_client: TestClient,
    stub_paypal: StubPayPalGateway,
    payment_intent_factory,
    payment_evaluate,
) -> None:
    completed = _completed_payment(
        payment_client, stub_paypal, payment_intent_factory, payment_evaluate
    )

    rows_before, digest_before = _db_digest(payment_app)

    for url in (
        "/api/v1/payments",
        "/api/v1/payments?limit=1&offset=0",
        "/api/v1/payments?state=COMPLETED",
        f"/api/v1/payments?intent_id={completed['intent_id']}",
        f"/api/v1/payments?transaction_id={completed['transaction_id']}",
        f"/api/v1/payments/{completed['payment_id']}",
    ):
        assert payment_client.get(url).status_code == 200, url

    rows_after, digest_after = _db_digest(payment_app)

    assert rows_after == rows_before
    assert digest_after == digest_before, "read endpoints mutated the database"
