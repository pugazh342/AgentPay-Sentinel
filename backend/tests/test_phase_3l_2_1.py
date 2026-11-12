"""Deterministic historical-evidence regression for policy evaluation/persistence.

Originally this test depended on a specific live-database intent ID. It is now
self-contained and uses an isolated authenticated test client/database.
"""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_phase_3l_2_1_evidence_verification(
    payment_client: TestClient,
    payment_intent_factory,
) -> None:
    """Verify deterministic evaluation and persisted transaction evidence."""
    intent = payment_intent_factory(
        user_id="user_phase3l21",
        purpose="Purchase one pair of running shoes",
        merchant_id="merchant_shoes",
        product_category="footwear",
        max_amount="800.00",
        currency="USD",
        max_quantity=1,
        require_approval=True,
    )

    resp = payment_client.get(f"/api/v1/intents/{intent['intent_id']}")
    assert resp.status_code == 200, resp.text
    fetched = resp.json()
    assert fetched["intent_id"] == intent["intent_id"]
    assert fetched["user_id"] == "user_phase3l21"
    assert fetched["merchant_id"] == "merchant_shoes"
    assert fetched["product_category"] == "footwear"
    assert fetched["max_amount"] == "800.00"
    assert fetched["currency"] == "USD"

    evaluation_payload = {
        "user_id": fetched["user_id"],
        "intent_id": fetched["intent_id"],
        "merchant_id": fetched["merchant_id"],
        "product_category": fetched["product_category"],
        "amount": fetched["max_amount"],
        "currency": fetched["currency"],
        "quantity": 1,
        "request_id": "req-phase-3l-2-1-verify",
    }

    eval_resp = payment_client.post("/api/v1/transactions/evaluate", json=evaluation_payload)
    assert eval_resp.status_code == 200, eval_resp.text
    decision = eval_resp.json()

    assert decision["decision"] == "ALLOW_FOR_APPROVAL"
    assert "ALL_CHECKS_PASSED" in decision["reason_codes"]
    assert decision["intent_id"] == fetched["intent_id"]

    tx_resp = payment_client.get(f"/api/v1/transactions/{decision['transaction_id']}")
    assert tx_resp.status_code == 200, tx_resp.text
    tx_record = tx_resp.json()

    assert tx_record["transaction_id"] == decision["transaction_id"]
    assert tx_record["request_id"] == "req-phase-3l-2-1-verify"
    assert tx_record["amount"] == "800.00"
    assert tx_record["currency"] == "USD"
    assert tx_record["intent_id"] == fetched["intent_id"]
    assert tx_record["decision"]["decision"] == "ALLOW_FOR_APPROVAL"
