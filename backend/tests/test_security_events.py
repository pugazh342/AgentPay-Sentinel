"""Security event generation and query tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import TEST_HMAC_SECRET


def test_intent_creation_and_evaluation_generate_events(
    client: TestClient,
    intent_factory,
    evaluate,
) -> None:
    intent = intent_factory()
    evaluate(intent)

    response = client.get("/api/v1/security/events")
    assert response.status_code == 200
    body = response.json()

    assert body["count"] == 2
    assert body["limit"] == 50
    events = body["items"]
    assert events[0]["event_type"] == "TRANSACTION_EVALUATED"
    assert events[0]["decision"] == "ALLOW_FOR_APPROVAL"
    assert events[0]["reason_codes"] == ["ALL_CHECKS_PASSED"]
    assert events[0]["transaction_id"] is not None
    assert events[1]["event_type"] == "INTENT_CREATED"
    assert events[1]["decision"] is None
    assert events[1]["transaction_id"] is None
    assert events[1]["reason_codes"] == []


def test_block_events_include_reason_codes(
    client: TestClient,
    intent_factory,
    evaluate,
) -> None:
    intent = intent_factory(max_amount="800.00")
    evaluate(intent, amount="1200.00")

    response = client.get(
        "/api/v1/security/events",
        params={"decision": "BLOCK", "event_type": "TRANSACTION_EVALUATED"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    event = body["items"][0]
    assert event["decision"] == "BLOCK"
    assert event["reason_codes"] == ["AMOUNT_EXCEEDS_MAXIMUM"]


def test_events_can_be_limited(
    client: TestClient,
    intent_factory,
    evaluate,
) -> None:
    intent = intent_factory()
    evaluate(intent)
    evaluate(intent, amount="1.00")

    response = client.get("/api/v1/security/events", params={"limit": 1})

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    assert body["limit"] == 1


def test_events_are_reverse_chronological(
    client: TestClient,
    intent_factory,
    evaluate,
    clock,
) -> None:
    intent = intent_factory()
    clock.advance(seconds=5)
    evaluate(intent)

    events = client.get("/api/v1/security/events").json()["items"]

    assert events[0]["event_type"] == "TRANSACTION_EVALUATED"
    assert events[1]["event_type"] == "INTENT_CREATED"
    assert events[0]["timestamp"] > events[1]["timestamp"]


def test_events_do_not_leak_secret_or_personal_fields(
    client: TestClient,
    intent_factory,
    evaluate,
) -> None:
    intent = intent_factory(
        user_id="sensitive_user_77",
        purpose="Sensitive purpose text",
    )
    evaluate(intent)

    response = client.get("/api/v1/security/events")
    text = response.text

    assert response.status_code == 200
    assert TEST_HMAC_SECRET not in text
    assert "sensitive_user_77" not in text
    assert "Sensitive purpose text" not in text
    for event in response.json()["items"]:
        assert set(event) == {
            "event_id",
            "transaction_id",
            "event_type",
            "decision",
            "reason_codes",
            "timestamp",
        }


def test_event_ids_are_unique(
    client: TestClient,
    intent_factory,
    evaluate,
) -> None:
    intent = intent_factory()
    evaluate(intent)
    evaluate(intent)

    events = client.get("/api/v1/security/events").json()["items"]

    assert len({event["event_id"] for event in events}) == len(events) == 3
