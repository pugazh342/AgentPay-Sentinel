"""Pure deterministic policy engine tests (no HTTP, no database)."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

from app.domain.entities import PurchaseIntent, TransactionRequest
from app.domain.enums import Decision, ReasonCode, RiskLevel
from app.domain.policy import evaluate_policy, risk_level_for
from app.security.fingerprint import FingerprintService

SECRET = "policy-test-secret-0123456789abcdefghij"
NOW = datetime(2026, 2, 1, 10, 0, 0, tzinfo=UTC)
SERVICE = FingerprintService(SECRET)


def make_intent(**overrides) -> PurchaseIntent:
    values = {
        "intent_id": uuid4(),
        "user_id": "user_1",
        "purpose": "Buy shoes",
        "merchant_id": "merchant_1",
        "product_category": "footwear",
        "max_amount": Decimal("800.00"),
        "currency": "USD",
        "max_quantity": 2,
        "require_approval": True,
        "created_at": NOW - timedelta(minutes=5),
        "expires_at": NOW + timedelta(hours=1),
    }
    values.update(overrides)
    unsigned = PurchaseIntent(**values)
    return replace(unsigned, fingerprint=SERVICE.fingerprint_intent(unsigned))


def make_request(intent: PurchaseIntent, **overrides) -> TransactionRequest:
    values = {
        "user_id": intent.user_id,
        "intent_id": intent.intent_id,
        "merchant_id": intent.merchant_id,
        "product_category": intent.product_category,
        "amount": intent.max_amount,
        "currency": intent.currency,
        "quantity": intent.max_quantity,
        "request_id": "req_policy_001",
    }
    values.update(overrides)
    return TransactionRequest(**values)


def test_valid_transaction_allows_for_approval() -> None:
    intent = make_intent()
    outcome = evaluate_policy(
        make_request(intent), intent, verifier=SERVICE, now=NOW
    )

    assert outcome.decision is Decision.ALLOW_FOR_APPROVAL
    assert outcome.reason_codes == (ReasonCode.ALL_CHECKS_PASSED,)


def test_unknown_intent_blocks() -> None:
    outcome = evaluate_policy(
        TransactionRequest(
            user_id="user_1",
            intent_id=uuid4(),
            merchant_id="merchant_1",
            product_category="footwear",
            amount=Decimal("10.00"),
            currency="USD",
            quantity=1,
            request_id="req_unknown",
        ),
        None,
        verifier=SERVICE,
        now=NOW,
    )

    assert outcome.decision is Decision.BLOCK
    assert outcome.reason_codes == (ReasonCode.UNKNOWN_INTENT,)


def test_wrong_user_blocks() -> None:
    intent = make_intent()
    outcome = evaluate_policy(
        make_request(intent, user_id="attacker"),
        intent,
        verifier=SERVICE,
        now=NOW,
    )

    assert outcome.decision is Decision.BLOCK
    assert outcome.reason_codes == (ReasonCode.USER_MISMATCH,)


def test_expired_intent_blocks() -> None:
    intent = make_intent(expires_at=NOW)
    outcome = evaluate_policy(
        make_request(intent), intent, verifier=SERVICE, now=NOW
    )

    assert outcome.decision is Decision.BLOCK
    assert outcome.reason_codes == (ReasonCode.INTENT_EXPIRED,)


def test_invalid_fingerprint_blocks() -> None:
    intent = make_intent()
    tampered = replace(intent, max_amount=Decimal("1200.00"))

    outcome = evaluate_policy(
        make_request(intent), tampered, verifier=SERVICE, now=NOW
    )

    assert outcome.decision is Decision.BLOCK
    assert outcome.reason_codes == (ReasonCode.INVALID_INTENT_FINGERPRINT,)


def test_merchant_substitution_blocks() -> None:
    intent = make_intent()
    outcome = evaluate_policy(
        make_request(intent, merchant_id="other_merchant"),
        intent,
        verifier=SERVICE,
        now=NOW,
    )

    assert outcome.decision is Decision.BLOCK
    assert outcome.reason_codes == (ReasonCode.MERCHANT_MISMATCH,)


def test_currency_manipulation_blocks() -> None:
    intent = make_intent()
    outcome = evaluate_policy(
        make_request(intent, currency="EUR"),
        intent,
        verifier=SERVICE,
        now=NOW,
    )

    assert outcome.decision is Decision.BLOCK
    assert outcome.reason_codes == (ReasonCode.CURRENCY_MISMATCH,)


def test_amount_over_maximum_blocks() -> None:
    intent = make_intent()
    outcome = evaluate_policy(
        make_request(intent, amount=Decimal("1200.00")),
        intent,
        verifier=SERVICE,
        now=NOW,
    )

    assert outcome.decision is Decision.BLOCK
    assert outcome.reason_codes == (ReasonCode.AMOUNT_EXCEEDS_MAXIMUM,)


def test_amount_one_cent_over_maximum_blocks() -> None:
    intent = make_intent()
    outcome = evaluate_policy(
        make_request(intent, amount=Decimal("800.01")),
        intent,
        verifier=SERVICE,
        now=NOW,
    )

    assert outcome.decision is Decision.BLOCK
    assert outcome.reason_codes == (ReasonCode.AMOUNT_EXCEEDS_MAXIMUM,)


def test_amount_exactly_at_maximum_is_allowed() -> None:
    intent = make_intent(max_amount=Decimal("800.00"))
    outcome = evaluate_policy(
        make_request(intent, amount=Decimal("800.00")),
        intent,
        verifier=SERVICE,
        now=NOW,
    )

    assert outcome.decision is Decision.ALLOW_FOR_APPROVAL


def test_quantity_over_maximum_blocks() -> None:
    intent = make_intent(max_quantity=2)
    outcome = evaluate_policy(
        make_request(intent, quantity=3),
        intent,
        verifier=SERVICE,
        now=NOW,
    )

    assert outcome.decision is Decision.BLOCK
    assert outcome.reason_codes == (ReasonCode.QUANTITY_EXCEEDS_MAXIMUM,)


def test_product_category_mismatch_requires_review() -> None:
    intent = make_intent()
    outcome = evaluate_policy(
        make_request(intent, product_category="electronics"),
        intent,
        verifier=SERVICE,
        now=NOW,
    )

    assert outcome.decision is Decision.REVIEW_REQUIRED
    assert outcome.reason_codes == (ReasonCode.PRODUCT_CATEGORY_MISMATCH,)


def test_hard_failures_take_precedence_over_category_review() -> None:
    intent = make_intent()
    outcome = evaluate_policy(
        make_request(
            intent,
            product_category="electronics",
            amount=Decimal("1200.00"),
        ),
        intent,
        verifier=SERVICE,
        now=NOW,
    )

    assert outcome.decision is Decision.BLOCK
    assert outcome.reason_codes == (ReasonCode.AMOUNT_EXCEEDS_MAXIMUM,)


def test_reason_codes_are_deterministic_and_ordered() -> None:
    intent = make_intent()
    outcome = evaluate_policy(
        make_request(
            intent,
            user_id="attacker",
            merchant_id="other_merchant",
            currency="EUR",
            amount=Decimal("1200.00"),
            quantity=10,
        ),
        intent,
        verifier=SERVICE,
        now=NOW,
    )

    assert outcome.decision is Decision.BLOCK
    assert outcome.reason_codes == (
        ReasonCode.USER_MISMATCH,
        ReasonCode.MERCHANT_MISMATCH,
        ReasonCode.CURRENCY_MISMATCH,
        ReasonCode.AMOUNT_EXCEEDS_MAXIMUM,
        ReasonCode.QUANTITY_EXCEEDS_MAXIMUM,
    )


def test_risk_level_is_descriptive_only() -> None:
    assert risk_level_for(Decision.ALLOW_FOR_APPROVAL) is RiskLevel.LOW
    assert risk_level_for(Decision.REVIEW_REQUIRED) is RiskLevel.MEDIUM
    assert risk_level_for(Decision.BLOCK) is RiskLevel.HIGH
