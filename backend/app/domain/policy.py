"""Deterministic authorization policy.

The policy is a pure function of the immutable intent, the validated request,
the current UTC time and the intent's HMAC integrity status.

No model output, client-supplied risk score, approval flag or other external
signal can influence the result. Rule evaluation order is fixed and documented
so outcomes are reproducible.
"""

from __future__ import annotations

from datetime import datetime

from app.domain.entities import PolicyOutcome, PurchaseIntent, TransactionRequest
from app.domain.enums import Decision, ReasonCode, RiskLevel
from app.domain.ports import IntentFingerprintVerifier
from app.domain.time import ensure_utc

_EXPLANATIONS: dict[ReasonCode, str] = {
    ReasonCode.UNKNOWN_INTENT: "No purchase intent exists for the supplied intent_id.",
    ReasonCode.USER_MISMATCH: "The transaction user does not match the intent owner.",
    ReasonCode.INTENT_EXPIRED: "The purchase intent has expired.",
    ReasonCode.INVALID_INTENT_FINGERPRINT: (
        "The stored intent failed integrity verification and cannot be trusted."
    ),
    ReasonCode.MERCHANT_MISMATCH: (
        "The merchant does not match the merchant authorized by the intent."
    ),
    ReasonCode.CURRENCY_MISMATCH: (
        "The transaction currency does not match the intent currency."
    ),
    ReasonCode.AMOUNT_EXCEEDS_MAXIMUM: (
        "The transaction amount exceeds the maximum amount authorized by the intent."
    ),
    ReasonCode.QUANTITY_EXCEEDS_MAXIMUM: (
        "The transaction quantity exceeds the maximum quantity authorized by the intent."
    ),
    ReasonCode.PRODUCT_CATEGORY_MISMATCH: (
        "The product category differs from the intent and requires human review."
    ),
}

def risk_level_for(decision: Decision) -> RiskLevel:
    """Map a decision to descriptive-only risk metadata."""

    if decision is Decision.BLOCK:
        return RiskLevel.HIGH
    if decision is Decision.REVIEW_REQUIRED:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _blocked(reason_codes: list[ReasonCode]) -> PolicyOutcome:
    details = " ".join(_EXPLANATIONS[code] for code in reason_codes)
    return PolicyOutcome(
        decision=Decision.BLOCK,
        reason_codes=tuple(reason_codes),
        explanation=f"Transaction blocked by deterministic policy. {details}",
    )


def evaluate_policy(
    request: TransactionRequest,
    intent: PurchaseIntent | None,
    *,
    verifier: IntentFingerprintVerifier,
    now: datetime,
) -> PolicyOutcome:
    """Evaluate the fixed rule set and return a deterministic outcome.

    Hard checks are evaluated in this order:
    unknown intent, wrong user, expiration, fingerprint integrity, merchant,
    currency, amount, quantity. Product-category mismatch is a soft check that
    only yields REVIEW_REQUIRED when every hard check passed.
    """

    evaluated_at = ensure_utc(now)

    if intent is None:
        return _blocked([ReasonCode.UNKNOWN_INTENT])

    hard_failures: list[ReasonCode] = []

    if request.user_id != intent.user_id:
        hard_failures.append(ReasonCode.USER_MISMATCH)

    if evaluated_at >= intent.expires_at:
        hard_failures.append(ReasonCode.INTENT_EXPIRED)

    # A missing/invalid server secret raises a configuration failure rather
    # than returning a permissive result.
    if not verifier.verify_intent(intent):
        hard_failures.append(ReasonCode.INVALID_INTENT_FINGERPRINT)

    if request.merchant_id != intent.merchant_id:
        hard_failures.append(ReasonCode.MERCHANT_MISMATCH)

    if request.currency != intent.currency:
        hard_failures.append(ReasonCode.CURRENCY_MISMATCH)

    # Both operands are Decimal; comparison is exact and never uses float.
    if request.amount > intent.max_amount:
        hard_failures.append(ReasonCode.AMOUNT_EXCEEDS_MAXIMUM)

    if request.quantity > intent.max_quantity:
        hard_failures.append(ReasonCode.QUANTITY_EXCEEDS_MAXIMUM)

    if hard_failures:
        return _blocked(hard_failures)

    if request.product_category != intent.product_category:
        return PolicyOutcome(
            decision=Decision.REVIEW_REQUIRED,
            reason_codes=(ReasonCode.PRODUCT_CATEGORY_MISMATCH,),
            explanation=(
                "All hard authorization limits passed, but the product category "
                "differs from the intent. Human review is required before any "
                "payment approval."
            ),
        )

    return PolicyOutcome(
        decision=Decision.ALLOW_FOR_APPROVAL,
        reason_codes=(ReasonCode.ALL_CHECKS_PASSED,),
        explanation=(
            "All hard authorization checks passed. This is an approval "
            "eligibility result only; it does not authorize, capture or settle "
            "a payment."
        ),
    )
