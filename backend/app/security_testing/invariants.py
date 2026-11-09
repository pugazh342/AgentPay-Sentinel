"""Security invariants verified by the adversarial scenario suite.

Each invariant names one or more scenarios that must pass for the guarantee to
be considered demonstrated. Verification is derived from executed scenario
statuses in :mod:`app.security_testing.reporting`; nothing here is a manual
claim of protection.
"""

from __future__ import annotations

from app.security_testing.models import Invariant

INVARIANTS: tuple[Invariant, ...] = (
    Invariant(
        invariant_id="INV-01-AI-CANNOT-OVERRIDE-BLOCK",
        description=(
            "Hard deterministic BLOCK decisions remain BLOCK regardless of AI "
            "output or adversarial context."
        ),
        scenario_ids=(
            "AI-BLOCK-OVERRIDE-001",
            "AI-INJECTION-MERCHANT-001",
        ),
    ),
    Invariant(
        invariant_id="INV-02-AI-CANNOT-DOWNGRADE-REVIEW",
        description=(
            "A deterministic REVIEW_REQUIRED decision is never downgraded by AI "
            "output."
        ),
        scenario_ids=("AI-REVIEW-DOWNGRADE-001",),
    ),
    Invariant(
        invariant_id="INV-03-AI-CANNOT-AUTHORIZE",
        description=(
            "AI output never independently authorizes, approves, creates an order "
            "or captures a payment."
        ),
        scenario_ids=(
            "AI-NO-AUTHORIZATION-001",
            "AI-INJECTION-DIRECT-001",
        ),
    ),
    Invariant(
        invariant_id="INV-04-EXPIRED-OR-MODIFIED-INTENT-NO-CAPTURE",
        description=(
            "An expired or modified intent cannot reach PayPal capture even after "
            "the buyer approved."
        ),
        scenario_ids=(
            "POLICY-EXPIRED-001",
            "PAYMENT-CAPTURE-AFTER-EXPIRY-001",
            "INTEGRITY-INTENT-TAMPER-001",
        ),
    ),
    Invariant(
        invariant_id="INV-05-WEBHOOK-REQUIRES-SIGNATURE",
        description=(
            "A webhook cannot complete a payment unless signature verification "
            "succeeds."
        ),
        scenario_ids=("WEBHOOK-SIGNATURE-001",),
    ),
    Invariant(
        invariant_id="INV-06-NO-DUPLICATE-CAPTURE",
        description=(
            "Duplicate or concurrent capture attempts cannot execute a second "
            "provider capture."
        ),
        scenario_ids=(
            "PAYMENT-DUPLICATE-CAPTURE-001",
            "CONCURRENCY-CAPTURE-CLAIM-001",
        ),
    ),
    Invariant(
        invariant_id="INV-07-AI-FAILURE-NO-AUTHORIZATION",
        description=(
            "An unavailable or failed AI provider cannot produce a clean "
            "authorization."
        ),
        scenario_ids=("AI-PROVIDER-FAILURE-001",),
    ),
    Invariant(
        invariant_id="INV-08-BROWSER-RETURN-NO-SUCCESS",
        description=(
            "User-facing browser return parameters cannot establish payment "
            "success; PayPal must be re-queried directly."
        ),
        scenario_ids=(
            "PAYMENT-BROWSER-PARAMS-001",
            "PAYMENT-WRONG-ORDER-001",
        ),
    ),
    Invariant(
        invariant_id="INV-09-NO-LIVE-PAYPAL",
        description=(
            "No payment operation can use a live PayPal environment or live API "
            "origin."
        ),
        scenario_ids=("LIVE-ENDPOINT-001",),
    ),
    Invariant(
        invariant_id="INV-10-DETERMINISTIC-AUTHORITY",
        description=(
            "The deterministic policy is the sole authorization authority for "
            "amount, merchant, currency, quantity, user, intent existence and "
            "intent integrity."
        ),
        scenario_ids=(
            "POLICY-AMOUNT-001",
            "POLICY-MERCHANT-001",
            "POLICY-CURRENCY-001",
            "POLICY-QUANTITY-001",
            "POLICY-WRONG-USER-001",
            "POLICY-UNKNOWN-INTENT-001",
            "POLICY-FINGERPRINT-001",
        ),
    ),
    Invariant(
        invariant_id="INV-11-ONE-PAYMENT-PER-TRANSACTION",
        description=(
            "A transaction owns at most one payment; repeated approval or "
            "concurrent preparation cannot create a second order."
        ),
        scenario_ids=(
            "CONCURRENCY-PAYMENT-ROW-001",
            "AUTH-TOKEN-REPLAY-001",
        ),
    ),
    Invariant(
        invariant_id="INV-12-PROVIDER-BINDING",
        description=(
            "PayPal order and capture responses must match the stored order ID, "
            "transaction binding, amount and currency."
        ),
        scenario_ids=(
            "PAYMENT-WRONG-ORDER-001",
            "PAYMENT-CAPTURE-WRONG-ORDER-001",
            "WEBHOOK-ORDER-BINDING-001",
        ),
    ),
    Invariant(
        invariant_id="INV-13-CAPTURE-REQUIRES-CLAIM",
        description=(
            "A verified webhook can only complete a payment this service already "
            "claimed as CAPTURE_PENDING; it cannot complete an unclaimed payment."
        ),
        scenario_ids=(
            "WEBHOOK-UNCLAIMED-001",
            "WEBHOOK-STATUS-001",
        ),
    ),
    Invariant(
        invariant_id="INV-14-STATE-MACHINE-CLOSED",
        description=(
            "Illegal payment state transitions are rejected before persistence."
        ),
        scenario_ids=("STATE-ILLEGAL-TRANSITION-001",),
    ),
)

__all__ = ["INVARIANTS"]
