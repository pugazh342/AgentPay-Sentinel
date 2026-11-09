"""Payment workflow entities and the explicit state machine.

The state machine is intentionally small and closed. A payment can only move
along documented edges; callers cannot mutate a payment row into an arbitrary
state. Capture-related states are only reachable after deterministic
re-evaluation and verified PayPal responses.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID

from app.domain.enums import PaymentState, PayPalStatus
from app.domain.money import normalize_currency, normalize_money
from app.domain.time import ensure_utc

# Only these edges are legal. Terminal states have no outgoing edges.
ALLOWED_TRANSITIONS: dict[PaymentState, frozenset[PaymentState]] = {
    PaymentState.PENDING_SECURITY: frozenset(
        {
            PaymentState.REVIEW_REQUIRED,
            PaymentState.BLOCKED,
            PaymentState.PENDING_USER_APPROVAL,
            PaymentState.EXPIRED,
        }
    ),
    PaymentState.REVIEW_REQUIRED: frozenset(
        {PaymentState.BLOCKED, PaymentState.EXPIRED}
    ),
    PaymentState.BLOCKED: frozenset(),
    PaymentState.PENDING_USER_APPROVAL: frozenset(
        {
            PaymentState.PAYPAL_ORDER_CREATED,
            PaymentState.REVIEW_REQUIRED,
            PaymentState.BLOCKED,
            PaymentState.EXPIRED,
            PaymentState.FAILED,
        }
    ),
    PaymentState.PAYPAL_ORDER_CREATED: frozenset(
        {
            PaymentState.BUYER_APPROVED,
            PaymentState.COMPLETED,
            PaymentState.FAILED,
            PaymentState.EXPIRED,
        }
    ),
    PaymentState.BUYER_APPROVED: frozenset(
        {
            PaymentState.CAPTURE_PENDING,
            PaymentState.COMPLETED,
            PaymentState.FAILED,
            PaymentState.EXPIRED,
        }
    ),
    PaymentState.CAPTURE_PENDING: frozenset(
        {PaymentState.COMPLETED, PaymentState.FAILED}
    ),
    PaymentState.COMPLETED: frozenset(),
    PaymentState.FAILED: frozenset(),
    PaymentState.EXPIRED: frozenset(),
}

TERMINAL_STATES = frozenset(
    {
        PaymentState.COMPLETED,
        PaymentState.FAILED,
        PaymentState.EXPIRED,
    }
)


def can_transition(current: PaymentState, target: PaymentState) -> bool:
    """Return whether ``current -> target`` is an explicitly allowed edge."""

    return target in ALLOWED_TRANSITIONS[current]


def assert_transition(current: PaymentState, target: PaymentState) -> None:
    """Raise before a disallowed state change is attempted."""

    if not can_transition(current, target):
        raise ValueError(
            f"illegal payment state transition: {current.value} -> {target.value}"
        )


@dataclass(frozen=True, slots=True)
class Payment:
    """Durable payment aggregate.

    Contains no PayPal credential, access token or client secret. The PayPal
    order ID is a provider reference, not an authorization token.
    """

    payment_id: UUID
    transaction_id: UUID
    intent_id: UUID
    user_id: str
    merchant_id: str
    product_category: str
    amount: Decimal
    currency: str
    state: PaymentState
    version: int
    created_at: datetime
    updated_at: datetime
    paypal_order_id: str | None = None
    approval_url: str | None = None
    paypal_capture_id: str | None = None
    paypal_status: str | None = None
    approved_by: str | None = None
    approved_at: datetime | None = None
    buyer_approved_at: datetime | None = None
    completed_at: datetime | None = None
    failure_reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.payment_id, UUID):
            raise ValueError("payment_id must be a UUID")
        if not isinstance(self.transaction_id, UUID):
            raise ValueError("transaction_id must be a UUID")
        if not isinstance(self.intent_id, UUID):
            raise ValueError("intent_id must be a UUID")
        for name in ("user_id", "merchant_id", "product_category"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        object.__setattr__(self, "amount", normalize_money(self.amount))
        object.__setattr__(self, "currency", normalize_currency(self.currency))
        if not isinstance(self.state, PaymentState):
            object.__setattr__(self, "state", PaymentState(self.state))
        if not isinstance(self.version, int) or isinstance(self.version, bool):
            raise ValueError("version must be an integer")
        if self.version < 0:
            raise ValueError("version must not be negative")
        object.__setattr__(self, "created_at", ensure_utc(self.created_at))
        object.__setattr__(self, "updated_at", ensure_utc(self.updated_at))
        for name in ("approved_at", "buyer_approved_at", "completed_at"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, ensure_utc(value))


@dataclass(frozen=True, slots=True)
class PayPalOrderResult:
    """Safe projection of a PayPal order response."""

    order_id: str
    status: str
    amount: Decimal | None
    currency: str | None
    approval_url: str | None = None
    custom_id: str | None = None
    capture_id: str | None = None
    capture_status: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.order_id, str) or not self.order_id.strip():
            raise ValueError("order_id must be a non-empty string")
        object.__setattr__(self, "status", str(self.status).strip().upper())
        if self.amount is not None:
            object.__setattr__(self, "amount", normalize_money(self.amount))
        if self.currency is not None:
            object.__setattr__(self, "currency", normalize_currency(self.currency))


@dataclass(frozen=True, slots=True)
class PayPalCaptureResult:
    """Safe projection of a PayPal capture response."""

    order_id: str
    capture_id: str
    capture_status: str
    order_status: str
    amount: Decimal
    currency: str
    custom_id: str | None = None

    def __post_init__(self) -> None:
        for name in ("order_id", "capture_id", "capture_status", "order_status"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
            object.__setattr__(self, name, value.strip().upper() if name.endswith("status") else value.strip())
        object.__setattr__(self, "amount", normalize_money(self.amount))
        object.__setattr__(self, "currency", normalize_currency(self.currency))


@dataclass(frozen=True, slots=True)
class PayPalWebhookEvent:
    """Minimal verified event projection used for reconciliation."""

    event_id: str
    event_type: str
    paypal_order_id: str | None
    capture_id: str | None
    capture_status: str | None
    amount: Decimal | None
    currency: str | None


@dataclass(frozen=True, slots=True)
class WebhookEventRecord:
    event_id: str
    event_type: str
    paypal_order_id: str | None
    capture_id: str | None
    verification_status: PayPalStatus
    received_at: datetime
    outcome: str = "RECEIVED"

    def __post_init__(self) -> None:
        object.__setattr__(self, "received_at", ensure_utc(self.received_at))


@dataclass(frozen=True, slots=True)
class WebhookProcessingResult:
    event_id: str
    event_type: str
    duplicate: bool
    outcome: str


__all__ = [
    "ALLOWED_TRANSITIONS",
    "TERMINAL_STATES",
    "Payment",
    "PayPalCaptureResult",
    "PayPalOrderResult",
    "PayPalWebhookEvent",
    "WebhookEventRecord",
    "WebhookProcessingResult",
    "assert_transition",
    "can_transition",
]
