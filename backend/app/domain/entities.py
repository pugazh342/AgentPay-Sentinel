"""Immutable domain entities.

Purchase intents are user-authored templates. Once created they are persisted
without an update path; the only mutation that is ever tolerated is tampering
in the database, which fingerprint verification detects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from uuid import UUID

from app.domain.enums import Decision, EventType, ReasonCode, RiskLevel
from app.domain.money import normalize_currency, normalize_money
from app.domain.time import ensure_utc


@dataclass(frozen=True, slots=True)
class PurchaseIntent:
    intent_id: UUID
    user_id: str
    purpose: str
    merchant_id: str
    product_category: str
    max_amount: Decimal
    currency: str
    max_quantity: int
    require_approval: bool
    created_at: datetime
    expires_at: datetime
    fingerprint: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.intent_id, UUID):
            raise ValueError("intent_id must be a UUID")
        for name in ("user_id", "purpose", "merchant_id", "product_category"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        object.__setattr__(self, "max_amount", normalize_money(self.max_amount))
        object.__setattr__(self, "currency", normalize_currency(self.currency))
        if not isinstance(self.max_quantity, int) or isinstance(
            self.max_quantity, bool
        ):
            raise ValueError("max_quantity must be an integer")
        if self.max_quantity < 1:
            raise ValueError("max_quantity must be at least 1")
        if not isinstance(self.require_approval, bool):
            raise ValueError("require_approval must be a boolean")
        object.__setattr__(self, "created_at", ensure_utc(self.created_at))
        object.__setattr__(self, "expires_at", ensure_utc(self.expires_at))
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")


@dataclass(frozen=True, slots=True)
class TransactionRequest:
    user_id: str
    intent_id: UUID
    merchant_id: str
    product_category: str
    amount: Decimal
    currency: str
    quantity: int
    request_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.intent_id, UUID):
            raise ValueError("intent_id must be a UUID")
        for name in (
            "user_id",
            "merchant_id",
            "product_category",
            "request_id",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        object.__setattr__(self, "amount", normalize_money(self.amount))
        object.__setattr__(self, "currency", normalize_currency(self.currency))
        if not isinstance(self.quantity, int) or isinstance(self.quantity, bool):
            raise ValueError("quantity must be an integer")
        if self.quantity < 1:
            raise ValueError("quantity must be at least 1")


@dataclass(frozen=True, slots=True)
class PolicyOutcome:
    decision: Decision
    reason_codes: tuple[ReasonCode, ...]
    explanation: str


@dataclass(frozen=True, slots=True)
class PaymentDecision:
    """Structured decision returned to the caller.

    The object deliberately contains no capture token or payment credential.
    """

    decision_id: UUID
    transaction_id: UUID
    intent_id: UUID
    decision: Decision
    reason_codes: tuple[ReasonCode, ...]
    explanation: str
    evaluated_at: datetime
    risk_level: RiskLevel

    def __post_init__(self) -> None:
        object.__setattr__(self, "evaluated_at", ensure_utc(self.evaluated_at))


@dataclass(frozen=True, slots=True)
class TransactionRecord:
    request: TransactionRequest
    decision: PaymentDecision


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    event_id: UUID
    transaction_id: UUID | None
    event_type: EventType
    decision: Decision | None
    reason_codes: tuple[ReasonCode, ...]
    timestamp: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "timestamp", ensure_utc(self.timestamp))
