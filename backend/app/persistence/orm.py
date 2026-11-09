"""SQLAlchemy ORM models.

Monetary columns are stored as exact decimal strings, not floats or SQLite
NUMERIC. Timestamps are stored as canonical UTC ISO-8601 strings so SQLite
cannot drop timezone information.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from app.domain.time import canonical_timestamp


class Base(DeclarativeBase):
    pass


class UTCDateTime(TypeDecorator[datetime]):
    """Timezone-safe UTC datetime stored as canonical ISO-8601 text."""

    impl = String(32)
    cache_ok = True

    def process_bind_param(self, value, dialect):  # noqa: ANN001
        if value is None:
            return None
        return canonical_timestamp(value)

    def process_result_value(self, value, dialect):  # noqa: ANN001
        if value is None:
            return None
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


class IntentRow(Base):
    __tablename__ = "purchase_intents"

    intent_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(String(500), nullable=False)
    merchant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    product_category: Mapped[str] = mapped_column(String(64), nullable=False)
    max_amount: Mapped[str] = mapped_column(String(32), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    max_quantity: Mapped[int] = mapped_column(Integer, nullable=False)
    require_approval: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)


class TransactionRow(Base):
    __tablename__ = "transaction_evaluations"

    transaction_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    intent_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    merchant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    product_category: Mapped[str] = mapped_column(String(64), nullable=False)
    amount: Mapped[str] = mapped_column(String(32), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)
    decision_id: Mapped[str] = mapped_column(
        String(36), nullable=False, unique=True
    )
    decision: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    reason_codes: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class PaymentRow(Base):
    __tablename__ = "payments"

    payment_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    transaction_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("transaction_evaluations.transaction_id"),
        nullable=False,
        unique=True,
        index=True,
    )
    intent_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    merchant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    product_category: Mapped[str] = mapped_column(String(64), nullable=False)
    amount: Mapped[str] = mapped_column(String(32), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    paypal_order_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True, unique=True, index=True
    )
    approval_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    paypal_capture_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    paypal_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(), nullable=True
    )
    buyer_approved_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(), nullable=True
    )
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class PayPalWebhookEventRow(Base):
    __tablename__ = "paypal_webhook_events"

    # The PayPal event ID is the deduplication key. A second delivery of the
    # same event is acknowledged but never reconciled twice.
    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    paypal_order_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True
    )
    capture_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    verification_status: Mapped[str] = mapped_column(String(32), nullable=False)
    outcome: Mapped[str] = mapped_column(String(64), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, index=True
    )


class ThreatAnalysisRow(Base):
    __tablename__ = "threat_analyses"

    # Sequence preserves insertion order when several analyses share a clock
    # timestamp.
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        String(36), nullable=False, unique=True
    )
    transaction_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("transaction_evaluations.transaction_id"),
        nullable=False,
        index=True,
    )
    analysis_status: Mapped[str] = mapped_column(String(32), nullable=False)
    provider_status: Mapped[str] = mapped_column(String(32), nullable=False)
    threat_level: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    detected_threats: Mapped[list[dict]] = mapped_column(JSON, nullable=False)
    evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    suspicious_instructions: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    intent_alignment: Mapped[str] = mapped_column(String(16), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_handling: Mapped[str] = mapped_column(Text, nullable=False)
    model_name: Mapped[str] = mapped_column(String(128), nullable=False)
    analyzed_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, index=True
    )


class SecurityEventRow(Base):
    __tablename__ = "security_events"

    # Autoincrement key provides stable insertion-order tie-breaking when two
    # events share the same clock timestamp.
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(
        String(36), nullable=False, unique=True
    )
    transaction_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    decision: Mapped[str | None] = mapped_column(
        String(32), nullable=True, index=True
    )
    reason_codes: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, index=True
    )
