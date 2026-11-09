"""Ports implemented by security and persistence adapters."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from app.domain.entities import PurchaseIntent, SecurityEvent, TransactionRecord
from app.domain.enums import Decision, EventType, PaymentState
from app.domain.payment import (
    Payment,
    PayPalCaptureResult,
    PayPalOrderResult,
    WebhookEventRecord,
)
from app.domain.threat import (
    ThreatAnalysisInput,
    ThreatAnalysisRecord,
    ThreatProviderResult,
)


class IntentFingerprintVerifier(Protocol):
    """Verifies that a stored intent still matches its HMAC fingerprint."""

    def verify_intent(self, intent: PurchaseIntent) -> bool: ...


class IntentRepository(Protocol):
    def add(self, intent: PurchaseIntent) -> None: ...

    def get(self, intent_id: UUID) -> PurchaseIntent | None: ...


class TransactionRepository(Protocol):
    def add(self, record: TransactionRecord) -> None: ...

    def get(self, transaction_id: UUID) -> TransactionRecord | None: ...


class SecurityEventRepository(Protocol):
    def add(self, event: SecurityEvent) -> None: ...

    def list_recent(
        self,
        *,
        limit: int,
        event_type: EventType | None = None,
        decision: Decision | None = None,
    ) -> list[SecurityEvent]: ...


class UnitOfWork(Protocol):
    def flush(self) -> None: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...


class ThreatAnalysisProvider(Protocol):
    """Advisory provider boundary. Never used by the policy engine."""

    @property
    def configured(self) -> bool: ...

    @property
    def model_name(self) -> str: ...

    def analyze(self, analysis_input: ThreatAnalysisInput) -> ThreatProviderResult: ...


class ThreatAnalysisRepository(Protocol):
    def add(self, record: ThreatAnalysisRecord) -> None: ...

    def get_latest(self, transaction_id: UUID) -> ThreatAnalysisRecord | None: ...


class PaymentRepository(Protocol):
    """Durable payment rows with conditional, version-checked transitions."""

    def add(self, payment: Payment) -> None: ...

    def get(self, payment_id: UUID) -> Payment | None: ...

    def get_by_transaction(self, transaction_id: UUID) -> Payment | None: ...

    def get_by_paypal_order(self, paypal_order_id: str) -> Payment | None: ...

    def transition(
        self,
        payment_id: UUID,
        *,
        expected_states: frozenset[PaymentState],
        new_state: PaymentState,
        expected_version: int | None,
        updated_at,
        **fields: object,
    ) -> Payment | None: ...

    def update_fields(
        self,
        payment_id: UUID,
        *,
        expected_state: PaymentState,
        expected_version: int | None,
        updated_at,
        **fields: object,
    ) -> Payment | None: ...


class WebhookEventRepository(Protocol):
    def try_add(self, record: WebhookEventRecord) -> bool: ...

    def mark_outcome(self, event_id: str, outcome: str) -> None: ...


class PayPalGateway(Protocol):
    """Provider boundary. Implementations must never log secrets or tokens."""

    @property
    def configured(self) -> bool: ...

    async def create_order(
        self,
        *,
        request_id: str,
        amount,
        currency: str,
        custom_id: str,
        description: str,
    ) -> PayPalOrderResult: ...

    async def get_order(self, order_id: str) -> PayPalOrderResult: ...

    async def capture_order(
        self,
        *,
        order_id: str,
        request_id: str,
        custom_id: str,
    ) -> PayPalCaptureResult: ...

    async def verify_webhook_signature(
        self,
        *,
        transmission_id: str,
        transmission_time: str,
        cert_url: str,
        auth_algo: str,
        transmission_sig: str,
        webhook_event: dict,
    ) -> bool: ...

    async def aclose(self) -> None: ...
