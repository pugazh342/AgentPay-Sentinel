"""Payment workflow use cases.

Order creation and capture are asynchronous provider calls wrapped in durable,
version-checked state transitions. The deterministic policy remains the only
authorization authority; the AI layer is not imported here at all.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.exc import IntegrityError

logger = logging.getLogger("agentpay")

from app.domain.clock import Clock
from app.domain.entities import PaymentDecision, PurchaseIntent, TransactionRecord
from app.domain.enums import Decision, PaymentState, PayPalStatus, ReasonCode
from app.domain.errors import (
    CaptureInProgress,
    NotFoundFailure,
    PayPalGatewayError,
    PayPalNotConfigured,
    PayPalProviderFailure,
    PaymentNotEligible,
    PaymentStateFailure,
    ValidationFailure,
    WebhookVerificationFailure,
)
from app.domain.payment import (
    Payment,
    PayPalOrderResult,
    PayPalWebhookEvent,
    WebhookEventRecord,
    WebhookProcessingResult,
    can_transition,
)
from app.domain.policy import evaluate_policy
from app.domain.ports import (
    IntentRepository,
    PayPalGateway,
    PaymentRepository,
    TransactionRepository,
    UnitOfWork,
    WebhookEventRepository,
)
from app.security.fingerprint import FingerprintService

_CAPTURE_EVENT_TYPES = frozenset(
    {
        "PAYMENT.CAPTURE.COMPLETED",
        "PAYMENT.CAPTURE.DENIED",
        "PAYMENT.CAPTURE.DECLINED",
        "PAYMENT.CAPTURE.FAILED",
        "PAYMENT.CAPTURE.REVERSED",
    }
)
_CAPTURE_FAILURE_EVENTS = _CAPTURE_EVENT_TYPES - {
    "PAYMENT.CAPTURE.COMPLETED"
}


@dataclass(frozen=True, slots=True)
class _EligibilityFailure:
    state: PaymentState
    reason: str


class PaymentService:
    def __init__(
        self,
        *,
        intents: IntentRepository,
        transactions: TransactionRepository,
        payments: PaymentRepository,
        webhook_events: WebhookEventRepository,
        fingerprints: FingerprintService,
        clock: Clock,
        gateway: PayPalGateway,
        unit_of_work: UnitOfWork,
    ) -> None:
        self._intents = intents
        self._transactions = transactions
        self._payments = payments
        self._webhook_events = webhook_events
        self._fingerprints = fingerprints
        self._clock = clock
        self._gateway = gateway
        self._unit_of_work = unit_of_work

    # ------------------------------------------------------------------
    # Read / list
    # ------------------------------------------------------------------
    def get(self, payment_id: UUID) -> Payment | None:
        return self._payments.get(payment_id)

    def list_payments(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        state: PaymentState | None = None,
        intent_id: UUID | None = None,
        transaction_id: UUID | None = None,
    ) -> list[Payment]:
        """List payments with optional filtering and pagination.

        Returns payments ordered by creation time descending.
        """
        return self._payments.list(
            limit=limit,
            offset=offset,
            state=state,
            intent_id=intent_id,
            transaction_id=transaction_id,
        )

    def count_payments(
        self,
        *,
        state: PaymentState | None = None,
        intent_id: UUID | None = None,
        transaction_id: UUID | None = None,
    ) -> int:
        """Return the total count of payments matching the given filters.

        Uses the same predicates as ``list_payments`` so that ``total_count``
        reflects the filtered dataset size rather than the current page size.
        """
        return self._payments.count(
            state=state,
            intent_id=intent_id,
            transaction_id=transaction_id,
        )

    # ------------------------------------------------------------------
    # Read / prepare
    # ------------------------------------------------------------------
    async def prepare(self, transaction_id: UUID) -> Payment:
        """Create (or return) the single payment bound to a transaction.

        SECURITY: Payment preparation creates an audit record for ALL transaction
        states. BLOCK and REVIEW_REQUIRED payments are created in their terminal
        states and cannot transition. Only ALLOW_FOR_APPROVAL payments proceed
        to PENDING_USER_APPROVAL and can be approved.

        The frontend must check the returned payment.state to determine next steps.
        """

        existing = self._payments.get_by_transaction(transaction_id)
        if existing is not None:
            return existing

        record = self._transactions.get(transaction_id)
        if record is None:
            raise NotFoundFailure("Transaction not found.")

        now = self._clock.now()
        failure = self._prepare_failure(record, now)
        target = (
            failure.state if failure is not None else PaymentState.PENDING_USER_APPROVAL
        )

        payment = Payment(
            payment_id=uuid4(),
            transaction_id=record.decision.transaction_id,
            intent_id=record.decision.intent_id,
            user_id=record.request.user_id,
            merchant_id=record.request.merchant_id,
            product_category=record.request.product_category,
            amount=record.request.amount,
            currency=record.request.currency,
            state=PaymentState.PENDING_SECURITY,
            version=0,
            created_at=now,
            updated_at=now,
        )

        try:
            self._payments.add(payment)
            self._unit_of_work.flush()
            if target is not PaymentState.PENDING_SECURITY:
                transitioned = self._payments.transition(
                    payment.payment_id,
                    expected_states=frozenset({PaymentState.PENDING_SECURITY}),
                    new_state=target,
                    expected_version=payment.version,
                    updated_at=now,
                    failure_reason=failure.reason if failure else None,
                )
                if transitioned is None:
                    raise PaymentStateFailure(
                        "Payment could not be initialised safely."
                    )
                payment = transitioned
            self._unit_of_work.commit()
        except IntegrityError:
            # A concurrent request created the same transaction payment first.
            # The unique transaction_id constraint is the authoritative guard.
            self._unit_of_work.rollback()
            existing = self._payments.get_by_transaction(transaction_id)
            if existing is None:
                raise
            return existing

        return payment

    # ------------------------------------------------------------------
    # Application-level demo approval + order creation
    # ------------------------------------------------------------------
    async def approve(self, payment_id: UUID, approved_by: str) -> Payment:
        if not isinstance(approved_by, str) or not approved_by.strip():
            raise ValidationFailure("approved_by must be a non-empty identifier.")
        payment = self._load_or_404(payment_id)
        if payment.state is PaymentState.COMPLETED:
            return payment
        if payment.state is not PaymentState.PENDING_USER_APPROVAL:
            raise PaymentStateFailure(
                f"Payment cannot be approved from state {payment.state.value}."
            )

        failure = self._revalidate(payment)
        if failure is not None:
            self._apply_failure(payment, failure)
            raise PaymentNotEligible(failure.reason)

        if not self._gateway.configured:
            raise PayPalNotConfigured(
                "PayPal sandbox is not configured; payment creation is disabled."
            )

        record = self._transactions.get(payment.transaction_id)
        if record is None:
            self._apply_failure(
                payment,
                _EligibilityFailure(
                    PaymentState.FAILED,
                    "The underlying transaction no longer exists.",
                ),
            )
            raise PaymentNotEligible("The underlying transaction no longer exists.")
        intent = self._intents.get(record.request.intent_id)
        description = intent.purpose if intent is not None else "Approved purchase"

        now = self._clock.now()
        claimed = self._payments.transition(
            payment.payment_id,
            expected_states=frozenset({PaymentState.PENDING_USER_APPROVAL}),
            new_state=PaymentState.PAYPAL_ORDER_CREATED,
            expected_version=payment.version,
            updated_at=now,
            approved_by=approved_by,
            approved_at=now,
        )
        if claimed is None:
            self._raise_concurrent(payment_id)
        self._unit_of_work.commit()

        try:
            order = await self._gateway.create_order(
                request_id=f"agentpay-order-{payment.payment_id}",
                amount=payment.amount,
                currency=payment.currency,
                custom_id=str(payment.transaction_id),
                description=description,
            )
        except PayPalGatewayError as exc:
            self._mark_failed(claimed, exc.message, exc.status)
            raise PayPalProviderFailure(exc.message) from exc

        mismatch = self._order_mismatch(payment, order)
        if mismatch is not None:
            self._mark_failed(claimed, mismatch, PayPalStatus.INVALID_RESPONSE)
            raise PayPalProviderFailure(mismatch)

        if not order.approval_url:
            self._mark_failed(
                claimed,
                "PayPal did not return an approval URL.",
                PayPalStatus.INVALID_RESPONSE,
            )
            raise PayPalProviderFailure(
                "PayPal did not return a buyer approval URL."
            )

        updated = self._payments.update_fields(
            claimed.payment_id,
            expected_state=PaymentState.PAYPAL_ORDER_CREATED,
            expected_version=claimed.version,
            updated_at=self._clock.now(),
            paypal_order_id=order.order_id,
            approval_url=order.approval_url,
            paypal_status=order.status,
        )
        if updated is None:
            self._raise_concurrent(payment_id)
        self._unit_of_work.commit()
        return updated

    # ------------------------------------------------------------------
    # Buyer return: browser data is untrusted; ask PayPal directly
    # ------------------------------------------------------------------
    async def buyer_return(self, payment_id: UUID) -> Payment:
        payment = self._load_or_404(payment_id)
        if payment.state in {PaymentState.COMPLETED, PaymentState.BUYER_APPROVED}:
            return payment
        if payment.state is not PaymentState.PAYPAL_ORDER_CREATED:
            raise PaymentStateFailure(
                f"Buyer return is not valid from state {payment.state.value}."
            )
        if not payment.paypal_order_id:
            self._mark_failed(
                payment,
                "Stored PayPal order ID is missing.",
                PayPalStatus.INVALID_RESPONSE,
            )
            raise PaymentStateFailure("Stored PayPal order ID is missing.")
        if not self._gateway.configured:
            raise PayPalNotConfigured(
                "PayPal sandbox is not configured; buyer return cannot be verified."
            )

        try:
            order = await self._gateway.get_order(payment.paypal_order_id)
        except PayPalGatewayError as exc:
            raise PayPalProviderFailure(exc.message) from exc

        mismatch = self._order_mismatch(payment, order)
        if mismatch is not None:
            self._mark_failed(payment, mismatch, PayPalStatus.INVALID_RESPONSE)
            raise PayPalProviderFailure(mismatch)

        now = self._clock.now()
        if order.status == "COMPLETED":
            if (
                not order.capture_id
                or order.capture_status != "COMPLETED"
                or order.amount != payment.amount
                or order.currency != payment.currency
            ):
                self._mark_failed(
                    payment,
                    "PayPal reported the order as completed without a verifiable capture.",
                    PayPalStatus.INVALID_RESPONSE,
                )
                raise PayPalProviderFailure(
                    "PayPal order completion could not be verified."
                )
            updated = self._payments.transition(
                payment.payment_id,
                expected_states=frozenset({PaymentState.PAYPAL_ORDER_CREATED}),
                new_state=PaymentState.COMPLETED,
                expected_version=payment.version,
                updated_at=now,
                paypal_capture_id=order.capture_id,
                paypal_status=order.capture_status,
                buyer_approved_at=now,
                completed_at=now,
            )
            if updated is None:
                current = self._payments.get(payment_id)
                if current is not None and current.state is PaymentState.COMPLETED:
                    return current
                self._raise_concurrent(payment_id)
            self._unit_of_work.commit()
            return updated

        if order.status != "APPROVED":
            # The buyer has not approved in PayPal. This is not proof of
            # payment and must not advance the workflow.
            return payment

        updated = self._payments.transition(
            payment.payment_id,
            expected_states=frozenset({PaymentState.PAYPAL_ORDER_CREATED}),
            new_state=PaymentState.BUYER_APPROVED,
            expected_version=payment.version,
            updated_at=now,
            buyer_approved_at=now,
            paypal_status=order.status,
        )
        if updated is None:
            current = self._payments.get(payment_id)
            if current is not None and current.state is PaymentState.BUYER_APPROVED:
                return current
            self._raise_concurrent(payment_id)
        self._unit_of_work.commit()
        return updated

    # ------------------------------------------------------------------
    # Capture
    # ------------------------------------------------------------------
    async def capture(self, payment_id: UUID) -> Payment:
        payment = self._load_or_404(payment_id)
        if payment.state is PaymentState.COMPLETED:
            return payment
        if payment.state is PaymentState.CAPTURE_PENDING:
            raise CaptureInProgress(
                "A capture for this payment is already in progress."
            )
        if payment.state is not PaymentState.BUYER_APPROVED:
            raise PaymentStateFailure(
                f"Capture is not allowed from state {payment.state.value}."
            )

        failure = self._revalidate(payment)
        if failure is not None:
            self._apply_failure(payment, failure)
            raise PaymentNotEligible(failure.reason)

        if not payment.paypal_order_id:
            self._mark_failed(
                payment,
                "Stored PayPal order ID is missing.",
                PayPalStatus.INVALID_RESPONSE,
            )
            raise PaymentStateFailure("Stored PayPal order ID is missing.")
        if not self._gateway.configured:
            raise PayPalNotConfigured(
                "PayPal sandbox is not configured; capture is disabled."
            )

        try:
            order = await self._gateway.get_order(payment.paypal_order_id)
        except PayPalGatewayError as exc:
            raise PayPalProviderFailure(exc.message) from exc

        mismatch = self._order_mismatch(payment, order)
        if mismatch is not None:
            self._mark_failed(payment, mismatch, PayPalStatus.INVALID_RESPONSE)
            raise PayPalProviderFailure(mismatch)

        if order.status == "COMPLETED":
            # PayPal already holds a capture for this order. Only record it if
            # the capture record matches the authorized amount and currency.
            if (
                not order.capture_id
                or order.capture_status != "COMPLETED"
                or order.amount != payment.amount
                or order.currency != payment.currency
            ):
                self._mark_failed(
                    payment,
                    "PayPal order was already completed without a verifiable capture.",
                    PayPalStatus.INVALID_RESPONSE,
                )
                raise PayPalProviderFailure(
                    "PayPal order completion could not be verified."
                )
            updated = self._payments.transition(
                payment.payment_id,
                expected_states=frozenset({PaymentState.BUYER_APPROVED}),
                new_state=PaymentState.COMPLETED,
                expected_version=payment.version,
                updated_at=self._clock.now(),
                paypal_capture_id=order.capture_id,
                paypal_status=order.capture_status,
                completed_at=self._clock.now(),
            )
            if updated is None:
                current = self._payments.get(payment_id)
                if current is not None and current.state is PaymentState.COMPLETED:
                    return current
                self._raise_concurrent(payment_id)
            self._unit_of_work.commit()
            return updated

        if order.status != "APPROVED":
            raise PaymentNotEligible(
                "PayPal does not report the order as buyer-approved."
            )

        now = self._clock.now()
        claimed = self._payments.transition(
            payment.payment_id,
            expected_states=frozenset({PaymentState.BUYER_APPROVED}),
            new_state=PaymentState.CAPTURE_PENDING,
            expected_version=payment.version,
            updated_at=now,
        )
        if claimed is None:
            current = self._payments.get(payment.payment_id)
            if current is not None and current.state is PaymentState.COMPLETED:
                return current
            if current is not None and current.state is PaymentState.CAPTURE_PENDING:
                raise CaptureInProgress(
                    "A capture for this payment is already in progress."
                )
            raise PaymentStateFailure(
                "The payment state changed before capture could be claimed."
            )
        # The claim is committed before the provider call so an ambiguous
        # provider outcome is durable and reconcilable by a verified webhook.
        self._unit_of_work.commit()

        try:
            result = await self._gateway.capture_order(
                order_id=payment.paypal_order_id,
                request_id=f"agentpay-capture-{payment.payment_id}",
                custom_id=str(payment.transaction_id),
            )
        except PayPalGatewayError as exc:
            if exc.ambiguous:
                self._payments.update_fields(
                    claimed.payment_id,
                    expected_state=PaymentState.CAPTURE_PENDING,
                    expected_version=claimed.version,
                    updated_at=self._clock.now(),
                    paypal_status=exc.status.value,
                    failure_reason=(
                        "Capture outcome is unknown; reconcile through a verified "
                        "PayPal webhook before retrying."
                    ),
                )
                self._unit_of_work.commit()
                raise PayPalProviderFailure(
                    "Capture outcome is unknown; reconcile through a verified "
                    "PayPal webhook before retrying."
                ) from exc

            self._payments.transition(
                claimed.payment_id,
                expected_states=frozenset({PaymentState.CAPTURE_PENDING}),
                new_state=PaymentState.FAILED,
                expected_version=claimed.version,
                updated_at=self._clock.now(),
                paypal_status=exc.status.value,
                failure_reason=exc.message,
            )
            self._unit_of_work.commit()
            raise PayPalProviderFailure(exc.message) from exc

        if (
            result.capture_status != "COMPLETED"
            or not result.capture_id
            or result.custom_id != str(payment.transaction_id)
            or result.amount != payment.amount
            or result.currency != payment.currency
        ):
            # The provider may have captured funds but returned an incomplete or
            # mismatched record. Keep CAPTURE_PENDING for webhook reconciliation
            # rather than marking the payment failed.
            self._payments.update_fields(
                claimed.payment_id,
                expected_state=PaymentState.CAPTURE_PENDING,
                expected_version=claimed.version,
                updated_at=self._clock.now(),
                paypal_status=PayPalStatus.INVALID_RESPONSE.value,
                failure_reason=(
                    "Capture response could not be verified; reconcile through a "
                    "verified PayPal webhook."
                ),
            )
            self._unit_of_work.commit()
            raise PayPalProviderFailure(
                "The PayPal capture response could not be verified."
            )

        completed = self._payments.transition(
            claimed.payment_id,
            expected_states=frozenset({PaymentState.CAPTURE_PENDING}),
            new_state=PaymentState.COMPLETED,
            expected_version=claimed.version,
            updated_at=self._clock.now(),
            paypal_capture_id=result.capture_id,
            paypal_status=result.capture_status,
            completed_at=self._clock.now(),
        )
        if completed is None:
            current = self._payments.get(payment.payment_id)
            if current is not None and current.state is PaymentState.COMPLETED:
                return current
            raise PaymentStateFailure(
                "Capture completed but the durable state could not be recorded."
            )
        self._unit_of_work.commit()
        return completed

    # ------------------------------------------------------------------
    # Webhooks
    # ------------------------------------------------------------------
    async def handle_webhook(
        self,
        *,
        event: dict[str, Any],
        transmission_id: str,
        transmission_time: str,
        cert_url: str,
        auth_algo: str,
        transmission_sig: str,
    ) -> WebhookProcessingResult:
        verified = await self._gateway.verify_webhook_signature(
            transmission_id=transmission_id,
            transmission_time=transmission_time,
            cert_url=cert_url,
            auth_algo=auth_algo,
            transmission_sig=transmission_sig,
            webhook_event=event,
        )
        if not verified:
            raise WebhookVerificationFailure(
                "PayPal webhook signature verification failed."
            )

        event_id = event.get("id")
        event_type = event.get("event_type")
        if (
            not isinstance(event_id, str)
            or not event_id.strip()
            or not isinstance(event_type, str)
            or not event_type.strip()
        ):
            raise WebhookVerificationFailure(
                "Webhook event is missing required identifiers."
            )

        projection = self._project_webhook(event, event_id, event_type)
        record = WebhookEventRecord(
            event_id=projection.event_id,
            event_type=projection.event_type,
            paypal_order_id=projection.paypal_order_id,
            capture_id=projection.capture_id,
            verification_status=PayPalStatus.OK,
            received_at=self._clock.now(),
        )
        inserted = self._webhook_events.try_add(record)
        if not inserted:
            self._unit_of_work.commit()
            return WebhookProcessingResult(
                event_id=projection.event_id,
                event_type=projection.event_type,
                duplicate=True,
                outcome="DUPLICATE",
            )

        outcome = self._reconcile_webhook(projection)
        self._webhook_events.mark_outcome(projection.event_id, outcome)
        self._unit_of_work.commit()
        return WebhookProcessingResult(
            event_id=projection.event_id,
            event_type=projection.event_type,
            duplicate=False,
            outcome=outcome,
        )

    def _reconcile_webhook(self, event: PayPalWebhookEvent) -> str:
        if not event.paypal_order_id:
            return "UNMATCHED"

        payment = self._payments.get_by_paypal_order(event.paypal_order_id)
        if payment is None:
            return "UNMATCHED"

        now = self._clock.now()
        if event.event_type == "CHECKOUT.ORDER.APPROVED":
            updated = self._payments.transition(
                payment.payment_id,
                expected_states=frozenset({PaymentState.PAYPAL_ORDER_CREATED}),
                new_state=PaymentState.BUYER_APPROVED,
                expected_version=None,
                updated_at=now,
                buyer_approved_at=now,
                paypal_status="APPROVED",
            )
            return "BUYER_APPROVED" if updated is not None else "IGNORED"

        if event.event_type == "PAYMENT.CAPTURE.COMPLETED":
            if event.capture_status != "COMPLETED":
                return "IGNORED"
            if not event.capture_id:
                return "IGNORED"
            if (
                event.amount is None
                or event.currency is None
                or event.amount != payment.amount
                or event.currency != payment.currency
            ):
                # Verified event, but it does not match the authorized money.
                return "AMOUNT_MISMATCH"

            updated = self._payments.transition(
                payment.payment_id,
                expected_states=frozenset({PaymentState.CAPTURE_PENDING}),
                new_state=PaymentState.COMPLETED,
                expected_version=None,
                updated_at=now,
                paypal_capture_id=event.capture_id,
                paypal_status="COMPLETED",
                completed_at=now,
            )
            if updated is not None:
                return "COMPLETED"
            if payment.state is PaymentState.COMPLETED:
                return "ALREADY_COMPLETED"
            return "IGNORED"

        if event.event_type in _CAPTURE_FAILURE_EVENTS:
            updated = self._payments.transition(
                payment.payment_id,
                expected_states=frozenset({PaymentState.CAPTURE_PENDING}),
                new_state=PaymentState.FAILED,
                expected_version=None,
                updated_at=now,
                paypal_status=event.capture_status or event.event_type,
                failure_reason=(
                    f"PayPal reported capture status {event.capture_status or event.event_type}."
                ),
            )
            return "FAILED" if updated is not None else "IGNORED"

        return "IGNORED"

    @staticmethod
    def _project_webhook(
        event: dict[str, Any], event_id: str, event_type: str
    ) -> PayPalWebhookEvent:
        resource = event.get("resource")
        if not isinstance(resource, dict):
            resource = {}

        resource_id = resource.get("id")
        order_id = None
        if event_type == "CHECKOUT.ORDER.APPROVED":
            order_id = resource_id if isinstance(resource_id, str) else None
        elif event_type.startswith("PAYMENT.CAPTURE."):
            supplementary = resource.get("supplementary_data")
            related = (
                supplementary.get("related_ids")
                if isinstance(supplementary, dict)
                else None
            )
            if isinstance(related, dict):
                candidate = related.get("order_id")
                order_id = candidate if isinstance(candidate, str) else None

        capture_id = (
            resource_id
            if event_type.startswith("PAYMENT.CAPTURE.")
            and isinstance(resource_id, str)
            else None
        )

        amount_data = resource.get("amount")
        amount = None
        currency = None
        if isinstance(amount_data, dict):
            raw_value = amount_data.get("value")
            try:
                amount = Decimal(str(raw_value)) if raw_value is not None else None
            except (InvalidOperation, TypeError, ValueError):
                amount = None
            raw_currency = amount_data.get("currency_code")
            currency = (
                raw_currency.strip().upper()
                if isinstance(raw_currency, str) and raw_currency.strip()
                else None
            )

        status = resource.get("status")
        capture_status = (
            status.strip().upper()
            if isinstance(status, str) and status.strip()
            else None
        )

        return PayPalWebhookEvent(
            event_id=event_id,
            event_type=event_type,
            paypal_order_id=order_id,
            capture_id=capture_id,
            capture_status=capture_status,
            amount=amount,
            currency=currency,
        )

    # ------------------------------------------------------------------
    # Revalidation helpers
    # ------------------------------------------------------------------
    def _prepare_failure(
        self, record: TransactionRecord, now: datetime
    ) -> _EligibilityFailure | None:
        decision = record.decision
        if decision.decision is not Decision.ALLOW_FOR_APPROVAL:
            if (
                decision.decision is Decision.BLOCK
                and ReasonCode.INTENT_EXPIRED in decision.reason_codes
            ):
                return _EligibilityFailure(
                    PaymentState.EXPIRED,
                    "The purchase intent has expired.",
                )
            if decision.decision is Decision.REVIEW_REQUIRED:
                return _EligibilityFailure(
                    PaymentState.REVIEW_REQUIRED,
                    "Deterministic policy requires human review.",
                )
            return _EligibilityFailure(
                PaymentState.BLOCKED,
                "Deterministic policy blocked this transaction.",
            )

        intent = self._intents.get(record.request.intent_id)
        if intent is None:
            return _EligibilityFailure(
                PaymentState.BLOCKED,
                "The purchase intent no longer exists.",
            )
        outcome = evaluate_policy(
            record.request,
            intent,
            verifier=self._fingerprints,
            now=now,
        )
        if outcome.decision is Decision.ALLOW_FOR_APPROVAL:
            return None
        if ReasonCode.INTENT_EXPIRED in outcome.reason_codes:
            return _EligibilityFailure(
                PaymentState.EXPIRED,
                outcome.explanation,
            )
        if outcome.decision is Decision.REVIEW_REQUIRED:
            return _EligibilityFailure(
                PaymentState.REVIEW_REQUIRED,
                outcome.explanation,
            )
        return _EligibilityFailure(PaymentState.BLOCKED, outcome.explanation)

    def _revalidate(self, payment: Payment) -> _EligibilityFailure | None:
        record = self._transactions.get(payment.transaction_id)
        if record is None:
            return _EligibilityFailure(
                PaymentState.FAILED,
                "The underlying transaction no longer exists.",
            )
        decision: PaymentDecision = record.decision
        if decision.decision is not Decision.ALLOW_FOR_APPROVAL:
            if (
                decision.decision is Decision.BLOCK
                and ReasonCode.INTENT_EXPIRED in decision.reason_codes
            ):
                return _EligibilityFailure(
                    PaymentState.EXPIRED, "The purchase intent has expired."
                )
            if decision.decision is Decision.REVIEW_REQUIRED:
                return _EligibilityFailure(
                    PaymentState.REVIEW_REQUIRED,
                    "Deterministic policy requires human review.",
                )
            return _EligibilityFailure(
                PaymentState.BLOCKED,
                "Deterministic policy blocked this transaction.",
            )

        request = record.request
        if (
            request.intent_id != payment.intent_id
            or request.user_id != payment.user_id
            or request.merchant_id != payment.merchant_id
            or request.product_category != payment.product_category
            or request.amount != payment.amount
            or request.currency != payment.currency
        ):
            return _EligibilityFailure(
                PaymentState.FAILED,
                "Stored payment fields no longer match the evaluated transaction.",
            )

        intent = self._intents.get(request.intent_id)
        if intent is None:
            return _EligibilityFailure(
                PaymentState.BLOCKED, "The purchase intent no longer exists."
            )

        outcome = evaluate_policy(
            request,
            intent,
            verifier=self._fingerprints,
            now=self._clock.now(),
        )
        if outcome.decision is Decision.ALLOW_FOR_APPROVAL:
            return None
        if ReasonCode.INTENT_EXPIRED in outcome.reason_codes:
            return _EligibilityFailure(PaymentState.EXPIRED, outcome.explanation)
        if outcome.decision is Decision.REVIEW_REQUIRED:
            return _EligibilityFailure(
                PaymentState.REVIEW_REQUIRED, outcome.explanation
            )
        return _EligibilityFailure(PaymentState.BLOCKED, outcome.explanation)

    def _order_mismatch(
        self, payment: Payment, order: PayPalOrderResult
    ) -> str | None:
        if payment.paypal_order_id and order.order_id != payment.paypal_order_id:
            logger.warning(
                "paypal_binding_order_id_mismatch",
                extra={
                    "payment_id": str(payment.payment_id),
                    "transaction_id": str(payment.transaction_id),
                    "expected_order_id": payment.paypal_order_id,
                    "received_order_id": order.order_id,
                },
            )
            return "PayPal returned a different order ID than the stored payment."
        expected_transaction_id = str(payment.transaction_id)
        if order.custom_id != expected_transaction_id:
            logger.warning(
                "paypal_binding_custom_id_mismatch",
                extra={
                    "payment_id": str(payment.payment_id),
                    "transaction_id": expected_transaction_id,
                    "expected_custom_id": expected_transaction_id,
                    "received_custom_id": order.custom_id,
                    "raw_custom_id": order.raw_custom_id,
                    "raw_reference_id": order.raw_reference_id,
                    "paypal_order_id": order.order_id,
                    "binding_validated": order.custom_id == expected_transaction_id,
                },
            )
            return "PayPal order is not bound to this internal transaction."
        if order.amount is None or order.currency is None:
            return "PayPal order did not include a verifiable amount."
        if order.amount != payment.amount:
            return "PayPal order amount does not match the authorized amount."
        if order.currency != payment.currency:
            return "PayPal order currency does not match the authorized currency."
        return None

    def _apply_failure(
        self, payment: Payment, failure: _EligibilityFailure
    ) -> None:
        target = failure.state
        if not can_transition(payment.state, target):
            target = PaymentState.FAILED
        if not can_transition(payment.state, target):
            return
        updated = self._payments.transition(
            payment.payment_id,
            expected_states=frozenset({payment.state}),
            new_state=target,
            expected_version=payment.version,
            updated_at=self._clock.now(),
            failure_reason=failure.reason,
        )
        if updated is not None:
            self._unit_of_work.commit()

    def _mark_failed(
        self, payment: Payment, reason: str, status: PayPalStatus
    ) -> None:
        if not can_transition(payment.state, PaymentState.FAILED):
            return
        self._payments.transition(
            payment.payment_id,
            expected_states=frozenset({payment.state}),
            new_state=PaymentState.FAILED,
            expected_version=payment.version,
            updated_at=self._clock.now(),
            failure_reason=reason,
            paypal_status=status.value,
        )
        self._unit_of_work.commit()

    def _load_or_404(self, payment_id: UUID) -> Payment:
        payment = self._payments.get(payment_id)
        if payment is None:
            raise NotFoundFailure("Payment not found.")
        return payment

    def _raise_concurrent(self, payment_id: UUID) -> None:
        current = self._payments.get(payment_id)
        if current is not None and current.state is PaymentState.CAPTURE_PENDING:
            raise CaptureInProgress(
                "A capture for this payment is already in progress."
            )
        raise PaymentStateFailure(
            "The payment state changed before the operation could be applied."
        )


__all__ = ["PaymentService"]
