"""SQLAlchemy repository and unit-of-work adapters."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.domain.entities import (
    PaymentDecision,
    PurchaseIntent,
    SecurityEvent,
    TransactionRecord,
    TransactionRequest,
)
from app.domain.enums import (
    AnalysisStatus,
    Decision,
    EventType,
    IntentAlignment,
    PaymentState,
    ProviderStatus,
    ReasonCode,
    RiskLevel,
    ThreatCategory,
    ThreatLevel,
    ThreatSeverity,
)
from app.domain.money import money_from_storage, money_to_storage
from app.domain.payment import (
    Payment,
    WebhookEventRecord,
    assert_transition,
)
from app.domain.threat import (
    DetectedThreat,
    ThreatAnalysisRecord,
    ThreatAssessment,
)
from app.persistence.orm import (
    IntentRow,
    PaymentRow,
    PayPalWebhookEventRow,
    SecurityEventRow,
    ThreatAnalysisRow,
    TransactionRow,
)

_PAYMENT_UPDATE_FIELDS = frozenset(
    {
        "paypal_order_id",
        "approval_url",
        "paypal_capture_id",
        "paypal_status",
        "approved_by",
        "approved_at",
        "buyer_approved_at",
        "completed_at",
        "failure_reason",
    }
)


def _payment_from_row(row: PaymentRow) -> Payment:
    return Payment(
        payment_id=UUID(row.payment_id),
        transaction_id=UUID(row.transaction_id),
        intent_id=UUID(row.intent_id),
        user_id=row.user_id,
        merchant_id=row.merchant_id,
        product_category=row.product_category,
        amount=money_from_storage(row.amount),
        currency=row.currency,
        state=PaymentState(row.state),
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        paypal_order_id=row.paypal_order_id,
        approval_url=row.approval_url,
        paypal_capture_id=row.paypal_capture_id,
        paypal_status=row.paypal_status,
        approved_by=row.approved_by,
        approved_at=row.approved_at,
        buyer_approved_at=row.buyer_approved_at,
        completed_at=row.completed_at,
        failure_reason=row.failure_reason,
    )


class SqlAlchemyIntentRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, intent: PurchaseIntent) -> None:
        self._session.add(
            IntentRow(
                intent_id=str(intent.intent_id),
                user_id=intent.user_id,
                purpose=intent.purpose,
                merchant_id=intent.merchant_id,
                product_category=intent.product_category,
                max_amount=money_to_storage(intent.max_amount),
                currency=intent.currency,
                max_quantity=intent.max_quantity,
                require_approval=intent.require_approval,
                created_at=intent.created_at,
                expires_at=intent.expires_at,
                fingerprint=intent.fingerprint,
            )
        )

    def get(self, intent_id: UUID) -> PurchaseIntent | None:
        row = self._session.get(IntentRow, str(intent_id))
        if row is None:
            return None
        return PurchaseIntent(
            intent_id=UUID(row.intent_id),
            user_id=row.user_id,
            purpose=row.purpose,
            merchant_id=row.merchant_id,
            product_category=row.product_category,
            max_amount=money_from_storage(row.max_amount),
            currency=row.currency,
            max_quantity=row.max_quantity,
            require_approval=row.require_approval,
            created_at=row.created_at,
            expires_at=row.expires_at,
            fingerprint=row.fingerprint,
        )


class SqlAlchemyTransactionRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, record: TransactionRecord) -> None:
        decision = record.decision
        request = record.request
        self._session.add(
            TransactionRow(
                transaction_id=str(decision.transaction_id),
                request_id=request.request_id,
                user_id=request.user_id,
                intent_id=str(request.intent_id),
                merchant_id=request.merchant_id,
                product_category=request.product_category,
                amount=money_to_storage(request.amount),
                currency=request.currency,
                quantity=request.quantity,
                decision_id=str(decision.decision_id),
                decision=decision.decision.value,
                reason_codes=[code.value for code in decision.reason_codes],
                explanation=decision.explanation,
                risk_level=decision.risk_level.value,
                evaluated_at=decision.evaluated_at,
            )
        )

    def get(self, transaction_id: UUID) -> TransactionRecord | None:
        row = self._session.get(TransactionRow, str(transaction_id))
        if row is None:
            return None

        decision = PaymentDecision(
            decision_id=UUID(row.decision_id),
            transaction_id=UUID(row.transaction_id),
            intent_id=UUID(row.intent_id),
            decision=Decision(row.decision),
            reason_codes=tuple(ReasonCode(code) for code in row.reason_codes),
            explanation=row.explanation,
            evaluated_at=row.evaluated_at,
            risk_level=RiskLevel(row.risk_level),
        )
        request = TransactionRequest(
            user_id=row.user_id,
            intent_id=UUID(row.intent_id),
            merchant_id=row.merchant_id,
            product_category=row.product_category,
            amount=money_from_storage(row.amount),
            currency=row.currency,
            quantity=row.quantity,
            request_id=row.request_id,
        )
        return TransactionRecord(request=request, decision=decision)


class SqlAlchemyThreatAnalysisRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, record: ThreatAnalysisRecord) -> None:
        assessment = record.assessment
        self._session.add(
            ThreatAnalysisRow(
                analysis_id=str(record.analysis_id),
                transaction_id=str(record.transaction_id),
                analysis_status=assessment.analysis_status.value,
                provider_status=record.provider_status.value,
                threat_level=assessment.threat_level.value,
                risk_score=assessment.risk_score,
                detected_threats=[
                    {
                        "category": threat.category.value,
                        "severity": threat.severity.value,
                        "evidence": threat.evidence,
                    }
                    for threat in assessment.detected_threats
                ],
                evidence=list(assessment.evidence),
                suspicious_instructions=list(assessment.suspicious_instructions),
                intent_alignment=assessment.intent_alignment.value,
                explanation=assessment.explanation,
                recommended_handling=assessment.recommended_handling,
                model_name=assessment.model_name,
                analyzed_at=assessment.analyzed_at,
            )
        )

    def get_latest(self, transaction_id: UUID) -> ThreatAnalysisRecord | None:
        statement = (
            select(ThreatAnalysisRow)
            .where(ThreatAnalysisRow.transaction_id == str(transaction_id))
            .order_by(ThreatAnalysisRow.sequence.desc())
            .limit(1)
        )
        row = self._session.scalars(statement).first()
        if row is None:
            return None

        assessment = ThreatAssessment(
            analysis_status=AnalysisStatus(row.analysis_status),
            threat_level=ThreatLevel(row.threat_level),
            risk_score=row.risk_score,
            detected_threats=tuple(
                DetectedThreat(
                    category=ThreatCategory(threat["category"]),
                    severity=ThreatSeverity(threat["severity"]),
                    evidence=threat["evidence"],
                )
                for threat in row.detected_threats
            ),
            evidence=tuple(row.evidence),
            suspicious_instructions=tuple(row.suspicious_instructions),
            intent_alignment=IntentAlignment(row.intent_alignment),
            explanation=row.explanation,
            recommended_handling=row.recommended_handling,
            model_name=row.model_name,
            analyzed_at=row.analyzed_at,
        )
        return ThreatAnalysisRecord(
            analysis_id=UUID(row.analysis_id),
            transaction_id=UUID(row.transaction_id),
            assessment=assessment,
            provider_status=ProviderStatus(row.provider_status),
        )


class SqlAlchemyPaymentRepository:
    """Conditional state transitions guarded by state and version.

    ``version`` is incremented on every write. A caller that read an older
    version cannot overwrite a newer state, which makes duplicate/concurrent
    capture claims fail rather than execute twice.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, payment: Payment) -> None:
        self._session.add(
            PaymentRow(
                payment_id=str(payment.payment_id),
                transaction_id=str(payment.transaction_id),
                intent_id=str(payment.intent_id),
                user_id=payment.user_id,
                merchant_id=payment.merchant_id,
                product_category=payment.product_category,
                amount=money_to_storage(payment.amount),
                currency=payment.currency,
                state=payment.state.value,
                version=payment.version,
                paypal_order_id=payment.paypal_order_id,
                approval_url=payment.approval_url,
                paypal_capture_id=payment.paypal_capture_id,
                paypal_status=payment.paypal_status,
                approved_by=payment.approved_by,
                approved_at=payment.approved_at,
                buyer_approved_at=payment.buyer_approved_at,
                completed_at=payment.completed_at,
                failure_reason=payment.failure_reason,
                created_at=payment.created_at,
                updated_at=payment.updated_at,
            )
        )

    def get(self, payment_id: UUID) -> Payment | None:
        row = self._session.get(PaymentRow, str(payment_id))
        return _payment_from_row(row) if row is not None else None

    def get_by_transaction(self, transaction_id: UUID) -> Payment | None:
        statement = select(PaymentRow).where(
            PaymentRow.transaction_id == str(transaction_id)
        )
        row = self._session.scalars(statement).first()
        return _payment_from_row(row) if row is not None else None

    def get_by_paypal_order(self, paypal_order_id: str) -> Payment | None:
        statement = select(PaymentRow).where(
            PaymentRow.paypal_order_id == paypal_order_id
        )
        row = self._session.scalars(statement).first()
        return _payment_from_row(row) if row is not None else None

    def transition(
        self,
        payment_id: UUID,
        *,
        expected_states: frozenset[PaymentState],
        new_state: PaymentState,
        expected_version: int | None,
        updated_at,
        **fields: object,
    ) -> Payment | None:
        for state in expected_states:
            assert_transition(state, new_state)
        self._validate_fields(fields)

        statement = (
            update(PaymentRow)
            .where(PaymentRow.payment_id == str(payment_id))
            .where(
                PaymentRow.state.in_([state.value for state in expected_states])
            )
        )
        if expected_version is not None:
            statement = statement.where(PaymentRow.version == expected_version)

        values: dict[str, object] = {
            "state": new_state.value,
            "version": PaymentRow.version + 1,
            "updated_at": updated_at,
        }
        values.update(fields)
        result = self._session.execute(statement.values(**values))
        if result.rowcount != 1:
            return None

        self._session.flush()
        row = self._session.get(PaymentRow, str(payment_id))
        return _payment_from_row(row) if row is not None else None

    def update_fields(
        self,
        payment_id: UUID,
        *,
        expected_state: PaymentState,
        expected_version: int | None,
        updated_at,
        **fields: object,
    ) -> Payment | None:
        self._validate_fields(fields)
        statement = (
            update(PaymentRow)
            .where(PaymentRow.payment_id == str(payment_id))
            .where(PaymentRow.state == expected_state.value)
        )
        if expected_version is not None:
            statement = statement.where(PaymentRow.version == expected_version)

        values: dict[str, object] = {
            "version": PaymentRow.version + 1,
            "updated_at": updated_at,
        }
        values.update(fields)
        result = self._session.execute(statement.values(**values))
        if result.rowcount != 1:
            return None

        self._session.flush()
        row = self._session.get(PaymentRow, str(payment_id))
        return _payment_from_row(row) if row is not None else None

    @staticmethod
    def _validate_fields(fields: dict[str, object]) -> None:
        unknown = set(fields) - _PAYMENT_UPDATE_FIELDS
        if unknown:
            raise ValueError(
                "unsupported payment update fields: " + ", ".join(sorted(unknown))
            )


class SqlAlchemyWebhookEventRepository:
    """Deduplicating webhook event store keyed by PayPal event ID."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def try_add(self, record: WebhookEventRecord) -> bool:
        statement = (
            sqlite_insert(PayPalWebhookEventRow)
            .values(
                event_id=record.event_id,
                event_type=record.event_type,
                paypal_order_id=record.paypal_order_id,
                capture_id=record.capture_id,
                verification_status=record.verification_status.value,
                outcome=record.outcome,
                received_at=record.received_at,
            )
            .on_conflict_do_nothing(
                index_elements=[PayPalWebhookEventRow.event_id]
            )
        )
        result = self._session.execute(statement)
        return result.rowcount == 1

    def mark_outcome(self, event_id: str, outcome: str) -> None:
        self._session.execute(
            update(PayPalWebhookEventRow)
            .where(PayPalWebhookEventRow.event_id == event_id)
            .values(outcome=outcome)
        )


class SqlAlchemySecurityEventRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, event: SecurityEvent) -> None:
        self._session.add(
            SecurityEventRow(
                event_id=str(event.event_id),
                transaction_id=(
                    str(event.transaction_id) if event.transaction_id else None
                ),
                event_type=event.event_type.value,
                decision=event.decision.value if event.decision else None,
                reason_codes=[code.value for code in event.reason_codes],
                timestamp=event.timestamp,
            )
        )

    def list_recent(
        self,
        *,
        limit: int,
        event_type: EventType | None = None,
        decision: Decision | None = None,
    ) -> list[SecurityEvent]:
        statement = select(SecurityEventRow)
        if event_type is not None:
            statement = statement.where(
                SecurityEventRow.event_type == event_type.value
            )
        if decision is not None:
            statement = statement.where(SecurityEventRow.decision == decision.value)
        statement = statement.order_by(
            SecurityEventRow.timestamp.desc(),
            SecurityEventRow.sequence.desc(),
        ).limit(limit)

        rows = self._session.scalars(statement).all()
        return [
            SecurityEvent(
                event_id=UUID(row.event_id),
                transaction_id=(
                    UUID(row.transaction_id) if row.transaction_id else None
                ),
                event_type=EventType(row.event_type),
                decision=Decision(row.decision) if row.decision else None,
                reason_codes=tuple(ReasonCode(code) for code in row.reason_codes),
                timestamp=row.timestamp,
            )
            for row in rows
        ]


class SqlAlchemyUnitOfWork:
    def __init__(self, session: Session) -> None:
        self._session = session

    def flush(self) -> None:
        self._session.flush()

    def commit(self) -> None:
        self._session.commit()

    def rollback(self) -> None:
        self._session.rollback()
