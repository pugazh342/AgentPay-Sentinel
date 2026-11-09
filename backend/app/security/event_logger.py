"""Security event audit logging."""

from __future__ import annotations

import logging
from uuid import uuid4

from app.domain.clock import Clock
from app.domain.entities import PaymentDecision, PurchaseIntent, SecurityEvent
from app.domain.enums import EventType, ReasonCode
from app.domain.ports import SecurityEventRepository


class SecurityEventLogger:
    """Persist an audit event and emit a structured, non-sensitive log line.

    Deliberately excluded from events and logs: HMAC secret, credentials,
    purpose text, user/merchant identifiers and any other unnecessary personal
    data.
    """

    def __init__(
        self,
        repository: SecurityEventRepository,
        clock: Clock,
        logger: logging.Logger | None = None,
    ) -> None:
        self._repository = repository
        self._clock = clock
        self._logger = logger or logging.getLogger("agentpay.security")

    def _record(
        self,
        *,
        transaction_id,
        event_type: EventType,
        decision,
        reason_codes: tuple[ReasonCode, ...],
    ) -> SecurityEvent:
        event = SecurityEvent(
            event_id=uuid4(),
            transaction_id=transaction_id,
            event_type=event_type,
            decision=decision,
            reason_codes=reason_codes,
            timestamp=self._clock.now(),
        )
        self._repository.add(event)
        self._logger.info(
            "security_event",
            extra={
                "event_id": str(event.event_id),
                "event_type": event.event_type.value,
                "transaction_id": (
                    str(event.transaction_id) if event.transaction_id else None
                ),
                "decision": event.decision.value if event.decision else None,
                "reason_codes": [code.value for code in event.reason_codes],
            },
        )
        return event

    def record_intent_created(self, intent: PurchaseIntent) -> SecurityEvent:
        return self._record(
            transaction_id=None,
            event_type=EventType.INTENT_CREATED,
            decision=None,
            reason_codes=(),
        )

    def record_transaction_evaluated(
        self, decision: PaymentDecision
    ) -> SecurityEvent:
        return self._record(
            transaction_id=decision.transaction_id,
            event_type=EventType.TRANSACTION_EVALUATED,
            decision=decision.decision,
            reason_codes=decision.reason_codes,
        )
