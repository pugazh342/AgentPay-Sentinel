"""Intent creation service."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from decimal import Decimal
from uuid import UUID, uuid4

from app.domain.clock import Clock
from app.domain.entities import PurchaseIntent
from app.domain.errors import ValidationFailure
from app.domain.ports import IntentRepository, UnitOfWork
from app.domain.time import ensure_utc
from app.security.event_logger import SecurityEventLogger
from app.security.fingerprint import FingerprintService


@dataclass(frozen=True, slots=True)
class CreateIntentCommand:
    user_id: str
    purpose: str
    merchant_id: str
    product_category: str
    max_amount: Decimal
    currency: str
    max_quantity: int
    require_approval: bool
    expires_at: datetime


class IntentService:
    """Creates immutable purchase intents and stamps their integrity fingerprint."""

    def __init__(
        self,
        intents: IntentRepository,
        fingerprints: FingerprintService,
        clock: Clock,
        events: SecurityEventLogger,
        unit_of_work: UnitOfWork,
    ) -> None:
        self._intents = intents
        self._fingerprints = fingerprints
        self._clock = clock
        self._events = events
        self._unit_of_work = unit_of_work

    def create(self, command: CreateIntentCommand) -> PurchaseIntent:
        now = self._clock.now()
        try:
            expires_at = ensure_utc(command.expires_at)
        except ValueError as exc:
            raise ValidationFailure(str(exc)) from exc
        if expires_at <= now:
            raise ValidationFailure("expires_at must be in the future")

        try:
            intent = PurchaseIntent(
                intent_id=uuid4(),
                user_id=command.user_id,
                purpose=command.purpose,
                merchant_id=command.merchant_id,
                product_category=command.product_category,
                max_amount=command.max_amount,
                currency=command.currency,
                max_quantity=command.max_quantity,
                require_approval=command.require_approval,
                created_at=now,
                expires_at=expires_at,
            )
            # Fingerprinting covers the fields above and excludes the
            # fingerprint itself. The entity is frozen, so stamping uses a
            # functional replacement before persistence.
            fingerprint = self._fingerprints.fingerprint_intent(intent)
            intent = replace(intent, fingerprint=fingerprint)
        except ValueError as exc:
            raise ValidationFailure(str(exc)) from exc

        self._intents.add(intent)
        self._events.record_intent_created(intent)
        self._unit_of_work.commit()
        return intent

    def get(self, intent_id: UUID) -> PurchaseIntent | None:
        return self._intents.get(intent_id)
