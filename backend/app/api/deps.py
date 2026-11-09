"""FastAPI dependencies."""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.application.intent_service import IntentService
from app.application.payment_service import PaymentService
from app.application.threat_analysis_service import ThreatAnalysisService
from app.application.threat_engine import ThreatAnalysisEngine
from app.application.transaction_service import TransactionService
from app.domain.clock import Clock
from app.domain.errors import SecurityConfigurationFailure
from app.domain.ports import PayPalGateway
from app.persistence.repositories import (
    SqlAlchemyIntentRepository,
    SqlAlchemyPaymentRepository,
    SqlAlchemySecurityEventRepository,
    SqlAlchemyThreatAnalysisRepository,
    SqlAlchemyTransactionRepository,
    SqlAlchemyUnitOfWork,
    SqlAlchemyWebhookEventRepository,
)
from app.security.event_logger import SecurityEventLogger
from app.security.fingerprint import FingerprintService


def get_session(request: Request) -> Iterator[Session]:
    database = request.app.state.db
    with database.session() as session:
        yield session


def get_clock(request: Request) -> Clock:
    return request.app.state.clock


def get_fingerprints(request: Request) -> FingerprintService:
    return request.app.state.fingerprints


def get_threat_engine(request: Request) -> ThreatAnalysisEngine:
    return request.app.state.threat_engine


def require_security_configuration(request: Request) -> None:
    """Fail-closed guard for every authorization-related endpoint."""

    fingerprints: FingerprintService = request.app.state.fingerprints
    if not fingerprints.configured:
        raise SecurityConfigurationFailure(
            "Security configuration is invalid; authorization operations are disabled."
        )


def _event_logger(request: Request, session: Session) -> SecurityEventLogger:
    return SecurityEventLogger(
        repository=SqlAlchemySecurityEventRepository(session),
        clock=request.app.state.clock,
    )


def get_intent_service(
    request: Request,
    session: Session = Depends(get_session),
) -> IntentService:
    return IntentService(
        intents=SqlAlchemyIntentRepository(session),
        fingerprints=request.app.state.fingerprints,
        clock=request.app.state.clock,
        events=_event_logger(request, session),
        unit_of_work=SqlAlchemyUnitOfWork(session),
    )


def get_transaction_service(
    request: Request,
    session: Session = Depends(get_session),
) -> TransactionService:
    return TransactionService(
        intents=SqlAlchemyIntentRepository(session),
        transactions=SqlAlchemyTransactionRepository(session),
        fingerprints=request.app.state.fingerprints,
        clock=request.app.state.clock,
        events=_event_logger(request, session),
        unit_of_work=SqlAlchemyUnitOfWork(session),
        threat_engine=request.app.state.threat_engine,
        analyses=SqlAlchemyThreatAnalysisRepository(session),
    )


def get_paypal_gateway(request: Request) -> PayPalGateway:
    return request.app.state.paypal_gateway


def get_payment_service(
    request: Request,
    session: Session = Depends(get_session),
) -> PaymentService:
    return PaymentService(
        intents=SqlAlchemyIntentRepository(session),
        transactions=SqlAlchemyTransactionRepository(session),
        payments=SqlAlchemyPaymentRepository(session),
        webhook_events=SqlAlchemyWebhookEventRepository(session),
        fingerprints=request.app.state.fingerprints,
        clock=request.app.state.clock,
        gateway=request.app.state.paypal_gateway,
        unit_of_work=SqlAlchemyUnitOfWork(session),
    )


def get_threat_analysis_service(
    request: Request,
    session: Session = Depends(get_session),
) -> ThreatAnalysisService:
    return ThreatAnalysisService(
        intents=SqlAlchemyIntentRepository(session),
        transactions=SqlAlchemyTransactionRepository(session),
        analyses=SqlAlchemyThreatAnalysisRepository(session),
        engine=request.app.state.threat_engine,
        unit_of_work=SqlAlchemyUnitOfWork(session),
    )


def get_security_event_repository(
    session: Session = Depends(get_session),
) -> SqlAlchemySecurityEventRepository:
    return SqlAlchemySecurityEventRepository(session)
