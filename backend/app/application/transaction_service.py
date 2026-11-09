"""Transaction evaluation service."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from app.application.threat_engine import (
    ThreatAnalysisEngine,
    build_analysis_input,
    build_unavailable_result,
)
from app.domain.clock import Clock
from app.domain.entities import PaymentDecision, TransactionRecord, TransactionRequest
from app.domain.enums import ProviderStatus, ReasonCode, RiskLevel
from app.domain.policy import evaluate_policy, risk_level_for
from app.domain.ports import (
    IntentRepository,
    ThreatAnalysisRepository,
    TransactionRepository,
    UnitOfWork,
)
from app.domain.threat import (
    ThreatAnalysisContext,
    ThreatAnalysisRecord,
    ThreatAnalysisResult,
)
from app.domain.threat_reconciliation import reconcile_with_threat_analysis
from app.security.event_logger import SecurityEventLogger
from app.security.fingerprint import FingerprintService


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """Transaction decision plus an optional advisory analysis record."""

    decision: PaymentDecision
    analysis: ThreatAnalysisRecord | None = None


class TransactionService:
    """Evaluates requests against immutable intents and records an audit trail.

    The intent is only read. Evaluation never updates purchase intent rows.
    """

    def __init__(
        self,
        intents: IntentRepository,
        transactions: TransactionRepository,
        fingerprints: FingerprintService,
        clock: Clock,
        events: SecurityEventLogger,
        unit_of_work: UnitOfWork,
        threat_engine: ThreatAnalysisEngine | None = None,
        analyses: ThreatAnalysisRepository | None = None,
    ) -> None:
        self._intents = intents
        self._transactions = transactions
        self._fingerprints = fingerprints
        self._clock = clock
        self._events = events
        self._unit_of_work = unit_of_work
        self._threat_engine = threat_engine
        self._analyses = analyses

    def evaluate(self, request: TransactionRequest) -> PaymentDecision:
        intent = self._intents.get(request.intent_id)
        now = self._clock.now()

        outcome = evaluate_policy(
            request,
            intent,
            verifier=self._fingerprints,
            now=now,
        )

        decision = PaymentDecision(
            decision_id=uuid4(),
            transaction_id=uuid4(),
            intent_id=request.intent_id,
            decision=outcome.decision,
            reason_codes=outcome.reason_codes,
            explanation=outcome.explanation,
            evaluated_at=now,
            risk_level=risk_level_for(outcome.decision),
        )

        # Persist the evaluated transaction and its audit event atomically.
        # A failure here aborts the evaluation instead of returning a decision
        # without an audit trail.
        self._transactions.add(TransactionRecord(request=request, decision=decision))
        self._events.record_transaction_evaluated(decision)
        self._unit_of_work.commit()
        return decision

    def evaluate_with_analysis(
        self,
        request: TransactionRequest,
        context: ThreatAnalysisContext,
    ) -> EvaluationResult:
        """Evaluate deterministically, then reconcile an advisory AI assessment.

        The AI is called only when the caller explicitly supplies context. The
        deterministic policy has already produced its outcome before any model
        output is considered.
        """

        intent = self._intents.get(request.intent_id)
        now = self._clock.now()

        outcome = evaluate_policy(
            request,
            intent,
            verifier=self._fingerprints,
            now=now,
        )

        provisional = PaymentDecision(
            decision_id=uuid4(),
            transaction_id=uuid4(),
            intent_id=request.intent_id,
            decision=outcome.decision,
            reason_codes=outcome.reason_codes,
            explanation=outcome.explanation,
            evaluated_at=now,
            risk_level=risk_level_for(outcome.decision),
        )

        if self._threat_engine is None:
            analysis_result: ThreatAnalysisResult = build_unavailable_result(
                provider_status=ProviderStatus.NOT_CONFIGURED,
                model_name="unconfigured",
                now=now,
            )
        else:
            analysis_input = build_analysis_input(
                transaction_id=provisional.transaction_id,
                request=request,
                intent=intent,
                context=context,
            )
            analysis_result = self._threat_engine.analyze(analysis_input)

        reconciled = reconcile_with_threat_analysis(outcome, analysis_result)
        final_decision = PaymentDecision(
            decision_id=provisional.decision_id,
            transaction_id=provisional.transaction_id,
            intent_id=request.intent_id,
            decision=reconciled.decision,
            reason_codes=reconciled.reason_codes,
            explanation=reconciled.explanation,
            evaluated_at=now,
            risk_level=(
                RiskLevel.HIGH
                if ReasonCode.AI_THREAT_ESCALATION in reconciled.reason_codes
                else risk_level_for(reconciled.decision)
            ),
        )

        analysis = ThreatAnalysisRecord(
            analysis_id=uuid4(),
            transaction_id=final_decision.transaction_id,
            assessment=analysis_result.assessment,
            provider_status=analysis_result.provider_status,
        )

        self._transactions.add(
            TransactionRecord(request=request, decision=final_decision)
        )
        # The analysis row references the transaction row. Flush the parent
        # first so the foreign-key constraint is satisfiable within the same
        # atomic unit of work.
        self._unit_of_work.flush()
        if self._analyses is not None:
            self._analyses.add(analysis)
        self._events.record_transaction_evaluated(final_decision)
        self._unit_of_work.commit()
        return EvaluationResult(decision=final_decision, analysis=analysis)

    def get(self, transaction_id: UUID) -> TransactionRecord | None:
        return self._transactions.get(transaction_id)


__all__ = ["EvaluationResult", "TransactionService"]
