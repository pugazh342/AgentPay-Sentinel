"""Standalone threat-analysis use case.

Standalone analysis never mutates the persisted transaction decision. It only
creates an advisory analysis record linked to the transaction.
"""

from __future__ import annotations

from uuid import UUID, uuid4

from app.application.threat_engine import ThreatAnalysisEngine, build_analysis_input
from app.domain.errors import NotFoundFailure
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


class ThreatAnalysisService:
    def __init__(
        self,
        *,
        intents: IntentRepository,
        transactions: TransactionRepository,
        analyses: ThreatAnalysisRepository,
        engine: ThreatAnalysisEngine,
        unit_of_work: UnitOfWork,
    ) -> None:
        self._intents = intents
        self._transactions = transactions
        self._analyses = analyses
        self._engine = engine
        self._unit_of_work = unit_of_work

    def analyze_transaction(
        self,
        transaction_id: UUID,
        context: ThreatAnalysisContext,
    ) -> ThreatAnalysisRecord:
        record = self._transactions.get(transaction_id)
        if record is None:
            raise NotFoundFailure("Transaction not found.")

        intent = self._intents.get(record.request.intent_id)
        analysis_input = build_analysis_input(
            transaction_id=record.decision.transaction_id,
            request=record.request,
            intent=intent,
            context=context,
        )
        result: ThreatAnalysisResult = self._engine.analyze(analysis_input)

        analysis = ThreatAnalysisRecord(
            analysis_id=uuid4(),
            transaction_id=record.decision.transaction_id,
            assessment=result.assessment,
            provider_status=result.provider_status,
        )
        self._analyses.add(analysis)
        self._unit_of_work.commit()
        return analysis

    def get_latest(self, transaction_id: UUID) -> ThreatAnalysisRecord | None:
        return self._analyses.get_latest(transaction_id)


__all__ = ["ThreatAnalysisService"]
