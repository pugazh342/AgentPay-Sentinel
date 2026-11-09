"""Threat-analysis engine.

The engine maps provider outcomes to safe, validated advisory assessments and
attaches trusted metadata (configured model name and server time). It has no
authorization capability.
"""

from __future__ import annotations

import logging
from datetime import datetime
from uuid import UUID

from app.domain.clock import Clock
from app.domain.entities import PurchaseIntent, TransactionRequest
from app.domain.enums import (
    AnalysisStatus,
    IntentAlignment,
    ProviderStatus,
    ThreatLevel,
)
from app.domain.ports import ThreatAnalysisProvider
from app.domain.threat import (
    ThreatAnalysisContext,
    ThreatAnalysisInput,
    ThreatAnalysisResult,
    ThreatAssessment,
    ThreatProviderResult,
)
from app.domain.time import ensure_utc

logger = logging.getLogger("agentpay.ai")


def build_analysis_input(
    *,
    transaction_id: UUID,
    request: TransactionRequest,
    intent: PurchaseIntent | None,
    context: ThreatAnalysisContext,
) -> ThreatAnalysisInput:
    """Build a bounded input from trusted transaction data and untrusted text."""

    purpose = intent.purpose if intent is not None else "(intent unavailable)"
    authorized_category = (
        intent.product_category if intent is not None else request.product_category
    )
    return ThreatAnalysisInput(
        transaction_id=transaction_id,
        purpose=purpose,
        authorized_category=authorized_category,
        merchant_id=request.merchant_id,
        amount=request.amount,
        currency=request.currency,
        quantity=request.quantity,
        product_title=context.product_title,
        product_description=context.product_description,
        merchant_name=context.merchant_name,
        agent_reasoning=context.agent_reasoning,
        transaction_context=context.transaction_context,
    )


def build_unavailable_result(
    *,
    provider_status: ProviderStatus,
    model_name: str,
    now: datetime,
) -> ThreatAnalysisResult:
    """Conservative result used whenever no clean analysis exists."""

    status = (
        AnalysisStatus.INVALID_RESPONSE
        if provider_status is ProviderStatus.INVALID_RESPONSE
        else AnalysisStatus.UNAVAILABLE
    )
    assessment = ThreatAssessment(
        analysis_status=status,
        threat_level=ThreatLevel.HIGH,
        risk_score=100,
        detected_threats=(),
        evidence=(),
        suspicious_instructions=(),
        intent_alignment=IntentAlignment.UNCLEAR,
        explanation=(
            "AI threat analysis did not complete successfully. The absence of a "
            "clean analysis is not evidence that the request is safe."
        ),
        recommended_handling="HUMAN_REVIEW",
        model_name=model_name,
        analyzed_at=ensure_utc(now),
    )
    return ThreatAnalysisResult(
        assessment=assessment,
        provider_status=provider_status,
    )


class ThreatAnalysisEngine:
    """Runs the injected provider and produces a safe advisory result."""

    def __init__(
        self,
        *,
        provider: ThreatAnalysisProvider,
        clock: Clock,
        model_name: str | None = None,
    ) -> None:
        self._provider = provider
        self._clock = clock
        self._model_name = model_name or provider.model_name

    def analyze(self, analysis_input: ThreatAnalysisInput) -> ThreatAnalysisResult:
        try:
            provider_result = self._provider.analyze(analysis_input)
        except Exception as exc:  # never trust provider internals to be safe
            logger.warning(
                "threat_provider_unhandled_error",
                extra={"error_type": type(exc).__name__},
            )
            return build_unavailable_result(
                provider_status=ProviderStatus.PROVIDER_ERROR,
                model_name=self._model_name,
                now=self._clock.now(),
            )

        if (
            provider_result.provider_status is not ProviderStatus.OK
            or provider_result.payload is None
        ):
            return build_unavailable_result(
                provider_status=provider_result.provider_status,
                model_name=self._model_name,
                now=self._clock.now(),
            )

        payload = provider_result.payload
        assessment = ThreatAssessment(
            analysis_status=AnalysisStatus.COMPLETED,
            threat_level=payload.threat_level,
            risk_score=payload.risk_score,
            detected_threats=payload.detected_threats,
            evidence=payload.evidence,
            suspicious_instructions=payload.suspicious_instructions,
            intent_alignment=payload.intent_alignment,
            explanation=payload.explanation,
            recommended_handling=payload.recommended_handling,
            model_name=self._model_name,
            analyzed_at=self._clock.now(),
        )
        return ThreatAnalysisResult(
            assessment=assessment,
            provider_status=ProviderStatus.OK,
        )


def build_unconfigured_provider_result() -> ThreatProviderResult:
    """Fallback used only when no provider/engine was wired."""

    return ThreatProviderResult(ProviderStatus.NOT_CONFIGURED)


__all__ = [
    "ThreatAnalysisEngine",
    "build_analysis_input",
    "build_unavailable_result",
    "build_unconfigured_provider_result",
]
