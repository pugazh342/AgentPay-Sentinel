"""Pure reconciliation between deterministic policy and AI threat analysis.

The deterministic policy remains the authorization source of truth. AI output
may only preserve an outcome or raise an eligible outcome to human review.
"""

from __future__ import annotations

from app.domain.entities import PolicyOutcome
from app.domain.enums import (
    AnalysisStatus,
    Decision,
    IntentAlignment,
    ReasonCode,
    ThreatLevel,
    ThreatSeverity,
)
from app.domain.threat import ThreatAssessment, ThreatAnalysisResult

_HIGH_THREAT_LEVELS = frozenset({ThreatLevel.HIGH, ThreatLevel.CRITICAL})
_HIGH_THREAT_SEVERITIES = frozenset(
    {ThreatSeverity.HIGH, ThreatSeverity.CRITICAL}
)


def is_high_risk_assessment(assessment: ThreatAssessment) -> bool:
    """Return whether advisory signals justify human review.

    The model-generated risk score is deliberately ignored. Escalation is
    driven by closed-vocabulary threat levels/severities plus explicit signals
    that a request deviates from intent or contains suspicious instructions.
    """

    if assessment.threat_level in _HIGH_THREAT_LEVELS:
        return True
    if any(
        threat.severity in _HIGH_THREAT_SEVERITIES
        for threat in assessment.detected_threats
    ):
        return True
    if assessment.intent_alignment is IntentAlignment.DEVIATES:
        return True
    return bool(assessment.suspicious_instructions)


def _unavailable_review(outcome: PolicyOutcome) -> PolicyOutcome:
    if outcome.decision is Decision.REVIEW_REQUIRED:
        reason_codes = outcome.reason_codes + (
            ReasonCode.AI_ANALYSIS_UNAVAILABLE,
        )
        prefix = "The deterministic policy already requires human review. "
    else:
        reason_codes = (
            ReasonCode.ALL_CHECKS_PASSED,
            ReasonCode.AI_ANALYSIS_UNAVAILABLE,
        )
        prefix = (
            "Deterministic policy found the request eligible for approval, but "
        )

    return PolicyOutcome(
        decision=Decision.REVIEW_REQUIRED,
        reason_codes=reason_codes,
        explanation=(
            f"{prefix}AI threat analysis was unavailable or invalid. The absence "
            "of an analysis is not evidence that the request is safe, so human "
            "review is required. This does not authorize, capture or settle a "
            "payment."
        ),
    )


def reconcile_with_threat_analysis(
    outcome: PolicyOutcome,
    result: ThreatAnalysisResult,
) -> PolicyOutcome:
    """Reconcile a deterministic outcome with an advisory AI assessment.

    Guarantees:
    * ``BLOCK`` is always preserved unchanged.
    * ``REVIEW_REQUIRED`` is never downgraded.
    * ``ALLOW_FOR_APPROVAL`` can only be created by the deterministic policy.
    * An unavailable/invalid analysis never becomes a clean result.
    """

    # Hard deterministic blocks are final. The AI cannot soften or replace
    # their reason codes.
    if outcome.decision is Decision.BLOCK:
        return outcome

    assessment = result.assessment

    if assessment.analysis_status is not AnalysisStatus.COMPLETED:
        return _unavailable_review(outcome)

    # Deterministic review is already the safe terminal outcome. AI findings
    # remain available in the persisted analysis record.
    if outcome.decision is Decision.REVIEW_REQUIRED:
        return outcome

    # The only remaining deterministic outcome is ALLOW_FOR_APPROVAL. AI may
    # escalate it to human review, but never authorize anything.
    if is_high_risk_assessment(assessment):
        categories = sorted(
            {threat.category.value for threat in assessment.detected_threats}
        )
        detail = (
            f" Detected categories: {', '.join(categories)}."
            if categories
            else ""
        )
        return PolicyOutcome(
            decision=Decision.REVIEW_REQUIRED,
            reason_codes=(
                ReasonCode.ALL_CHECKS_PASSED,
                ReasonCode.AI_THREAT_ESCALATION,
            ),
            explanation=(
                "Deterministic policy found the request eligible for approval, "
                f"but contextual threat analysis reported high-risk indicators.{detail} "
                "Human review is required. This does not authorize, capture or "
                "settle a payment."
            ),
        )

    return outcome


__all__ = ["is_high_risk_assessment", "reconcile_with_threat_analysis"]
