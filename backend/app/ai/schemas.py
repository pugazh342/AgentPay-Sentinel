"""Pydantic validation for structured Gemini output.

The model returns JSON, but valid JSON is not trusted on its own. Every field
is validated against a closed vocabulary and bounded length, and each detected
threat must carry concrete evidence.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

from app.domain.enums import (
    IntentAlignment,
    ThreatCategory,
    ThreatLevel,
    ThreatSeverity,
)
from app.domain.threat import (
    MAX_EVIDENCE_CHARS,
    MAX_EVIDENCE_ITEMS,
    MAX_EXPLANATION_CHARS,
    MAX_HANDLING_CHARS,
    MAX_SUSPICIOUS_INSTRUCTIONS,
    MAX_THREATS,
    DetectedThreat,
    ThreatAssessmentPayload,
)

EvidenceText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=MAX_EVIDENCE_CHARS,
    ),
]
InstructionText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=MAX_EVIDENCE_CHARS,
    ),
]


class DetectedThreatModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: ThreatCategory
    severity: ThreatSeverity
    evidence: EvidenceText

    def to_domain(self) -> DetectedThreat:
        return DetectedThreat(
            category=self.category,
            severity=self.severity,
            evidence=self.evidence,
        )


class GeminiThreatResponse(BaseModel):
    """Exact schema requested from Gemini and validated before acceptance."""

    model_config = ConfigDict(extra="forbid")

    threat_level: ThreatLevel
    risk_score: int = Field(ge=0, le=100)
    detected_threats: list[DetectedThreatModel] = Field(
        default_factory=list,
        max_length=MAX_THREATS,
    )
    evidence: list[EvidenceText] = Field(
        default_factory=list,
        max_length=MAX_EVIDENCE_ITEMS,
    )
    suspicious_instructions: list[InstructionText] = Field(
        default_factory=list,
        max_length=MAX_SUSPICIOUS_INSTRUCTIONS,
    )
    intent_alignment: IntentAlignment
    explanation: str = Field(
        min_length=1,
        max_length=MAX_EXPLANATION_CHARS,
    )
    recommended_handling: str = Field(
        min_length=1,
        max_length=MAX_HANDLING_CHARS,
        description="Advisory text only; never interpreted as an authorization action.",
    )

    @model_validator(mode="after")
    def enforce_evidence_and_consistency(self) -> GeminiThreatResponse:
        if self.detected_threats and not self.evidence:
            raise ValueError(
                "evidence is required when detected_threats is not empty"
            )

        high_severities = {ThreatSeverity.HIGH, ThreatSeverity.CRITICAL}
        if self.threat_level is ThreatLevel.LOW and any(
            threat.severity in high_severities
            for threat in self.detected_threats
        ):
            raise ValueError(
                "threat_level LOW cannot contain HIGH or CRITICAL findings"
            )

        if self.threat_level in {ThreatLevel.HIGH, ThreatLevel.CRITICAL}:
            if not self.evidence:
                raise ValueError(
                    "evidence is required for HIGH or CRITICAL threat levels"
                )

        normalized_explanation = self.explanation.strip()
        if not normalized_explanation:
            raise ValueError("explanation must not be blank")
        if normalized_explanation != self.explanation:
            object.__setattr__(self, "explanation", normalized_explanation)

        normalized_handling = self.recommended_handling.strip()
        if not normalized_handling:
            raise ValueError("recommended_handling must not be blank")
        if normalized_handling != self.recommended_handling:
            object.__setattr__(self, "recommended_handling", normalized_handling)

        return self

    def to_domain(self) -> ThreatAssessmentPayload:
        return ThreatAssessmentPayload(
            threat_level=self.threat_level,
            risk_score=self.risk_score,
            detected_threats=tuple(
                threat.to_domain() for threat in self.detected_threats
            ),
            evidence=tuple(self.evidence),
            suspicious_instructions=tuple(self.suspicious_instructions),
            intent_alignment=self.intent_alignment,
            explanation=self.explanation,
            recommended_handling=self.recommended_handling,
        )


__all__ = ["DetectedThreatModel", "GeminiThreatResponse"]
