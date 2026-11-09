"""API schemas for advisory threat analysis."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.domain.enums import (
    AnalysisStatus,
    IntentAlignment,
    ProviderStatus,
    ThreatCategory,
    ThreatLevel,
    ThreatSeverity,
)
from app.domain.threat import (
    MAX_AGENT_REASONING_CHARS,
    MAX_MERCHANT_NAME_CHARS,
    MAX_PRODUCT_DESCRIPTION_CHARS,
    MAX_PRODUCT_TITLE_CHARS,
    MAX_TRANSACTION_CONTEXT_CHARS,
    ThreatAnalysisContext,
    ThreatAnalysisRecord,
)

ProductTitle = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=MAX_PRODUCT_TITLE_CHARS,
    ),
]
ProductDescription = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=MAX_PRODUCT_DESCRIPTION_CHARS,
    ),
]
MerchantName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=MAX_MERCHANT_NAME_CHARS,
    ),
]
AgentReasoning = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=MAX_AGENT_REASONING_CHARS,
    ),
]
TransactionContext = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=MAX_TRANSACTION_CONTEXT_CHARS,
    ),
]


class AnalysisContextRequest(BaseModel):
    """Optional untrusted context for contextual threat analysis.

    Unknown fields are rejected. Every text field is bounded before it reaches
    the provider.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "product_title": "Trail running shoes",
                "product_description": "Lightweight neutral running shoes.",
                "merchant_name": "Example Shoes",
                "agent_reasoning": "Matches the requested footwear category.",
                "transaction_context": "One pair, within the authorized maximum.",
            }
        },
    )

    product_title: ProductTitle | None = Field(
        default=None,
        description="Proposed product title. Treated as untrusted data.",
    )
    product_description: ProductDescription | None = Field(
        default=None,
        description="Proposed product description. Treated as untrusted data.",
    )
    merchant_name: MerchantName | None = Field(
        default=None,
        description="Human-readable merchant name. Treated as untrusted data.",
    )
    agent_reasoning: AgentReasoning | None = Field(
        default=None,
        description="Agent-provided reasoning. Treated as untrusted data.",
    )
    transaction_context: TransactionContext | None = Field(
        default=None,
        description="Additional transaction context. Treated as untrusted data.",
    )

    def to_domain(self) -> ThreatAnalysisContext:
        return ThreatAnalysisContext(
            product_title=self.product_title,
            product_description=self.product_description,
            merchant_name=self.merchant_name,
            agent_reasoning=self.agent_reasoning,
            transaction_context=self.transaction_context,
        )


class ThreatFindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    category: ThreatCategory
    severity: ThreatSeverity
    evidence: str


class ThreatAnalysisResponse(BaseModel):
    """Advisory threat assessment. This is never a payment authorization."""

    analysis_id: UUID
    transaction_id: UUID
    analysis_status: AnalysisStatus = Field(
        description="COMPLETED only when a validated provider assessment exists."
    )
    provider_status: ProviderStatus = Field(
        description="Sanitized provider outcome recorded for audit."
    )
    threat_level: ThreatLevel
    risk_score: int = Field(
        ge=0,
        le=100,
        description="Descriptive only. Never used for authorization.",
    )
    detected_threats: list[ThreatFindingResponse]
    evidence: list[str]
    suspicious_instructions: list[str]
    intent_alignment: IntentAlignment
    explanation: str
    recommended_handling: str = Field(
        description="Advisory text only; never executed as a payment action."
    )
    model_name: str
    analyzed_at: datetime

    @classmethod
    def from_record(cls, record: ThreatAnalysisRecord) -> "ThreatAnalysisResponse":
        assessment = record.assessment
        return cls(
            analysis_id=record.analysis_id,
            transaction_id=record.transaction_id,
            analysis_status=assessment.analysis_status,
            provider_status=record.provider_status,
            threat_level=assessment.threat_level,
            risk_score=assessment.risk_score,
            detected_threats=[
                ThreatFindingResponse.model_validate(threat)
                for threat in assessment.detected_threats
            ],
            evidence=list(assessment.evidence),
            suspicious_instructions=list(assessment.suspicious_instructions),
            intent_alignment=assessment.intent_alignment,
            explanation=assessment.explanation,
            recommended_handling=assessment.recommended_handling,
            model_name=assessment.model_name,
            analyzed_at=assessment.analyzed_at,
        )


__all__ = [
    "AnalysisContextRequest",
    "ThreatAnalysisResponse",
    "ThreatFindingResponse",
]
