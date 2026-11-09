"""Threat-analysis domain models.

Everything in this module is advisory. The AI never authorizes payments, and
none of these values are inputs to the deterministic policy engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID

from app.domain.enums import (
    AnalysisStatus,
    IntentAlignment,
    ProviderStatus,
    ThreatCategory,
    ThreatLevel,
    ThreatSeverity,
)
from app.domain.time import ensure_utc

# Input limits prevent prompt stuffing and oversized provider requests. The
# API schemas enforce the same bounds; these checks protect direct callers.
MAX_PURPOSE_CHARS = 500
MAX_CATEGORY_CHARS = 64
MAX_PRODUCT_TITLE_CHARS = 200
MAX_PRODUCT_DESCRIPTION_CHARS = 2_000
MAX_MERCHANT_NAME_CHARS = 200
MAX_MERCHANT_ID_CHARS = 64
MAX_AGENT_REASONING_CHARS = 2_000
MAX_TRANSACTION_CONTEXT_CHARS = 1_000
MAX_EVIDENCE_CHARS = 300
MAX_EXPLANATION_CHARS = 1_000
MAX_HANDLING_CHARS = 300
MAX_THREATS = 10
MAX_EVIDENCE_ITEMS = 10
MAX_SUSPICIOUS_INSTRUCTIONS = 10
MAX_PROMPT_CHARS = 12_000


def _optional_text(value: str | None, *, field: str, limit: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized:
        return None
    if len(normalized) > limit:
        raise ValueError(f"{field} must be at most {limit} characters")
    return normalized


@dataclass(frozen=True, slots=True)
class ThreatAnalysisContext:
    """Optional untrusted context supplied by the caller for analysis."""

    product_title: str | None = None
    product_description: str | None = None
    merchant_name: str | None = None
    agent_reasoning: str | None = None
    transaction_context: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "product_title",
            _optional_text(
                self.product_title,
                field="product_title",
                limit=MAX_PRODUCT_TITLE_CHARS,
            ),
        )
        object.__setattr__(
            self,
            "product_description",
            _optional_text(
                self.product_description,
                field="product_description",
                limit=MAX_PRODUCT_DESCRIPTION_CHARS,
            ),
        )
        object.__setattr__(
            self,
            "merchant_name",
            _optional_text(
                self.merchant_name,
                field="merchant_name",
                limit=MAX_MERCHANT_NAME_CHARS,
            ),
        )
        object.__setattr__(
            self,
            "agent_reasoning",
            _optional_text(
                self.agent_reasoning,
                field="agent_reasoning",
                limit=MAX_AGENT_REASONING_CHARS,
            ),
        )
        object.__setattr__(
            self,
            "transaction_context",
            _optional_text(
                self.transaction_context,
                field="transaction_context",
                limit=MAX_TRANSACTION_CONTEXT_CHARS,
            ),
        )


@dataclass(frozen=True, slots=True)
class ThreatAnalysisInput:
    """Bounded analysis input. All text is treated as untrusted data."""

    transaction_id: UUID
    purpose: str
    authorized_category: str
    merchant_id: str
    amount: Decimal
    currency: str
    quantity: int
    product_title: str | None = None
    product_description: str | None = None
    merchant_name: str | None = None
    agent_reasoning: str | None = None
    transaction_context: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.transaction_id, UUID):
            raise ValueError("transaction_id must be a UUID")
        for name, limit in (
            ("purpose", MAX_PURPOSE_CHARS),
            ("authorized_category", MAX_CATEGORY_CHARS),
            ("merchant_id", MAX_MERCHANT_ID_CHARS),
            ("currency", 3),
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
            if len(value) > limit:
                raise ValueError(f"{name} must be at most {limit} characters")
        for name, limit in (
            ("product_title", MAX_PRODUCT_TITLE_CHARS),
            ("product_description", MAX_PRODUCT_DESCRIPTION_CHARS),
            ("merchant_name", MAX_MERCHANT_NAME_CHARS),
            ("agent_reasoning", MAX_AGENT_REASONING_CHARS),
            ("transaction_context", MAX_TRANSACTION_CONTEXT_CHARS),
        ):
            object.__setattr__(
                self,
                name,
                _optional_text(getattr(self, name), field=name, limit=limit),
            )
        if not isinstance(self.amount, Decimal):
            raise ValueError("amount must be a Decimal")
        if not self.amount.is_finite() or self.amount <= 0:
            raise ValueError("amount must be a finite positive Decimal")
        if not isinstance(self.quantity, int) or isinstance(self.quantity, bool):
            raise ValueError("quantity must be an integer")
        if self.quantity < 1:
            raise ValueError("quantity must be at least 1")

    def to_untrusted_payload(self) -> dict[str, object]:
        """Serialize only analysis inputs for the provider prompt."""

        return {
            "transaction_id": str(self.transaction_id),
            "purchase_purpose": self.purpose,
            "authorized_product_category": self.authorized_category,
            "merchant_id": self.merchant_id,
            "amount": format(self.amount, "f"),
            "currency": self.currency,
            "quantity": self.quantity,
            "product_title": self.product_title,
            "product_description": self.product_description,
            "merchant_name": self.merchant_name,
            "agent_reasoning": self.agent_reasoning,
            "transaction_context": self.transaction_context,
        }


@dataclass(frozen=True, slots=True)
class DetectedThreat:
    category: ThreatCategory
    severity: ThreatSeverity
    evidence: str

    def __post_init__(self) -> None:
        if not isinstance(self.category, ThreatCategory):
            raise ValueError("category must be a ThreatCategory")
        if not isinstance(self.severity, ThreatSeverity):
            raise ValueError("severity must be a ThreatSeverity")
        if not isinstance(self.evidence, str) or not self.evidence.strip():
            raise ValueError("evidence must be a non-empty string")
        if len(self.evidence.strip()) > MAX_EVIDENCE_CHARS:
            raise ValueError("evidence is too long")
        object.__setattr__(self, "evidence", self.evidence.strip())


@dataclass(frozen=True, slots=True)
class ThreatAssessmentPayload:
    """Validated model output before trusted metadata is attached."""

    threat_level: ThreatLevel
    risk_score: int
    detected_threats: tuple[DetectedThreat, ...]
    evidence: tuple[str, ...]
    suspicious_instructions: tuple[str, ...]
    intent_alignment: IntentAlignment
    explanation: str
    recommended_handling: str

    def __post_init__(self) -> None:
        if not isinstance(self.threat_level, ThreatLevel):
            raise ValueError("threat_level must be a ThreatLevel")
        if not isinstance(self.risk_score, int) or isinstance(
            self.risk_score, bool
        ):
            raise ValueError("risk_score must be an integer")
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")
        if len(self.detected_threats) > MAX_THREATS:
            raise ValueError("too many detected threats")
        if len(self.evidence) > MAX_EVIDENCE_ITEMS:
            raise ValueError("too many evidence items")
        if len(self.suspicious_instructions) > MAX_SUSPICIOUS_INSTRUCTIONS:
            raise ValueError("too many suspicious instructions")
        if not isinstance(self.intent_alignment, IntentAlignment):
            raise ValueError("intent_alignment must be an IntentAlignment")
        for name, limit in (
            ("explanation", MAX_EXPLANATION_CHARS),
            ("recommended_handling", MAX_HANDLING_CHARS),
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
            if len(value.strip()) > limit:
                raise ValueError(f"{name} is too long")
            object.__setattr__(self, name, value.strip())


@dataclass(frozen=True, slots=True)
class ThreatProviderResult:
    """Sanitized provider result. No raw provider error is retained."""

    provider_status: ProviderStatus
    payload: ThreatAssessmentPayload | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.provider_status, ProviderStatus):
            raise ValueError("provider_status must be a ProviderStatus")
        if self.provider_status is ProviderStatus.OK:
            if self.payload is None:
                raise ValueError("OK provider status requires a payload")
        elif self.payload is not None:
            raise ValueError("non-OK provider status must not carry a payload")


@dataclass(frozen=True, slots=True)
class ThreatAssessment:
    """Complete advisory assessment persisted and returned to API clients."""

    analysis_status: AnalysisStatus
    threat_level: ThreatLevel
    risk_score: int
    detected_threats: tuple[DetectedThreat, ...]
    evidence: tuple[str, ...]
    suspicious_instructions: tuple[str, ...]
    intent_alignment: IntentAlignment
    explanation: str
    recommended_handling: str
    model_name: str
    analyzed_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.analysis_status, AnalysisStatus):
            raise ValueError("analysis_status must be an AnalysisStatus")
        if not isinstance(self.model_name, str) or not self.model_name.strip():
            raise ValueError("model_name must be a non-empty string")
        object.__setattr__(self, "analyzed_at", ensure_utc(self.analyzed_at))
        # Reuse payload validation for the model-derived fields.
        ThreatAssessmentPayload(
            threat_level=self.threat_level,
            risk_score=self.risk_score,
            detected_threats=self.detected_threats,
            evidence=self.evidence,
            suspicious_instructions=self.suspicious_instructions,
            intent_alignment=self.intent_alignment,
            explanation=self.explanation,
            recommended_handling=self.recommended_handling,
        )


@dataclass(frozen=True, slots=True)
class ThreatAnalysisResult:
    assessment: ThreatAssessment
    provider_status: ProviderStatus

    def __post_init__(self) -> None:
        if not isinstance(self.assessment, ThreatAssessment):
            raise ValueError("assessment must be a ThreatAssessment")
        if not isinstance(self.provider_status, ProviderStatus):
            raise ValueError("provider_status must be a ProviderStatus")


@dataclass(frozen=True, slots=True)
class ThreatAnalysisRecord:
    analysis_id: UUID
    transaction_id: UUID
    assessment: ThreatAssessment
    provider_status: ProviderStatus

    def __post_init__(self) -> None:
        if not isinstance(self.analysis_id, UUID):
            raise ValueError("analysis_id must be a UUID")
        if not isinstance(self.transaction_id, UUID):
            raise ValueError("transaction_id must be a UUID")
        if not isinstance(self.assessment, ThreatAssessment):
            raise ValueError("assessment must be a ThreatAssessment")
        if not isinstance(self.provider_status, ProviderStatus):
            raise ValueError("provider_status must be a ProviderStatus")
