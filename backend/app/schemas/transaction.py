"""Transaction evaluation API schemas."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictInt

from app.domain.enums import Decision, ReasonCode, RiskLevel
from app.schemas.analysis import AnalysisContextRequest, ThreatAnalysisResponse
from app.schemas.common import Identifier, RequestId
from app.schemas.intent import Currency, Money, ProductCategory

Quantity = Annotated[StrictInt, Field(ge=1, le=1_000_000)]


class TransactionEvaluationRequest(BaseModel):
    """Validated payment request submitted for deterministic evaluation.

    Unknown fields are rejected. In particular there is no client-supplied
    approval, risk score or model judgment field that can influence policy.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "user_id": "user_123",
                "intent_id": "0f8fad5b-d9cb-469f-a165-70867728950e",
                "merchant_id": "merchant_shoes",
                "product_category": "footwear",
                "amount": "800.00",
                "currency": "USD",
                "quantity": 1,
                "request_id": "req_2026_0001",
            }
        },
    )

    user_id: Identifier
    intent_id: UUID
    merchant_id: Identifier
    product_category: ProductCategory
    amount: Money
    currency: Currency
    quantity: Quantity
    request_id: RequestId
    analysis_context: AnalysisContextRequest | None = Field(
        default=None,
        description=(
            "Optional untrusted context. Supplying it triggers advisory AI "
            "analysis and safe reconciliation; omitting it preserves the "
            "deterministic-only response."
        ),
    )


class DecisionResponse(BaseModel):
    """Structured decision. ALLOW_FOR_APPROVAL is not a capture authorization."""

    model_config = ConfigDict(from_attributes=True)

    decision_id: UUID
    transaction_id: UUID
    intent_id: UUID
    decision: Decision = Field(
        description=(
            "ALLOW_FOR_APPROVAL is approval eligibility only and must never be "
            "treated as permission to capture a payment."
        )
    )
    reason_codes: list[ReasonCode]
    explanation: str
    evaluated_at: datetime
    risk_level: RiskLevel = Field(
        description="Descriptive metadata only; never used for authorization."
    )
    analysis: ThreatAnalysisResponse | None = Field(
        default=None,
        description=(
            "Advisory contextual analysis when analysis_context was supplied. "
            "Never a payment authorization."
        ),
    )


class TransactionResponse(BaseModel):
    """Persisted transaction evaluation with its decision."""

    transaction_id: UUID
    request_id: str
    user_id: str
    intent_id: UUID
    merchant_id: str
    product_category: str
    amount: Decimal
    currency: str
    quantity: int
    decision: DecisionResponse
