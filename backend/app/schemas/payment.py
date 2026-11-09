"""Payment workflow API schemas.

Request models contain no client-supplied amount, currency, merchant, capture
parameters, approval flags or PayPal identifiers. Every payment value is derived
from the persisted transaction evaluation.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.domain.enums import PaymentState
from app.schemas.common import Identifier


class PaymentPrepareRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transaction_id: UUID = Field(
        description="Persisted transaction evaluation to bind this payment to."
    )


class PaymentApprovalRequest(BaseModel):
    """Demo-only application approval.

    There is no production user authentication in this milestone. The
    ``approved_by`` value is recorded for audit purposes and must not be
    treated as an authenticated identity.
    """

    model_config = ConfigDict(extra="forbid")

    approved_by: Identifier = Field(
        description=(
            "Demo approval identity. Not authenticated in this milestone; "
            "never trust it as a production user identity."
        )
    )


class PaymentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    payment_id: UUID
    transaction_id: UUID
    intent_id: UUID
    amount: Decimal
    currency: str
    merchant_id: str
    product_category: str
    state: PaymentState
    paypal_order_id: str | None = None
    approval_url: str | None = Field(
        default=None,
        description=(
            "PayPal sandbox approval URL. The browser return is untrusted and is "
            "always re-verified directly with PayPal."
        ),
    )
    paypal_capture_id: str | None = None
    paypal_status: str | None = None
    approved_by: str | None = None
    approved_at: datetime | None = None
    buyer_approved_at: datetime | None = None
    completed_at: datetime | None = None
    failure_reason: str | None = None
    created_at: datetime
    updated_at: datetime


class PayPalWebhookResponse(BaseModel):
    event_id: str
    event_type: str
    duplicate: bool
    outcome: str


__all__ = [
    "PaymentApprovalRequest",
    "PaymentPrepareRequest",
    "PaymentResponse",
    "PayPalWebhookResponse",
]
