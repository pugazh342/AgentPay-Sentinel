"""Payment workflow API schemas.

Request models contain no client-supplied amount, currency, merchant, capture
parameters, approval flags or PayPal identifiers. Every payment value is derived
from the persisted transaction evaluation.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.domain.enums import PaymentState
from app.schemas.common import Identifier

# The buyer approval URL is a bearer link and is only needed while checkout is
# still pending. PENDING_USER_APPROVAL is the frontend checkout gate;
# PAYPAL_ORDER_CREATED is the state in which the PayPal order (and its approval
# URL) actually exists and the buyer has not yet approved it.
_APPROVAL_URL_VISIBLE_STATES = frozenset(
    {
        PaymentState.PENDING_USER_APPROVAL,
        PaymentState.PAYPAL_ORDER_CREATED,
    }
)


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

    @model_validator(mode="after")
    def redact_approval_url_for_non_pending_states(self) -> "PaymentResponse":
        """Redact the buyer approval URL unless checkout is still pending.

        SECURITY: ``approval_url`` is a PayPal bearer link. Returning it for
        completed, failed, expired or post-approval payments exposes a token
        that is no longer needed for the workflow. This is an independent
        server-side restriction; it does not rely on frontend state gating.
        """
        if self.state not in _APPROVAL_URL_VISIBLE_STATES:
            self.approval_url = None
        return self


class PaymentResponseSafe(BaseModel):
    """Payment response with approval_url excluded for listing endpoints."""

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


class PaymentListResponse(BaseModel):
    """Paginated list of payment records."""

    model_config = ConfigDict(from_attributes=True)

    total_count: int = Field(description="Total number of payments in database.")
    limit: int = Field(description="Maximum results per page.")
    offset: int = Field(description="Offset for pagination.")
    results: list[PaymentResponseSafe] = Field(description="List of payment records (approval_url excluded for security).")


class PaymentsFilter(BaseModel):
    """Filter parameters for payment listing."""

    model_config = ConfigDict(extra="forbid")

    state: PaymentState | None = Field(
        default=None, description="Filter by payment state."
    )
    intent_id: UUID | None = Field(
        default=None, description="Filter by purchase intent ID."
    )
    transaction_id: UUID | None = Field(
        default=None, description="Filter by transaction ID."
    )
    limit: int = Field(default=100, ge=1, le=1000, description="Max results.")
    offset: int = Field(default=0, ge=0, description="Pagination offset.")


__all__ = [
    "PaymentApprovalRequest",
    "PaymentPrepareRequest",
    "PaymentResponse",
    "PaymentResponseSafe",
    "PayPalWebhookResponse",
    "PaymentListResponse",
    "PaymentsFilter",
]
