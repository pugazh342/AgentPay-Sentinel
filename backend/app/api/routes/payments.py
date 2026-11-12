"""PayPal sandbox payment workflow endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends

from app.api.deps import get_payment_service, require_security_configuration
from app.application.payment_service import PaymentService
from app.domain.errors import NotFoundFailure
from app.schemas.common import ErrorResponse
from app.schemas.payment import (
    PaymentApprovalRequest,
    PaymentListResponse,
    PaymentsFilter,
    PaymentPrepareRequest,
    PaymentResponse,
    PaymentResponseSafe,
)

router = APIRouter(
    prefix="/api/v1/payments",
    tags=["Payments"],
    dependencies=[Depends(require_security_configuration)],
)

_ERROR_RESPONSES = {
    404: {"model": ErrorResponse, "description": "Transaction or payment not found"},
    409: {"model": ErrorResponse, "description": "Illegal payment state transition"},
    422: {"model": ErrorResponse, "description": "Validation error"},
    502: {"model": ErrorResponse, "description": "PayPal provider failure"},
    503: {"model": ErrorResponse, "description": "PayPal or security not configured"},
}


@router.post(
    "",
    response_model=PaymentResponse,
    summary="Prepare a payment from a persisted deterministic evaluation",
    description=(
        "Binds one payment to an existing transaction evaluation. BLOCK and "
        "REVIEW_REQUIRED transactions are persisted in their terminal states and "
        "cannot be approved or captured. The request carries only a trusted "
        "server-side transaction_id; no amount, currency or merchant can be "
        "supplied by the client."
    ),
    responses=_ERROR_RESPONSES,
)
async def prepare_payment(
    payload: PaymentPrepareRequest,
    service: PaymentService = Depends(get_payment_service),
) -> PaymentResponse:
    payment = await service.prepare(payload.transaction_id)
    return PaymentResponse.model_validate(payment)


@router.get(
    "",
    response_model=PaymentListResponse,
    summary="List payments with optional filtering",
    description=(
        "Returns a paginated list of persisted payments. "
        "Supports filtering by state, intent_id, and transaction_id. "
        "Results are ordered by creation time descending."
    ),
)
def list_payments(
    filter: PaymentsFilter = Depends(),
    service: PaymentService = Depends(get_payment_service),
) -> PaymentListResponse:
    payments = service.list_payments(
        limit=filter.limit,
        offset=filter.offset,
        state=filter.state,
        intent_id=filter.intent_id,
        transaction_id=filter.transaction_id,
    )
    # Apply the same filters to get the accurate filtered count
    total = service.count_payments(
        state=filter.state,
        intent_id=filter.intent_id,
        transaction_id=filter.transaction_id,
    )
    return PaymentListResponse(
        total_count=total,
        limit=filter.limit,
        offset=filter.offset,
        results=[PaymentResponseSafe.model_validate(p) for p in payments],
    )


@router.get(
    "/{payment_id}",
    response_model=PaymentResponse,
    summary="Retrieve a payment workflow",
    responses={
        404: {"model": ErrorResponse, "description": "Payment not found"},
        **_ERROR_RESPONSES,
    },
)
def get_payment(
    payment_id: UUID,
    service: PaymentService = Depends(get_payment_service),
) -> PaymentResponse:
    payment = service.get(payment_id)
    if payment is None:
        raise NotFoundFailure("Payment not found.")
    return PaymentResponse.model_validate(payment)


@router.post(
    "/{payment_id}/approve",
    response_model=PaymentResponse,
    summary="Record demo application approval and create a PayPal sandbox order",
    description=(
        "Demo-only approval identity. This milestone has no production user "
        "authentication. Approval revalidates the intent fingerprint, expiry, "
        "amount, currency, merchant, product category and stored deterministic "
        "decision before creating any PayPal order."
    ),
    responses=_ERROR_RESPONSES,
)
async def approve_payment(
    payment_id: UUID,
    payload: PaymentApprovalRequest,
    service: PaymentService = Depends(get_payment_service),
) -> PaymentResponse:
    payment = await service.approve(payment_id, payload.approved_by)
    return PaymentResponse.model_validate(payment)


@router.post(
    "/{payment_id}/buyer-return",
    response_model=PaymentResponse,
    summary="Verify the buyer's return directly with PayPal",
    description=(
        "Any browser-supplied PayPal token or PayerID is ignored. The stored "
        "PayPal order is fetched from PayPal and the browser return is never "
        "treated as proof of payment."
    ),
    responses=_ERROR_RESPONSES,
)
async def buyer_return(
    payment_id: UUID,
    service: PaymentService = Depends(get_payment_service),
) -> PaymentResponse:
    payment = await service.buyer_return(payment_id)
    return PaymentResponse.model_validate(payment)


@router.post(
    "/{payment_id}/capture",
    response_model=PaymentResponse,
    summary="Capture a buyer-approved PayPal sandbox order",
    description=(
        "Revalidates the original intent fingerprint, expiry, exact amount, "
        "currency, merchant, transaction status and buyer approval before "
        "claiming the durable CAPTURE_PENDING state. Duplicate and concurrent "
        "capture requests cannot execute a second provider capture."
    ),
    responses=_ERROR_RESPONSES,
)
async def capture_payment(
    payment_id: UUID,
    service: PaymentService = Depends(get_payment_service),
) -> PaymentResponse:
    payment = await service.capture(payment_id)
    return PaymentResponse.model_validate(payment)


__all__ = ["router"]
