"""Transaction evaluation and retrieval endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends

from app.api.deps import get_transaction_service, require_security_configuration
from app.application.transaction_service import TransactionService
from app.domain.entities import TransactionRequest
from app.domain.errors import NotFoundFailure
from app.schemas.analysis import ThreatAnalysisResponse
from app.schemas.common import ErrorResponse
from app.schemas.transaction import (
    DecisionResponse,
    TransactionEvaluationRequest,
    TransactionResponse,
)

router = APIRouter(
    prefix="/api/v1/transactions",
    tags=["Transactions"],
    dependencies=[Depends(require_security_configuration)],
)

_ERROR_RESPONSES = {
    422: {"model": ErrorResponse, "description": "Validation error"},
    503: {"model": ErrorResponse, "description": "Security configuration invalid"},
}


@router.post(
    "/evaluate",
    response_model=DecisionResponse,
    response_model_exclude_none=True,
    summary="Evaluate a payment request against an immutable intent",
    description=(
        "Runs the deterministic policy. Unknown intents return a BLOCK decision, "
        "not a 404. Client risk scores or approval flags are rejected. "
        "ALLOW_FOR_APPROVAL is never permission to capture a payment. If "
        "analysis_context is supplied, advisory AI analysis is reconciled "
        "without overriding hard policy blocks."
    ),
    responses=_ERROR_RESPONSES,
)
def evaluate_transaction(
    payload: TransactionEvaluationRequest,
    service: TransactionService = Depends(get_transaction_service),
) -> DecisionResponse:
    request = TransactionRequest(
        user_id=payload.user_id,
        intent_id=payload.intent_id,
        merchant_id=payload.merchant_id,
        product_category=payload.product_category,
        amount=payload.amount,
        currency=payload.currency,
        quantity=payload.quantity,
        request_id=payload.request_id,
    )

    if payload.analysis_context is not None:
        result = service.evaluate_with_analysis(
            request,
            payload.analysis_context.to_domain(),
        )
        response = DecisionResponse.model_validate(result.decision)
        return response.model_copy(
            update={"analysis": ThreatAnalysisResponse.from_record(result.analysis)}
            if result.analysis is not None
            else {}
        )

    decision = service.evaluate(request)
    return DecisionResponse.model_validate(decision)


@router.get(
    "/{transaction_id}",
    response_model=TransactionResponse,
    response_model_exclude_none=True,
    summary="Retrieve a persisted transaction evaluation",
    responses={
        404: {"model": ErrorResponse, "description": "Transaction not found"},
        **_ERROR_RESPONSES,
    },
)
def get_transaction(
    transaction_id: UUID,
    service: TransactionService = Depends(get_transaction_service),
) -> TransactionResponse:
    record = service.get(transaction_id)
    if record is None:
        raise NotFoundFailure("Transaction not found.")

    return TransactionResponse(
        transaction_id=record.decision.transaction_id,
        request_id=record.request.request_id,
        user_id=record.request.user_id,
        intent_id=record.request.intent_id,
        merchant_id=record.request.merchant_id,
        product_category=record.request.product_category,
        amount=record.request.amount,
        currency=record.request.currency,
        quantity=record.request.quantity,
        decision=DecisionResponse.model_validate(record.decision),
    )
