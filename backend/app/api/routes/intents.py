"""Purchase intent endpoints (create and read only; intents are immutable)."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, status

from app.api.deps import (
    get_intent_service,
    require_security_configuration,
)
from app.application.intent_service import CreateIntentCommand, IntentService
from app.domain.errors import NotFoundFailure
from app.schemas.common import ErrorResponse
from app.schemas.intent import IntentCreateRequest, IntentResponse

router = APIRouter(
    prefix="/api/v1/intents",
    tags=["Intents"],
    dependencies=[Depends(require_security_configuration)],
)

_ERROR_RESPONSES = {
    422: {"model": ErrorResponse, "description": "Validation error"},
    503: {"model": ErrorResponse, "description": "Security configuration invalid"},
}


@router.post(
    "",
    response_model=IntentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an immutable purchase intent",
    description=(
        "Creates a user-authored purchase intent, stamps it with an HMAC-SHA256 "
        "fingerprint, and persists it. There is no update endpoint by design."
    ),
    responses={**_ERROR_RESPONSES, 201: {"description": "Intent created"}},
)
def create_intent(
    payload: IntentCreateRequest,
    service: IntentService = Depends(get_intent_service),
) -> IntentResponse:
    intent = service.create(
        CreateIntentCommand(
            user_id=payload.user_id,
            purpose=payload.purpose,
            merchant_id=payload.merchant_id,
            product_category=payload.product_category,
            max_amount=payload.max_amount,
            currency=payload.currency,
            max_quantity=payload.max_quantity,
            require_approval=payload.require_approval,
            expires_at=payload.expires_at,
        )
    )
    return IntentResponse.model_validate(intent)


@router.get(
    "/{intent_id}",
    response_model=IntentResponse,
    summary="Retrieve a purchase intent",
    description=(
        "Returns the stored immutable intent. The integrity fingerprint is not "
        "exposed. Fingerprint verification is enforced during evaluation."
    ),
    responses={
        404: {"model": ErrorResponse, "description": "Intent not found"},
        **_ERROR_RESPONSES,
    },
)
def get_intent(
    intent_id: UUID,
    service: IntentService = Depends(get_intent_service),
) -> IntentResponse:
    intent = service.get(intent_id)
    if intent is None:
        raise NotFoundFailure("Intent not found.")
    return IntentResponse.model_validate(intent)
