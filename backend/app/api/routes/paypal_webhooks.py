"""Verified PayPal webhook receiver."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.api.deps import get_payment_service, require_security_configuration
from app.application.payment_service import PaymentService
from app.domain.errors import WebhookVerificationFailure
from app.schemas.common import ErrorResponse
from app.schemas.payment import PayPalWebhookResponse

router = APIRouter(
    prefix="/api/v1/paypal",
    tags=["PayPal Webhooks"],
    dependencies=[Depends(require_security_configuration)],
)

_ERROR_RESPONSES = {
    400: {"model": ErrorResponse, "description": "Unverified webhook"},
    422: {"model": ErrorResponse, "description": "Malformed webhook"},
    503: {"model": ErrorResponse, "description": "Security or PayPal not configured"},
}


@router.post(
    "/webhooks",
    response_model=PayPalWebhookResponse,
    summary="Receive and verify a PayPal webhook",
    description=(
        "Every delivery is verified through PayPal's official "
        "verify-webhook-signature endpoint using the configured webhook ID. "
        "Unverified events are rejected before persistence. Event IDs are "
        "deduplicated, and a verified capture event can only complete a payment "
        "that this service already claimed as CAPTURE_PENDING."
    ),
    responses=_ERROR_RESPONSES,
)
async def receive_webhook(
    request: Request,
    service: PaymentService = Depends(get_payment_service),
) -> PayPalWebhookResponse:
    try:
        event = await request.json()
    except Exception as exc:  # noqa: BLE001 - malformed bodies fail closed
        raise WebhookVerificationFailure(
            "Webhook body must be valid JSON."
        ) from exc
    if not isinstance(event, dict):
        raise WebhookVerificationFailure(
            "Webhook body must be a JSON object."
        )

    result = await service.handle_webhook(
        event=event,
        transmission_id=request.headers.get("paypal-transmission-id", ""),
        transmission_time=request.headers.get("paypal-transmission-time", ""),
        cert_url=request.headers.get("paypal-cert-url", ""),
        auth_algo=request.headers.get("paypal-auth-algo", ""),
        transmission_sig=request.headers.get("paypal-transmission-sig", ""),
    )
    return PayPalWebhookResponse(
        event_id=result.event_id,
        event_type=result.event_type,
        duplicate=result.duplicate,
        outcome=result.outcome,
    )


__all__ = ["router"]
