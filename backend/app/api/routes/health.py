"""Health endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response
from sqlalchemy import text

from app import __version__
from app.schemas.common import ErrorResponse, HealthChecks, HealthResponse

router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness and security-configuration health",
    description=(
        "Returns 200 when the database is reachable and the HMAC secret is valid. "
        "Returns 503 when the gateway is failing closed."
    ),
    responses={503: {"model": ErrorResponse, "description": "Degraded/fail-closed"}},
)
def health(request: Request, response: Response) -> HealthResponse:
    database_status = "ok"
    try:
        with request.app.state.db.session() as session:
            session.execute(text("SELECT 1"))
    except Exception:
        database_status = "error"

    fingerprints = request.app.state.fingerprints
    hmac_status = "configured" if fingerprints.configured else "invalid"
    healthy = database_status == "ok" and fingerprints.configured
    response.status_code = 200 if healthy else 503

    settings = request.app.state.settings
    ai_status = "configured" if settings.active_provider_configured else "not_configured"

    return HealthResponse(
        status="ok" if healthy else "degraded",
        service="agentpay-sentinel",
        version=__version__,
        environment=settings.environment,
        checks=HealthChecks(
            database=database_status,
            hmac_configuration=hmac_status,
            ai_provider=settings.ai_provider,
            ai_model=settings.active_model,
            ai_status=ai_status,
        ),
    )
