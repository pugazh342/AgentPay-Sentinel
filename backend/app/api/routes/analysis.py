"""Advisory threat-analysis endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends

from app.api.deps import (
    get_threat_analysis_service,
    require_security_configuration,
)
from app.application.threat_analysis_service import ThreatAnalysisService
from app.domain.errors import NotFoundFailure
from app.domain.threat import ThreatAnalysisContext
from app.schemas.analysis import AnalysisContextRequest, ThreatAnalysisResponse
from app.schemas.common import ErrorResponse

router = APIRouter(
    prefix="/api/v1/analysis",
    tags=["Analysis"],
    dependencies=[Depends(require_security_configuration)],
)

_ERROR_RESPONSES = {
    422: {"model": ErrorResponse, "description": "Validation error"},
    503: {"model": ErrorResponse, "description": "Security configuration invalid"},
}


@router.post(
    "/transactions/{transaction_id}",
    response_model=ThreatAnalysisResponse,
    summary="Run advisory threat analysis for a persisted transaction",
    description=(
        "Analyzes a persisted transaction using the configured Gemini provider. "
        "The result is advisory and persisted; it never authorizes, captures or "
        "executes a payment and never changes the stored deterministic decision."
    ),
    responses={
        404: {"model": ErrorResponse, "description": "Transaction not found"},
        **_ERROR_RESPONSES,
    },
)
def analyze_transaction(
    transaction_id: UUID,
    payload: AnalysisContextRequest | None = None,
    service: ThreatAnalysisService = Depends(get_threat_analysis_service),
) -> ThreatAnalysisResponse:
    context = payload.to_domain() if payload is not None else ThreatAnalysisContext()
    record = service.analyze_transaction(transaction_id, context)
    return ThreatAnalysisResponse.from_record(record)


@router.get(
    "/transactions/{transaction_id}",
    response_model=ThreatAnalysisResponse,
    summary="Retrieve the latest advisory threat analysis",
    description=(
        "Returns the most recently persisted analysis for a transaction. "
        "Analysis output is advisory only."
    ),
    responses={
        404: {"model": ErrorResponse, "description": "Analysis not found"},
        **_ERROR_RESPONSES,
    },
)
def get_transaction_analysis(
    transaction_id: UUID,
    service: ThreatAnalysisService = Depends(get_threat_analysis_service),
) -> ThreatAnalysisResponse:
    record = service.get_latest(transaction_id)
    if record is None:
        raise NotFoundFailure("Threat analysis not found for this transaction.")
    return ThreatAnalysisResponse.from_record(record)
