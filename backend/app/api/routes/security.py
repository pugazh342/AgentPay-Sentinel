"""Security audit event query endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.deps import (
    get_security_event_repository,
    require_security_configuration,
)
from app.domain.enums import Decision, EventType
from app.persistence.repositories import SqlAlchemySecurityEventRepository
from app.schemas.common import ErrorResponse
from app.schemas.security import SecurityEventListResponse, SecurityEventResponse

router = APIRouter(
    prefix="/api/v1/security",
    tags=["Security"],
    dependencies=[Depends(require_security_configuration)],
)


@router.get(
    "/events",
    response_model=SecurityEventListResponse,
    summary="List recent security events",
    description=(
        "Returns recent audit events in reverse chronological order. Events "
        "contain no secrets, credentials or unnecessary personal data."
    ),
    responses={
        422: {"model": ErrorResponse, "description": "Validation error"},
        503: {"model": ErrorResponse, "description": "Security configuration invalid"},
    },
)
def list_security_events(
    limit: int = Query(default=50, ge=1, le=200),
    event_type: EventType | None = Query(default=None),
    decision: Decision | None = Query(default=None),
    repository: SqlAlchemySecurityEventRepository = Depends(
        get_security_event_repository
    ),
) -> SecurityEventListResponse:
    events = repository.list_recent(
        limit=limit,
        event_type=event_type,
        decision=decision,
    )
    total = repository.count(event_type=event_type, decision=decision)
    items = [SecurityEventResponse.model_validate(event) for event in events]
    return SecurityEventListResponse(
        items=items, count=len(items), total_count=total, limit=limit
    )
