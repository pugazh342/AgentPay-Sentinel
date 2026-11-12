"""Security event API schemas."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.domain.enums import Decision, EventType, ReasonCode


class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: UUID
    transaction_id: UUID | None = Field(
        description="Null for intent lifecycle events that are not transaction-scoped."
    )
    event_type: EventType
    decision: Decision | None
    reason_codes: list[ReasonCode]
    timestamp: datetime


class SecurityEventListResponse(BaseModel):
    items: list[SecurityEventResponse]
    count: int
    total_count: int
    limit: int
