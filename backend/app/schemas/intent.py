"""Intent API schemas."""

from __future__ import annotations

import re
from datetime import datetime
from decimal import Decimal
from typing import Annotated
from uuid import UUID

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
)

from app.domain.money import normalize_currency, normalize_money
from app.domain.time import ensure_utc
from app.schemas.common import Identifier, Purpose

_CATEGORY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9 _-]{0,63}$")


def _normalize_category(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("product_category must be a string")
    normalized = value.strip().lower()
    if not _CATEGORY_PATTERN.fullmatch(normalized):
        raise ValueError(
            "product_category must be 1-64 lowercase letters, digits, spaces, "
            "underscores or hyphens"
        )
    return normalized


def _normalize_currency_code(value: str) -> str:
    return normalize_currency(value)


def _reject_float_money(value: object) -> object:
    """Require exact decimal input, never a binary float.

    JSON numeric amounts parsed as floats are rejected; callers must send an
    ISO decimal string (or an integer), eliminating binary rounding at the
    boundary as well as in policy arithmetic.
    """

    if isinstance(value, float):
        raise ValueError("amount must be a decimal string, not a float")
    return value


def _normalize_money_input(value: Decimal) -> Decimal:
    return normalize_money(value)


Money = Annotated[
    Decimal,
    BeforeValidator(_reject_float_money),
    Field(gt=0, max_digits=18, decimal_places=2, allow_inf_nan=False),
    AfterValidator(_normalize_money_input),
]

Currency = Annotated[str, AfterValidator(_normalize_currency_code)]
ProductCategory = Annotated[str, AfterValidator(_normalize_category)]
MaxQuantity = Annotated[StrictInt, Field(ge=1, le=1_000_000)]


def _to_utc(value: datetime) -> datetime:
    return ensure_utc(value)


class IntentCreateRequest(BaseModel):
    """User-authored purchase intent. All fields become immutable after creation."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "user_id": "user_123",
                "purpose": "Purchase one pair of running shoes",
                "merchant_id": "merchant_shoes",
                "product_category": "footwear",
                "max_amount": "800.00",
                "currency": "USD",
                "max_quantity": 1,
                "require_approval": True,
                "expires_at": "2026-12-31T23:59:59Z",
            }
        },
    )

    user_id: Identifier = Field(description="Owner of the intent.")
    purpose: Purpose = Field(description="User's human-readable purchase purpose.")
    merchant_id: Identifier = Field(description="Only this merchant is authorized.")
    product_category: ProductCategory = Field(
        description="Expected product category, normalized to lowercase."
    )
    max_amount: Money = Field(
        description="Maximum authorized amount with at most two decimal places."
    )
    currency: Currency = Field(
        description="Supported ISO-style currency: USD, EUR, GBP, CAD or AUD."
    )
    max_quantity: MaxQuantity = Field(description="Maximum authorized quantity.")
    require_approval: StrictBool = Field(
        default=True,
        description="Approval requirement metadata; this milestone still never captures.",
    )
    expires_at: AwareDatetime = Field(
        description="Expiry timestamp. Must be timezone-aware and in the future."
    )

    @field_validator("expires_at")
    @classmethod
    def normalize_expires_at(cls, value: datetime) -> datetime:
        try:
            return _to_utc(value)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc


class IntentResponse(BaseModel):
    """Public intent resource. The HMAC fingerprint is intentionally not exposed."""

    model_config = ConfigDict(from_attributes=True)

    intent_id: UUID
    user_id: str
    purpose: str
    merchant_id: str
    product_category: str
    max_amount: Decimal = Field(
        description="Exact decimal amount serialized as a string in JSON."
    )
    currency: str
    max_quantity: int
    require_approval: bool
    created_at: datetime
    expires_at: datetime
