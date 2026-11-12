"""Pydantic schemas shared by API routes."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


Identifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    ),
]

RequestId = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    ),
]

Purpose = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=500),
]


class ErrorDetail(BaseModel):
    field: str = Field(description="Field path associated with the error.")
    message: str = Field(description="Safe validation error message.")


class ErrorBody(BaseModel):
    code: str = Field(description="Stable machine-readable error code.")
    message: str = Field(description="Safe human-readable error message.")
    details: list[ErrorDetail] | None = Field(
        default=None, description="Optional field-level validation details."
    )


class ErrorResponse(BaseModel):
    error: ErrorBody


class HealthChecks(BaseModel):
    database: str
    hmac_configuration: str
    ai_provider: str | None = None
    ai_model: str | None = None
    ai_status: str | None = None


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    environment: str
    checks: HealthChecks


def validation_error_example() -> dict[str, Any]:
    """Reusable OpenAPI example for 422 responses."""

    return {
        "error": {
            "code": "VALIDATION_ERROR",
            "message": "Request validation failed.",
            "details": [
                {"field": "amount", "message": "Input should be greater than 0"}
            ],
        }
    }
