"""Consistent error envelope and exception handlers."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.domain.errors import (
    AppError,
    ConfigurationFailure,
    SecurityConfigurationFailure,
)
from app.schemas.common import ErrorBody, ErrorDetail, ErrorResponse

logger = logging.getLogger("agentpay.api")


def _error_response(
    *,
    status_code: int,
    code: str,
    message: str,
    details: list[ErrorDetail] | None = None,
) -> JSONResponse:
    body = ErrorResponse(
        error=ErrorBody(code=code, message=message, details=details)
    )
    return JSONResponse(
        status_code=status_code,
        content=body.model_dump(mode="json", exclude_none=True),
    )


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def handle_app_error(_request: Request, exc: AppError) -> JSONResponse:
        return _error_response(
            status_code=exc.status_code,
            code=exc.code,
            message=exc.message,
        )

    @app.exception_handler(ConfigurationFailure)
    async def handle_configuration_failure(
        _request: Request, _exc: ConfigurationFailure
    ) -> JSONResponse:
        return _error_response(
            status_code=SecurityConfigurationFailure.status_code,
            code=SecurityConfigurationFailure.code,
            message=(
                "Security configuration is invalid; authorization operations "
                "are disabled."
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        details: list[ErrorDetail] = []
        for error in exc.errors():
            location = [
                str(part)
                for part in error.get("loc", ())
                if part not in {"body", "query", "path"}
            ]
            details.append(
                ErrorDetail(
                    field=".".join(location) or "request",
                    message=str(error.get("msg", "Invalid value")),
                )
            )
        return _error_response(
            status_code=422,
            code="VALIDATION_ERROR",
            message="Request validation failed.",
            details=details,
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(
        _request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        default_codes = {
            401: "UNAUTHORIZED",
            403: "FORBIDDEN",
            404: "NOT_FOUND",
            405: "METHOD_NOT_ALLOWED",
        }
        message = exc.detail if isinstance(exc.detail, str) else "Request failed."
        return _error_response(
            status_code=exc.status_code,
            code=default_codes.get(exc.status_code, f"HTTP_{exc.status_code}"),
            message=message,
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(
        request: Request, exc: Exception
    ) -> JSONResponse:
        logger.error(
            "unhandled_exception",
            extra={"path": request.url.path, "error_type": type(exc).__name__},
        )
        return _error_response(
            status_code=500,
            code="INTERNAL_ERROR",
            message="An internal error occurred.",
        )
