"""FastAPI application factory and ASGI entrypoint."""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, Request

from app import __version__
from app.ai.gemini_provider import GeminiThreatProvider
from app.api.errors import register_exception_handlers
from app.api.routes import (
    analysis,
    health,
    intents,
    payments,
    paypal_webhooks,
    security,
    transactions,
)
from app.application.threat_engine import ThreatAnalysisEngine
from app.config import Settings
from app.domain.clock import Clock, SystemClock
from app.domain.ports import PayPalGateway, ThreatAnalysisProvider
from app.logging_config import configure_logging
from app.paypal.client import PayPalClient
from app.persistence.database import Database
from app.security.fingerprint import FingerprintService

logger = logging.getLogger("agentpay")

DESCRIPTION = """
AgentPay Sentinel is a zero-trust authorization core for AI-agent payments.

This milestone adds PayPal Orders v2 integration in **sandbox mode only**.

Security boundaries:

* The AI model never authorizes, creates or captures a payment.
* Deterministic policy remains the authorization source of truth.
* AI output can only preserve a decision or raise an eligible request to human
  review; it can never downgrade or override a policy block.
* Clients cannot submit approval status, risk scores or policy overrides.
* `ALLOW_FOR_APPROVAL` means only that a request is eligible for a separate
  approval workflow. It is **not** permission to capture, settle or execute a
  payment.
* Payment amounts, currencies and merchants are derived from persisted
  server-side records, never from capture parameters.
* Buyer browser returns are untrusted and are always re-verified directly with
  PayPal.
* Webhooks are accepted only after PayPal signature verification.
* The PayPal base URL is fixed to the sandbox. Live payment execution is not
  configurable.
* This remains a local-development foundation with no production user
  authentication. It is not a production-secure gateway.
"""


def create_app(
    settings: Settings | None = None,
    clock: Clock | None = None,
    threat_provider: ThreatAnalysisProvider | None = None,
    paypal_gateway: PayPalGateway | None = None,
) -> FastAPI:
    resolved_settings = settings or Settings()
    configure_logging(resolved_settings.log_level)

    fingerprints = FingerprintService(resolved_settings.hmac_secret_value)
    database = Database(resolved_settings.database_url)
    resolved_clock = clock or SystemClock()

    resolved_provider = threat_provider or GeminiThreatProvider(
        api_key=resolved_settings.gemini_api_key_value,
        model=resolved_settings.gemini_model,
        timeout_ms=resolved_settings.gemini_timeout_ms,
        max_retries=resolved_settings.gemini_max_retries,
        retry_backoff_seconds=resolved_settings.gemini_retry_backoff_seconds,
    )
    threat_engine = ThreatAnalysisEngine(
        provider=resolved_provider,
        clock=resolved_clock,
        model_name=resolved_settings.gemini_model,
    )
    resolved_gateway = paypal_gateway or PayPalClient(
        client_id=resolved_settings.paypal_client_id_value,
        client_secret=resolved_settings.paypal_client_secret_value,
        webhook_id=resolved_settings.paypal_webhook_id_value,
        base_url=resolved_settings.paypal_base_url,
        timeout_ms=resolved_settings.paypal_timeout_ms,
        max_retries=resolved_settings.paypal_max_retries,
        retry_backoff_seconds=resolved_settings.paypal_retry_backoff_seconds,
        token_skew_seconds=resolved_settings.paypal_token_skew_seconds,
        return_url=resolved_settings.paypal_return_url,
        cancel_url=resolved_settings.paypal_cancel_url,
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        database.create_all()
        if fingerprints.configured:
            logger.info(
                "application_startup",
                extra={"environment": resolved_settings.environment},
            )
        else:
            logger.warning(
                "security_configuration_invalid",
                extra={"environment": resolved_settings.environment},
            )
        if resolved_provider.configured:
            logger.info(
                "ai_provider_configured",
                extra={"model_name": resolved_settings.gemini_model},
            )
        else:
            logger.warning(
                "ai_provider_not_configured",
                extra={"model_name": resolved_settings.gemini_model},
            )
        if resolved_gateway.configured:
            logger.info(
                "paypal_sandbox_configured",
                extra={"environment": resolved_settings.environment},
            )
        else:
            logger.warning(
                "paypal_sandbox_not_configured",
                extra={"environment": resolved_settings.environment},
            )
        try:
            yield
        finally:
            await resolved_gateway.aclose()
            database.dispose()

    app = FastAPI(
        title="AgentPay Sentinel",
        version=__version__,
        description=DESCRIPTION,
        lifespan=lifespan,
        openapi_tags=[
            {"name": "Health", "description": "Service and security configuration health."},
            {"name": "Intents", "description": "Create and read immutable purchase intents."},
            {
                "name": "Transactions",
                "description": (
                    "Deterministic authorization evaluation. Not payment execution."
                ),
            },
            {
                "name": "Analysis",
                "description": (
                    "Advisory AI threat intelligence. Never payment authorization."
                ),
            },
            {
                "name": "Payments",
                "description": (
                    "Durable PayPal sandbox payment workflow with deterministic "
                    "revalidation and capture safeguards."
                ),
            },
            {
                "name": "PayPal Webhooks",
                "description": (
                    "Signature-verified PayPal event reconciliation."
                ),
            },
            {"name": "Security", "description": "Audit event visibility."},
        ],
        contact={"name": "AgentPay Sentinel"},
        license_info={"name": "Proprietary"},
    )

    app.state.settings = resolved_settings
    app.state.fingerprints = fingerprints
    app.state.db = database
    app.state.clock = resolved_clock
    app.state.threat_provider = resolved_provider
    app.state.threat_engine = threat_engine
    app.state.paypal_gateway = resolved_gateway

    register_exception_handlers(app)

    @app.middleware("http")
    async def request_observability(request: Request, call_next):
        request_id = str(uuid4())
        started = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "http_request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "environment": resolved_settings.environment,
            },
        )
        return response

    app.include_router(health.router)
    app.include_router(intents.router)
    app.include_router(transactions.router)
    app.include_router(analysis.router)
    app.include_router(payments.router)
    app.include_router(paypal_webhooks.router)
    app.include_router(security.router)

    return app


app = create_app()
