"""Structured JSON logging.

Only an allowlisted set of structured fields is serialized. This prevents
accidental leakage of secrets or request bodies through ``extra``.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

_ALLOWED_EXTRA_FIELDS = (
    "environment",
    "event_id",
    "event_type",
    "transaction_id",
    "intent_id",
    "decision",
    "reason_codes",
    "request_id",
    "method",
    "path",
    "status_code",
    "duration_ms",
    "error_type",
    "provider_status",
    "analysis_status",
    "model_name",
    "payment_id",
    "payment_state",
    "paypal_order_id",
    "paypal_capture_id",
    "paypal_status",
    "webhook_event_id",
    "webhook_event_type",
    "outcome",
)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in _ALLOWED_EXTRA_FIELDS:
            if hasattr(record, field):
                payload[field] = getattr(record, field)
        if record.exc_info and record.exc_info[0] is not None:
            payload["error_type"] = record.exc_info[0].__name__
        return json.dumps(payload, default=str, separators=(",", ":"))


def configure_logging(level: str) -> None:
    """Configure the application logger idempotently."""

    logger = logging.getLogger("agentpay")
    logger.setLevel(level)
    logger.propagate = False

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)

    for existing in logger.handlers:
        existing.setLevel(level)
