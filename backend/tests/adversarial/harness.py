"""Scenario harness: fresh app + deterministic doubles per attack.

Each scenario receives an isolated SQLite database, a mutable clock, a stub
Gemini provider and a stub PayPal gateway. Scenarios exercise real application
services, repositories and state transitions; only external providers are
mocked.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import text

from app.config import Settings
from app.domain.money import money_to_storage
from app.domain.time import canonical_timestamp
from app.main import create_app
from tests.conftest import (
    BASE_TIME,
    TEST_HMAC_SECRET,
    TEST_OPERATOR_PASSWORD,
    TEST_OPERATOR_PASSWORD_HASH,
    TEST_OPERATOR_SESSION_SECRET,
    TEST_OPERATOR_USERNAME,
    MutableClock,
    StubPayPalGateway,
    StubThreatProvider,
)

WEBHOOK_HEADERS = {
    "paypal-transmission-id": "adv-transmission-1",
    "paypal-transmission-time": "2026-01-15T12:00:00Z",
    "paypal-cert-url": "https://api.sandbox.paypal.com/cert",
    "paypal-auth-algo": "SHA256withRSA",
    "paypal-transmission-sig": "adv-signature",
}

_DATETIME_FIELDS = frozenset(
    {
        "created_at",
        "expires_at",
        "updated_at",
        "evaluated_at",
        "approved_at",
        "buyer_approved_at",
        "completed_at",
        "received_at",
        "analyzed_at",
        "timestamp",
    }
)

_ALLOWED_FIELDS: dict[str, frozenset[str]] = {
    "purchase_intents": frozenset(
        {
            "user_id",
            "purpose",
            "merchant_id",
            "product_category",
            "max_amount",
            "currency",
            "max_quantity",
            "require_approval",
            "created_at",
            "expires_at",
            "fingerprint",
        }
    ),
    "transaction_evaluations": frozenset(
        {
            "request_id",
            "user_id",
            "merchant_id",
            "product_category",
            "amount",
            "currency",
            "quantity",
            "decision",
            "reason_codes",
            "explanation",
            "risk_level",
            "evaluated_at",
        }
    ),
    "payments": frozenset(
        {
            "state",
            "version",
            "paypal_order_id",
            "paypal_capture_id",
            "paypal_status",
            "approved_by",
            "approved_at",
            "buyer_approved_at",
            "completed_at",
            "failure_reason",
            "amount",
            "currency",
            "updated_at",
        }
    ),
}


def _sql_value(field: str, value: Any) -> Any:
    if value is None:
        return None
    if field in _DATETIME_FIELDS and isinstance(value, datetime):
        return canonical_timestamp(value)
    if isinstance(value, Decimal):
        return money_to_storage(value)
    return value


class ScenarioHarness(AbstractContextManager["ScenarioHarness"]):
    """Owns one isolated application instance for one scenario execution."""

    def __init__(self, directory: Path | str) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self._client_context: Any = None
        self.client: TestClient | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def __enter__(self) -> ScenarioHarness:
        db_path = (self.directory / "adversarial.db").as_posix()
        self.settings = Settings(
            _env_file=None,
            hmac_secret=TEST_HMAC_SECRET,
            database_url=f"sqlite:///{db_path}",
            environment="test",
            log_level="WARNING",
            operator_username=TEST_OPERATOR_USERNAME,
            operator_password_hash=TEST_OPERATOR_PASSWORD_HASH,
            operator_session_secret=TEST_OPERATOR_SESSION_SECRET,
            operator_cookie_secure=False,
            auth_enabled=True,
        )
        self.clock = MutableClock(BASE_TIME)
        self.threat_provider = StubThreatProvider()
        self.paypal = StubPayPalGateway()
        self.app = create_app(
            settings=self.settings,
            clock=self.clock,
            threat_provider=self.threat_provider,
            paypal_gateway=self.paypal,
        )
        self._client_context = TestClient(self.app)
        self.client = self._client_context.__enter__()
        self._login()
        self._wrap_csrf()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        assert self._client_context is not None
        self._client_context.__exit__(exc_type, exc, traceback)

    @property
    def database(self):
        return self.app.state.db

    # ------------------------------------------------------------------
    # Intent / transaction / payment helpers
    # ------------------------------------------------------------------
    def create_intent(self, **overrides: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "user_id": "user_123",
            "purpose": "Purchase one pair of running shoes",
            "merchant_id": "merchant_shoes",
            "product_category": "footwear",
            "max_amount": "800.00",
            "currency": "USD",
            "max_quantity": 1,
            "require_approval": True,
            "expires_at": (
                self.clock.now() + timedelta(hours=2)
            ).isoformat(),
        }
        payload.update(overrides)
        expires_at = payload.get("expires_at")
        if isinstance(expires_at, datetime):
            payload["expires_at"] = expires_at.isoformat()
        response = self._client().post("/api/v1/intents", json=payload)
        if response.status_code != 201:
            raise RuntimeError(
                f"intent creation failed with HTTP {response.status_code}: "
                f"{response.text}"
            )
        return response.json()

    def evaluate(
        self,
        intent: Mapping[str, Any],
        *,
        request_id: str | None = None,
        **overrides: Any,
    ):
        payload: dict[str, Any] = {
            "user_id": intent["user_id"],
            "intent_id": intent["intent_id"],
            "merchant_id": intent["merchant_id"],
            "product_category": intent["product_category"],
            "amount": intent["max_amount"],
            "currency": intent["currency"],
            "quantity": intent["max_quantity"],
            "request_id": request_id or f"req_adv_{self._next_request_id()}",
        }
        payload.update(overrides)
        return self._client().post(
            "/api/v1/transactions/evaluate", json=payload
        )

    def evaluate_json(
        self,
        intent: Mapping[str, Any],
        *,
        request_id: str | None = None,
        **overrides: Any,
    ) -> dict[str, Any]:
        response = self.evaluate(
            intent, request_id=request_id, **overrides
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"evaluation failed with HTTP {response.status_code}: "
                f"{response.text}"
            )
        return response.json()

    def prepare(self, transaction_id: str):
        return self._client().post(
            "/api/v1/payments", json={"transaction_id": transaction_id}
        )

    def prepare_ok(self, transaction_id: str) -> dict[str, Any]:
        response = self.prepare(transaction_id)
        if response.status_code != 200:
            raise RuntimeError(
                f"payment preparation failed with HTTP {response.status_code}: "
                f"{response.text}"
            )
        return response.json()

    def approve(self, payment_id: str):
        return self._client().post(
            f"/api/v1/payments/{payment_id}/approve",
            json={"approved_by": "demo_operator"},
        )

    def approve_raw(self, payment_id: str, payload: dict[str, Any]):
        return self._client().post(
            f"/api/v1/payments/{payment_id}/approve", json=payload
        )

    def buyer_return(self, payment_id: str, *, query: str | None = None):
        url = f"/api/v1/payments/{payment_id}/buyer-return"
        if query:
            url = f"{url}?{query}"
        return self._client().post(url)

    def capture(self, payment_id: str):
        return self._client().post(
            f"/api/v1/payments/{payment_id}/capture"
        )

    def get_payment(self, payment_id: str) -> dict[str, Any]:
        response = self._client().get(
            f"/api/v1/payments/{payment_id}"
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"payment lookup failed with HTTP {response.status_code}: "
                f"{response.text}"
            )
        return response.json()

    # ------------------------------------------------------------------
    # Composite flows
    # ------------------------------------------------------------------
    def start_order(self, **intent_overrides: Any) -> tuple[
        dict[str, Any], dict[str, Any], dict[str, Any]
    ]:
        intent = self.create_intent(**intent_overrides)
        decision = self.evaluate_json(intent)
        payment = self.prepare_ok(decision["transaction_id"])
        approved = self.approve(payment["payment_id"])
        if approved.status_code != 200:
            raise RuntimeError(
                f"approval failed with HTTP {approved.status_code}: "
                f"{approved.text}"
            )
        order = approved.json()
        if order["state"] != "PAYPAL_ORDER_CREATED":
            raise RuntimeError(
                f"expected PAYPAL_ORDER_CREATED, got {order['state']}"
            )
        return intent, decision, order

    def start_buyer_approved(self, **intent_overrides: Any) -> tuple[
        dict[str, Any], dict[str, Any], dict[str, Any]
    ]:
        intent, decision, order = self.start_order(**intent_overrides)
        self.paypal.set_order_status(order["paypal_order_id"], "APPROVED")
        returned = self.buyer_return(order["payment_id"])
        if returned.status_code != 200:
            raise RuntimeError(
                f"buyer return failed with HTTP {returned.status_code}: "
                f"{returned.text}"
            )
        payment = returned.json()
        if payment["state"] != "BUYER_APPROVED":
            raise RuntimeError(
                f"expected BUYER_APPROVED, got {payment['state']}"
            )
        return intent, decision, payment

    def capture_pending(self, **intent_overrides: Any) -> tuple[
        dict[str, Any], dict[str, Any], dict[str, Any]
    ]:
        from app.domain.enums import PayPalStatus
        from app.domain.errors import PayPalGatewayError

        intent, decision, approved = self.start_buyer_approved(
            **intent_overrides
        )
        self.paypal.capture_error = PayPalGatewayError(
            "PayPal request timed out.",
            status=PayPalStatus.TIMEOUT,
            ambiguous=True,
        )
        response = self.capture(approved["payment_id"])
        self.paypal.capture_error = None
        if response.status_code != 502:
            raise RuntimeError(
                "expected an ambiguous capture (HTTP 502), got "
                f"HTTP {response.status_code}: {response.text}"
            )
        pending = self.get_payment(approved["payment_id"])
        if pending["state"] != "CAPTURE_PENDING":
            raise RuntimeError(
                f"expected CAPTURE_PENDING, got {pending['state']}"
            )
        return intent, decision, pending

    # ------------------------------------------------------------------
    # PayPal webhook helpers
    # ------------------------------------------------------------------
    def capture_event(
        self,
        payment: Mapping[str, Any],
        *,
        event_id: str,
        capture_id: str = "PAYPAL-CAPTURE-ADV-0001",
        order_id: str | None = None,
        amount: str | None = None,
        currency: str | None = None,
        status: str = "COMPLETED",
    ) -> dict[str, Any]:
        return {
            "id": event_id,
            "event_type": "PAYMENT.CAPTURE.COMPLETED",
            "resource": {
                "id": capture_id,
                "status": status,
                "amount": {
                    "value": (
                        amount
                        if amount is not None
                        else f"{Decimal(str(payment['amount'])):.2f}"
                    ),
                    "currency_code": currency or payment["currency"],
                },
                "supplementary_data": {
                    "related_ids": {
                        "order_id": order_id or payment["paypal_order_id"],
                    }
                },
            },
        }

    def post_webhook(
        self,
        event: Mapping[str, Any],
        *,
        headers: Mapping[str, str] | None = None,
    ):
        return self._client().post(
            "/api/v1/paypal/webhooks",
            json=dict(event),
            headers=dict(headers or WEBHOOK_HEADERS),
        )

    # ------------------------------------------------------------------
    # Raw database inspection and tampering (attack simulation only)
    # ------------------------------------------------------------------
    def execute(self, sql: str, params: Mapping[str, Any] | None = None) -> None:
        with self.database.session() as session:
            session.execute(text(sql), dict(params or {}))
            session.commit()

    def scalar(self, sql: str, params: Mapping[str, Any] | None = None) -> Any:
        with self.database.session() as session:
            return session.execute(text(sql), dict(params or {})).scalar_one()

    def row(
        self, sql: str, params: Mapping[str, Any] | None = None
    ) -> dict[str, Any] | None:
        with self.database.session() as session:
            mapping = (
                session.execute(text(sql), dict(params or {}))
                .mappings()
                .first()
            )
            return dict(mapping) if mapping is not None else None

    def tamper_intent(self, intent_id: str, **fields: Any) -> None:
        self._tamper("purchase_intents", "intent_id", intent_id, fields)

    def tamper_transaction(self, transaction_id: str, **fields: Any) -> None:
        self._tamper(
            "transaction_evaluations",
            "transaction_id",
            transaction_id,
            fields,
        )

    def tamper_payment(self, payment_id: str, **fields: Any) -> None:
        self._tamper("payments", "payment_id", payment_id, fields)

    def _tamper(
        self,
        table: str,
        key_column: str,
        key_value: str,
        fields: Mapping[str, Any],
    ) -> None:
        allowed = _ALLOWED_FIELDS[table]
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(
                "unsupported tamper fields: " + ", ".join(sorted(unknown))
            )
        values = {
            name: _sql_value(name, value) for name, value in fields.items()
        }
        assignments = ", ".join(f"{name} = :{name}" for name in values)
        parameters = {**values, "key_value": str(key_value)}
        self.execute(
            f"UPDATE {table} SET {assignments} WHERE {key_column} = :key_value",
            parameters,
        )

    def payment_row(self, payment_id: str) -> dict[str, Any] | None:
        return self.row(
            "SELECT * FROM payments WHERE payment_id = :payment_id",
            {"payment_id": str(payment_id)},
        )

    def payment_count(self, transaction_id: str | None = None) -> int:
        if transaction_id is None:
            return int(self.scalar("SELECT COUNT(*) FROM payments"))
        return int(
            self.scalar(
                "SELECT COUNT(*) FROM payments WHERE transaction_id = :value",
                {"value": str(transaction_id)},
            )
        )

    def transaction_count(self) -> int:
        return int(self.scalar("SELECT COUNT(*) FROM transaction_evaluations"))

    def webhook_row_count(self) -> int:
        return int(self.scalar("SELECT COUNT(*) FROM paypal_webhook_events"))

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _login(self) -> None:
        client = self._client()
        response = client.post(
            "/api/v1/auth/login",
            json={"username": TEST_OPERATOR_USERNAME, "password": TEST_OPERATOR_PASSWORD},
        )
        if response.status_code != 200:
            raise RuntimeError(f"test operator login failed: {response.status_code} {response.text}")

    def _wrap_csrf(self) -> None:
        client = self._client()
        original_request = client.request

        def request_with_csrf(method, url, **kwargs):
            m = str(method).upper()
            if m not in {"GET", "HEAD", "OPTIONS"}:
                csrf = client.cookies.get("aps_csrf")
                if csrf:
                    headers = dict(kwargs.get("headers") or {})
                    headers.setdefault("X-CSRF-Token", csrf)
                    kwargs["headers"] = headers
            return original_request(method, url, **kwargs)

        client.request = request_with_csrf  # type: ignore[assignment]

    def _client(self) -> TestClient:
        assert self.client is not None, "harness is not entered"
        return self.client

    def _next_request_id(self) -> int:
        if not hasattr(self, "_request_sequence"):
            self._request_sequence = 0
        self._request_sequence += 1
        return self._request_sequence


__all__ = ["ScenarioHarness", "WEBHOOK_HEADERS"]
