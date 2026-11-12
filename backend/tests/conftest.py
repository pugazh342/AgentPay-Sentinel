"""Shared pytest fixtures."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from itertools import count
from threading import Lock
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.domain.enums import IntentAlignment, PayPalStatus, ProviderStatus, ThreatLevel
from app.domain.errors import PayPalGatewayError
from app.domain.payment import PayPalCaptureResult, PayPalOrderResult
from app.domain.threat import ThreatAnalysisInput, ThreatAssessmentPayload, ThreatProviderResult
from app.main import create_app

TEST_HMAC_SECRET = "test-only-secret-0123456789abcdef0123456789abcdef"
TEST_OPERATOR_USERNAME = "operator"
TEST_OPERATOR_PASSWORD = "testpass123"
TEST_OPERATOR_PASSWORD_HASH = "pbkdf2_sha256$260000$YOhOsEc7thph7pSfuHzP1g$uoGNrKarT6ZDd0yN3Y22c0Ku5TBG4BK9hJozQH2f-wk"
TEST_OPERATOR_SESSION_SECRET = "test-operator-session-secret-0123456789abcdef"
BASE_TIME = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


class MutableClock:
    """Deterministic injectable clock; no sleeps in tests."""

    def __init__(self, now: datetime) -> None:
        self._now = now
        self._lock = Lock()

    def now(self) -> datetime:
        with self._lock:
            return self._now

    def advance(self, **kwargs: float) -> None:
        with self._lock:
            self._now = self._now + timedelta(**kwargs)


@pytest.fixture
def clock() -> MutableClock:
    return MutableClock(BASE_TIME)


@pytest.fixture
def settings(tmp_path) -> Settings:
    database_path = (tmp_path / "agentpay-test.db").as_posix()
    return Settings(
        _env_file=None,
        hmac_secret=TEST_HMAC_SECRET,
        database_url=f"sqlite:///{database_path}",
        environment="test",
        log_level="WARNING",
        operator_username=TEST_OPERATOR_USERNAME,
        operator_password_hash=TEST_OPERATOR_PASSWORD_HASH,
        operator_session_secret=TEST_OPERATOR_SESSION_SECRET,
        operator_cookie_secure=False,
        auth_enabled=True,
    )


@pytest.fixture
def app(settings: Settings, clock: MutableClock) -> FastAPI:
    return create_app(settings=settings, clock=clock)


def _login_test_operator(test_client: TestClient) -> None:
    response = test_client.post(
        "/api/v1/auth/login",
        json={"username": TEST_OPERATOR_USERNAME, "password": TEST_OPERATOR_PASSWORD},
    )
    assert response.status_code == 200, response.text


def _attach_csrf_header(test_client: TestClient, method: str, kwargs: dict) -> None:
    if str(method).upper() in {"GET", "HEAD", "OPTIONS"}:
        return
    csrf = test_client.cookies.get("aps_csrf")
    if not csrf:
        return
    headers = dict(kwargs.get("headers") or {})
    headers.setdefault("X-CSRF-Token", csrf)
    kwargs["headers"] = headers


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        _login_test_operator(test_client)
        original_request = test_client.request

        def request_with_csrf(method, url, **kwargs):
            _attach_csrf_header(test_client, method, kwargs)
            return original_request(method, url, **kwargs)

        test_client.request = request_with_csrf  # type: ignore[assignment]
        yield test_client


@pytest.fixture
def intent_payload(clock: MutableClock) -> dict[str, Any]:
    return {
        "user_id": "user_123",
        "purpose": "Purchase one pair of running shoes",
        "merchant_id": "merchant_shoes",
        "product_category": "footwear",
        "max_amount": "800.00",
        "currency": "USD",
        "max_quantity": 1,
        "require_approval": True,
        "expires_at": (clock.now() + timedelta(hours=2)).isoformat(),
    }


@pytest.fixture
def intent_factory(
    client: TestClient,
    intent_payload: dict[str, Any],
) -> Callable[..., dict[str, Any]]:
    sequence = count(1)

    def create(**overrides: Any) -> dict[str, Any]:
        payload = dict(intent_payload)
        payload["purpose"] = f"{payload['purpose']} #{next(sequence)}"
        payload.update(overrides)
        expires_at = payload.get("expires_at")
        if isinstance(expires_at, datetime):
            payload["expires_at"] = expires_at.isoformat()
        response = client.post("/api/v1/intents", json=payload)
        assert response.status_code == 201, response.text
        return response.json()

    return create


@pytest.fixture
def evaluate(
    client: TestClient,
) -> Callable[..., Any]:
    sequence = count(1)

    def run(intent: dict[str, Any], **overrides: Any) -> Any:
        payload: dict[str, Any] = {
            "user_id": intent["user_id"],
            "intent_id": intent["intent_id"],
            "merchant_id": intent["merchant_id"],
            "product_category": intent["product_category"],
            "amount": intent["max_amount"],
            "currency": intent["currency"],
            "quantity": intent["max_quantity"],
            "request_id": f"req_test_{next(sequence):04d}",
        }
        payload.update(overrides)
        return client.post("/api/v1/transactions/evaluate", json=payload)

    return run


def benign_payload() -> ThreatAssessmentPayload:
    return ThreatAssessmentPayload(
        threat_level=ThreatLevel.LOW,
        risk_score=5,
        detected_threats=(),
        evidence=("The request matches the authorized purchase intent.",),
        suspicious_instructions=(),
        intent_alignment=IntentAlignment.ALIGNED,
        explanation="No contextual threat indicators were found.",
        recommended_handling="NO_ESCALATION",
    )


class StubThreatProvider:
    """Deterministic provider double used by API-level tests."""

    def __init__(
        self,
        *,
        provider_status: ProviderStatus = ProviderStatus.OK,
        payload: ThreatAssessmentPayload | None = None,
    ) -> None:
        self.provider_status = provider_status
        self.payload = payload if payload is not None else benign_payload()
        self.calls: list[ThreatAnalysisInput] = []

    @property
    def configured(self) -> bool:
        return True

    @property
    def model_name(self) -> str:
        return "gemini-test"

    def analyze(self, analysis_input: ThreatAnalysisInput) -> ThreatProviderResult:
        self.calls.append(analysis_input)
        if self.provider_status is ProviderStatus.OK:
            return ThreatProviderResult(
                provider_status=ProviderStatus.OK,
                payload=self.payload,
            )
        return ThreatProviderResult(provider_status=self.provider_status)


@pytest.fixture
def stub_provider() -> StubThreatProvider:
    return StubThreatProvider()


@pytest.fixture
def analysis_app(
    settings: Settings,
    clock: MutableClock,
    stub_provider: StubThreatProvider,
) -> FastAPI:
    return create_app(
        settings=settings,
        clock=clock,
        threat_provider=stub_provider,
    )


@pytest.fixture
def analysis_client(analysis_app: FastAPI) -> Iterator[TestClient]:
    with TestClient(analysis_app) as test_client:
        _login_test_operator(test_client)
        original_request = test_client.request

        def request_with_csrf(method, url, **kwargs):
            _attach_csrf_header(test_client, method, kwargs)
            return original_request(method, url, **kwargs)

        test_client.request = request_with_csrf  # type: ignore[assignment]
        yield test_client


class StubPayPalGateway:
    """Deterministic async PayPal double used by API-level tests.

    No network access and no credentials are required. Tests can mutate the
    stored order, inject provider errors or override provider results.
    """

    def __init__(self) -> None:
        self._configured = True
        self.orders: dict[str, dict[str, Any]] = {}
        self.order_overrides: dict[str, PayPalOrderResult] = {}
        self.capture_result_override: PayPalCaptureResult | None = None
        self.create_error: PayPalGatewayError | None = None
        self.get_error: PayPalGatewayError | None = None
        self.capture_error: PayPalGatewayError | None = None
        self.create_calls: list[dict[str, Any]] = []
        self.get_calls: list[str] = []
        self.capture_calls: list[dict[str, Any]] = []
        self.verify_calls: list[dict[str, Any]] = []
        self.verify_result = True
        self.closed = False
        self._order_sequence = count(1)
        self._capture_sequence = count(1)

    @property
    def configured(self) -> bool:
        return self._configured

    def set_configured(self, value: bool) -> None:
        self._configured = value

    def set_order_status(self, order_id: str, status: str) -> None:
        self.orders[order_id]["status"] = status

    async def create_order(
        self,
        *,
        request_id: str,
        amount: Decimal,
        currency: str,
        custom_id: str,
        description: str,
    ) -> PayPalOrderResult:
        self.create_calls.append(
            {
                "request_id": request_id,
                "amount": amount,
                "currency": currency,
                "custom_id": custom_id,
                "description": description,
            }
        )
        if self.create_error is not None:
            raise self.create_error
        order_id = f"PAYPAL-ORDER-{next(self._order_sequence):04d}"
        self.orders[order_id] = {
            "status": "CREATED",
            "amount": amount,
            "currency": currency,
            "custom_id": custom_id,
            "approval_url": (
                "https://www.sandbox.paypal.com/checkoutnow?token=" + order_id
            ),
            "capture_id": None,
            "capture_status": None,
        }
        return self._order(order_id)

    async def get_order(self, order_id: str) -> PayPalOrderResult:
        self.get_calls.append(order_id)
        if self.get_error is not None:
            raise self.get_error
        override = self.order_overrides.get(order_id)
        if override is not None:
            return override
        if order_id not in self.orders:
            raise PayPalGatewayError(
                "Unknown PayPal order.",
                status=PayPalStatus.REJECTED,
            )
        return self._order(order_id)

    async def capture_order(
        self,
        *,
        order_id: str,
        request_id: str,
        custom_id: str,
    ) -> PayPalCaptureResult:
        self.capture_calls.append(
            {
                "order_id": order_id,
                "request_id": request_id,
                "custom_id": custom_id,
            }
        )
        if self.capture_error is not None:
            raise self.capture_error
        if self.capture_result_override is not None:
            return self.capture_result_override
        order = self.orders[order_id]
        capture_id = f"PAYPAL-CAPTURE-{next(self._capture_sequence):04d}"
        order["status"] = "COMPLETED"
        order["capture_id"] = capture_id
        order["capture_status"] = "COMPLETED"
        return PayPalCaptureResult(
            order_id=order_id,
            capture_id=capture_id,
            capture_status="COMPLETED",
            order_status="COMPLETED",
            amount=order["amount"],
            currency=order["currency"],
            custom_id=order["custom_id"],
        )

    async def verify_webhook_signature(
        self,
        *,
        transmission_id: str,
        transmission_time: str,
        cert_url: str,
        auth_algo: str,
        transmission_sig: str,
        webhook_event: dict,
    ) -> bool:
        self.verify_calls.append(
            {
                "transmission_id": transmission_id,
                "transmission_time": transmission_time,
                "cert_url": cert_url,
                "auth_algo": auth_algo,
                "transmission_sig": transmission_sig,
                "webhook_event": webhook_event,
            }
        )
        return self.verify_result

    async def aclose(self) -> None:
        self.closed = True

    def _order(self, order_id: str) -> PayPalOrderResult:
        order = self.orders[order_id]
        return PayPalOrderResult(
            order_id=order_id,
            status=order["status"],
            amount=order["amount"],
            currency=order["currency"],
            approval_url=order["approval_url"],
            custom_id=order["custom_id"],
            capture_id=order["capture_id"],
            capture_status=order["capture_status"],
            raw_custom_id=order.get("custom_id"),
            raw_reference_id=order.get("reference_id"),
        )


@pytest.fixture
def stub_paypal() -> StubPayPalGateway:
    return StubPayPalGateway()


@pytest.fixture
def payment_app(
    settings: Settings,
    clock: MutableClock,
    stub_paypal: StubPayPalGateway,
) -> FastAPI:
    return create_app(
        settings=settings,
        clock=clock,
        paypal_gateway=stub_paypal,
    )


@pytest.fixture
def payment_client(payment_app: FastAPI) -> Iterator[TestClient]:
    with TestClient(payment_app) as test_client:
        _login_test_operator(test_client)
        original_request = test_client.request

        def request_with_csrf(method, url, **kwargs):
            _attach_csrf_header(test_client, method, kwargs)
            return original_request(method, url, **kwargs)

        test_client.request = request_with_csrf  # type: ignore[assignment]
        yield test_client


@pytest.fixture
def payment_intent_factory(
    payment_client: TestClient,
    intent_payload: dict[str, Any],
) -> Callable[..., dict[str, Any]]:
    sequence = count(1)

    def create(**overrides: Any) -> dict[str, Any]:
        payload = dict(intent_payload)
        payload["purpose"] = f"{payload['purpose']} #{next(sequence)}"
        payload.update(overrides)
        expires_at = payload.get("expires_at")
        if isinstance(expires_at, datetime):
            payload["expires_at"] = expires_at.isoformat()
        response = payment_client.post("/api/v1/intents", json=payload)
        assert response.status_code == 201, response.text
        return response.json()

    return create


@pytest.fixture
def payment_evaluate(
    payment_client: TestClient,
) -> Callable[..., Any]:
    sequence = count(1)

    def run(intent: dict[str, Any], **overrides: Any) -> Any:
        payload: dict[str, Any] = {
            "user_id": intent["user_id"],
            "intent_id": intent["intent_id"],
            "merchant_id": intent["merchant_id"],
            "product_category": intent["product_category"],
            "amount": intent["max_amount"],
            "currency": intent["currency"],
            "quantity": intent["max_quantity"],
            "request_id": f"req_pay_{next(sequence):04d}",
        }
        payload.update(overrides)
        return payment_client.post(
            "/api/v1/transactions/evaluate", json=payload
        )

    return run


@pytest.fixture
def analysis_intent_factory(
    analysis_client: TestClient,
    intent_payload: dict[str, Any],
) -> Callable[..., dict[str, Any]]:
    sequence = count(1)

    def create(**overrides: Any) -> dict[str, Any]:
        payload = dict(intent_payload)
        payload["purpose"] = f"{payload['purpose']} #{next(sequence)}"
        payload.update(overrides)
        expires_at = payload.get("expires_at")
        if isinstance(expires_at, datetime):
            payload["expires_at"] = expires_at.isoformat()
        response = analysis_client.post("/api/v1/intents", json=payload)
        assert response.status_code == 201, response.text
        return response.json()

    return create


@pytest.fixture
def analysis_evaluate(
    analysis_client: TestClient,
) -> Callable[..., Any]:
    sequence = count(1)

    def run(intent: dict[str, Any], **overrides: Any) -> Any:
        payload: dict[str, Any] = {
            "user_id": intent["user_id"],
            "intent_id": intent["intent_id"],
            "merchant_id": intent["merchant_id"],
            "product_category": intent["product_category"],
            "amount": intent["max_amount"],
            "currency": intent["currency"],
            "quantity": intent["max_quantity"],
            "request_id": f"req_ai_{next(sequence):04d}",
        }
        payload.update(overrides)
        return analysis_client.post("/api/v1/transactions/evaluate", json=payload)

    return run
