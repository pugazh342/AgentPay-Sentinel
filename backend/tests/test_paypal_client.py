"""PayPal sandbox adapter tests using mocked HTTP responses."""

from __future__ import annotations

import asyncio
import json
from decimal import Decimal
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from app.config import Settings
from app.domain.enums import PayPalStatus
from app.domain.errors import PayPalGatewayError
from app.paypal.client import PayPalClient
from tests.conftest import TEST_HMAC_SECRET


def order_payload(
    *,
    order_id: str = "ORDER-1",
    status: str = "CREATED",
    amount: str = "800.00",
    currency: str = "USD",
    custom_id: str = "tx-1",
    approval: bool = True,
    capture_id: str | None = None,
    capture_status: str | None = None,
) -> dict[str, Any]:
    unit: dict[str, Any] = {
        "custom_id": custom_id,
        "amount": {"currency_code": currency, "value": amount},
    }
    if capture_id is not None:
        unit["payments"] = {
            "captures": [
                {
                    "id": capture_id,
                    "status": capture_status or "COMPLETED",
                    "amount": {"currency_code": currency, "value": amount},
                }
            ]
        }
    payload: dict[str, Any] = {
        "id": order_id,
        "status": status,
        "purchase_units": [unit],
    }
    if approval:
        payload["links"] = [
            {
                "rel": "approve",
                "href": f"https://www.sandbox.paypal.com/checkoutnow?token={order_id}",
            }
        ]
    return payload


def token_payload(token: str = "ACCESS-TOKEN") -> dict[str, Any]:
    return {"access_token": token, "expires_in": 3600, "token_type": "Bearer"}


def make_client(
    handler,
    *,
    time_source=None,
    max_retries: int = 0,
    sleep=None,
) -> PayPalClient:
    return PayPalClient(
        client_id="sandbox-client-id",
        client_secret="sandbox-client-secret",
        webhook_id="WEBHOOK-ID",
        timeout_ms=1000,
        max_retries=max_retries,
        retry_backoff_seconds=0.0,
        token_skew_seconds=60,
        return_url="http://127.0.0.1:8000/return",
        cancel_url="http://127.0.0.1:8000/cancel",
        transport=httpx.MockTransport(handler),
        time_source=time_source,
        sleep=sleep,
    )


def test_oauth_token_is_cached_and_request_ids_are_sent() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/v1/oauth2/token":
            return httpx.Response(200, json=token_payload())
        return httpx.Response(
            201,
            json=order_payload(order_id="ORDER-CACHED", custom_id="tx-1"),
        )

    async def main() -> None:
        client = make_client(handler, time_source=lambda: 100.0)
        try:
            first = await client.create_order(
                request_id="agentpay-order-1",
                amount=Decimal("800.00"),
                currency="USD",
                custom_id="tx-1",
                description="Trail running shoes",
            )
            second = await client.create_order(
                request_id="agentpay-order-2",
                amount=Decimal("800.00"),
                currency="USD",
                custom_id="tx-1",
                description="Trail running shoes",
            )
            assert first.approval_url is not None
            assert second.order_id == "ORDER-CACHED"
        finally:
            await client.aclose()

    asyncio.run(main())

    token_requests = [r for r in requests if r.url.path == "/v1/oauth2/token"]
    order_requests = [
        r for r in requests if r.url.path == "/v2/checkout/orders"
    ]
    assert len(token_requests) == 1
    assert token_requests[0].headers["authorization"].startswith("Basic ")
    assert len(order_requests) == 2
    assert order_requests[0].headers["paypal-request-id"] == "agentpay-order-1"
    assert order_requests[1].headers["paypal-request-id"] == "agentpay-order-2"
    assert order_requests[0].headers["authorization"].startswith("Bearer ")


def test_oauth_failure_is_sanitized() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"name": "AUTHENTICATION_FAILURE", "message": "bad credentials"},
        )

    async def main() -> PayPalGatewayError:
        client = make_client(handler)
        try:
            with pytest.raises(PayPalGatewayError) as excinfo:
                await client.create_order(
                    request_id="r1",
                    amount=Decimal("1.00"),
                    currency="USD",
                    custom_id="tx-1",
                    description="test",
                )
        finally:
            await client.aclose()
        return excinfo.value

    error = asyncio.run(main())
    assert error.status is PayPalStatus.REJECTED
    assert "sandbox-client-secret" not in error.message
    assert "bad credentials" not in error.message


def test_token_refreshes_shortly_before_expiry() -> None:
    now = [100.0]
    tokens = iter(["TOKEN-ONE", "TOKEN-TWO"])
    authorizations: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/oauth2/token":
            return httpx.Response(200, json=token_payload(next(tokens)))
        authorizations.append(request.headers["authorization"])
        return httpx.Response(
            201, json=order_payload(order_id="ORDER-1", custom_id="tx-1")
        )

    async def main() -> None:
        client = make_client(handler, time_source=lambda: now[0])
        try:
            await client.create_order(
                request_id="r1",
                amount=Decimal("1.00"),
                currency="USD",
                custom_id="tx-1",
                description="test",
            )
            # Still within the 60 second refresh skew.
            now[0] = 3600.0 + 100.0 - 60.0 - 1.0
            await client.create_order(
                request_id="r2",
                amount=Decimal("1.00"),
                currency="USD",
                custom_id="tx-1",
                description="test",
            )
            # Past the skew: a new token must be acquired.
            now[0] = 3600.0 + 100.0 - 60.0 + 1.0
            await client.create_order(
                request_id="r3",
                amount=Decimal("1.00"),
                currency="USD",
                custom_id="tx-1",
                description="test",
            )
        finally:
            await client.aclose()

    asyncio.run(main())

    assert authorizations == [
        "Bearer TOKEN-ONE",
        "Bearer TOKEN-ONE",
        "Bearer TOKEN-TWO",
    ]


def test_create_order_uses_trusted_payload_and_return_urls() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/oauth2/token":
            return httpx.Response(200, json=token_payload())
        captured.append(request)
        return httpx.Response(
            201, json=order_payload(order_id="ORDER-PAYLOAD", custom_id="tx-9")
        )

    async def main() -> Any:
        client = make_client(handler)
        try:
            result = await client.create_order(
                request_id="agentpay-order-9",
                amount=Decimal("800.00"),
                currency="USD",
                custom_id="tx-9",
                description="Purchase one pair of running shoes",
            )
        finally:
            await client.aclose()
        return result

    result = asyncio.run(main())
    body = json.loads(captured[0].content)
    assert body["intent"] == "CAPTURE"
    assert body["purchase_units"][0]["custom_id"] == "tx-9"
    assert body["purchase_units"][0]["amount"] == {
        "currency_code": "USD",
        "value": "800.00",
    }
    assert (
        body["application_context"]["return_url"]
        == "http://127.0.0.1:8000/return"
    )
    assert result.order_id == "ORDER-PAYLOAD"
    assert result.approval_url is not None


def test_capture_order_sends_idempotency_key_and_verifies_binding() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/oauth2/token":
            return httpx.Response(200, json=token_payload())
        captured.append(request)
        return httpx.Response(
            201,
            json=order_payload(
                order_id="ORDER-CAP",
                status="COMPLETED",
                custom_id="tx-cap",
                capture_id="CAPTURE-1",
            ),
        )

    async def main() -> Any:
        client = make_client(handler)
        try:
            result = await client.capture_order(
                order_id="ORDER-CAP",
                request_id="agentpay-capture-1",
                custom_id="tx-cap",
            )
        finally:
            await client.aclose()
        return result

    result = asyncio.run(main())
    assert captured[0].headers["paypal-request-id"] == "agentpay-capture-1"
    assert result.capture_id == "CAPTURE-1"
    assert result.capture_status == "COMPLETED"
    assert result.amount == Decimal("800.00")
    assert result.custom_id == "tx-cap"


def test_capture_rejects_wrong_transaction_binding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/oauth2/token":
            return httpx.Response(200, json=token_payload())
        return httpx.Response(
            201,
            json=order_payload(
                order_id="ORDER-CAP",
                status="COMPLETED",
                custom_id="other-transaction",
                capture_id="CAPTURE-1",
            ),
        )

    async def main() -> PayPalGatewayError:
        client = make_client(handler)
        try:
            with pytest.raises(PayPalGatewayError) as excinfo:
                await client.capture_order(
                    order_id="ORDER-CAP",
                    request_id="agentpay-capture-1",
                    custom_id="tx-cap",
                )
        finally:
            await client.aclose()
        return excinfo.value

    error = asyncio.run(main())
    assert error.status is PayPalStatus.INVALID_RESPONSE
    assert error.ambiguous is True


def test_webhook_signature_verification_success_and_failure() -> None:
    mode = ["success"]
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/v1/oauth2/token":
            return httpx.Response(200, json=token_payload())
        status = "SUCCESS" if mode[0] == "success" else "FAILURE"
        return httpx.Response(
            200, json={"verification_status": status}
        )

    event = {"id": "WH-1", "event_type": "PAYMENT.CAPTURE.COMPLETED"}

    async def main() -> tuple[bool, bool, bool]:
        client = make_client(handler)
        try:
            ok = await client.verify_webhook_signature(
                transmission_id="t1",
                transmission_time="2026-01-15T12:00:00Z",
                cert_url="https://api.sandbox.paypal.com/cert",
                auth_algo="SHA256withRSA",
                transmission_sig="signature",
                webhook_event=event,
            )
            mode[0] = "failure"
            failed = await client.verify_webhook_signature(
                transmission_id="t2",
                transmission_time="2026-01-15T12:00:01Z",
                cert_url="https://api.sandbox.paypal.com/cert",
                auth_algo="SHA256withRSA",
                transmission_sig="signature",
                webhook_event=event,
            )
            missing = await client.verify_webhook_signature(
                transmission_id="",
                transmission_time="",
                cert_url="",
                auth_algo="",
                transmission_sig="",
                webhook_event=event,
            )
        finally:
            await client.aclose()
        return ok, failed, missing

    ok, failed, missing = asyncio.run(main())

    assert ok is True
    assert failed is False
    assert missing is False
    verify_requests = [
        r for r in requests if "verify-webhook-signature" in r.url.path
    ]
    assert len(verify_requests) == 2
    body = json.loads(verify_requests[0].content)
    assert body["webhook_id"] == "WEBHOOK-ID"
    assert body["webhook_event"] == event


def test_webhook_verification_fails_closed_on_provider_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/oauth2/token":
            return httpx.Response(200, json=token_payload())
        return httpx.Response(500, json={"name": "INTERNAL_ERROR"})

    async def main() -> None:
        client = make_client(handler, max_retries=0)
        try:
            result = await client.verify_webhook_signature(
                transmission_id="t1",
                transmission_time="2026-01-15T12:00:00Z",
                cert_url="https://api.sandbox.paypal.com/cert",
                auth_algo="SHA256withRSA",
                transmission_sig="signature",
                webhook_event={"id": "WH-1"},
            )
        finally:
            await client.aclose()
        assert result is False

    asyncio.run(main())


def test_provider_timeout_is_ambiguous() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/oauth2/token":
            return httpx.Response(200, json=token_payload())
        raise httpx.ReadTimeout("timed out", request=request)

    async def main() -> PayPalGatewayError:
        client = make_client(handler, max_retries=0)
        try:
            with pytest.raises(PayPalGatewayError) as excinfo:
                await client.get_order("ORDER-1")
        finally:
            await client.aclose()
        return excinfo.value

    error = asyncio.run(main())
    assert error.status is PayPalStatus.TIMEOUT
    assert error.ambiguous is True


def test_server_error_is_ambiguous_and_bounded_retries() -> None:
    attempts = [0]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/oauth2/token":
            return httpx.Response(200, json=token_payload())
        attempts[0] += 1
        return httpx.Response(500, json={"name": "INTERNAL_ERROR"})

    async def no_sleep(_seconds: float) -> None:
        return None

    async def main() -> PayPalGatewayError:
        client = make_client(handler, max_retries=1, sleep=no_sleep)
        try:
            with pytest.raises(PayPalGatewayError) as excinfo:
                await client.get_order("ORDER-1")
        finally:
            await client.aclose()
        return excinfo.value

    error = asyncio.run(main())
    assert attempts[0] == 2
    assert error.status is PayPalStatus.PROVIDER_ERROR
    assert error.ambiguous is True


def test_rejected_request_is_not_ambiguous() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/oauth2/token":
            return httpx.Response(200, json=token_payload())
        return httpx.Response(
            422,
            json={
                "name": "UNPROCESSABLE_ENTITY",
                "message": "raw provider detail that must not leak",
            },
        )

    async def main() -> PayPalGatewayError:
        client = make_client(handler)
        try:
            with pytest.raises(PayPalGatewayError) as excinfo:
                await client.create_order(
                    request_id="r1",
                    amount=Decimal("1.00"),
                    currency="USD",
                    custom_id="tx-1",
                    description="test",
                )
        finally:
            await client.aclose()
        return excinfo.value

    error = asyncio.run(main())
    assert error.status is PayPalStatus.REJECTED
    assert error.ambiguous is False
    assert "raw provider detail" not in error.message
    assert "UNPROCESSABLE_ENTITY" in error.message


def test_client_rejects_live_base_url() -> None:
    with pytest.raises(ValueError):
        PayPalClient(
            client_id="id",
            client_secret="secret",
            base_url="https://api-m.paypal.com",
        )


def test_settings_reject_live_environment() -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            hmac_secret=TEST_HMAC_SECRET,
            paypal_environment="live",
        )
