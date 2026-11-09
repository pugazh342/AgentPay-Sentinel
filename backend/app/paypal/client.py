"""PayPal Orders v2 sandbox client.

Security properties:

* The base URL is a fixed sandbox origin; live execution is not configurable.
* OAuth client credentials are only sent to the token endpoint, wrapped in
  Basic authentication, and never logged or returned.
* Access tokens are cached in memory until shortly before expiry.
* Requests have bounded timeouts and retries. Error messages are sanitized.
* Browser return parameters are never treated as payment proof: callers must
  fetch the order directly from PayPal.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import quote

import httpx

from app.config import PAYPAL_SANDBOX_BASE_URL
from app.domain.enums import PayPalStatus
from app.domain.errors import PayPalGatewayError
from app.domain.payment import PayPalCaptureResult, PayPalOrderResult

logger = logging.getLogger("agentpay.paypal")

_MAX_SAFE_ERROR_NAME = 64


def _safe_error_name(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except (ValueError, TypeError):
        return "UNKNOWN"
    if not isinstance(payload, dict):
        return "UNKNOWN"
    name = payload.get("name")
    if not isinstance(name, str) or not name.strip():
        return "UNKNOWN"
    return name.strip()[:_MAX_SAFE_ERROR_NAME]


def _decimal(value: Any) -> Decimal | None:
    if value is None:
        return None
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return None
    return parsed


def _string(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


class PayPalClient:
    """Async PayPal REST adapter used by the payment service."""

    def __init__(
        self,
        *,
        client_id: str | None,
        client_secret: str | None,
        webhook_id: str | None = None,
        base_url: str = PAYPAL_SANDBOX_BASE_URL,
        timeout_ms: int = 15_000,
        max_retries: int = 1,
        retry_backoff_seconds: float = 0.5,
        token_skew_seconds: int = 60,
        return_url: str | None = None,
        cancel_url: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        time_source: Callable[[], float] | None = None,
        sleep: Callable[[float], Any] | None = None,
    ) -> None:
        if base_url.rstrip("/") != PAYPAL_SANDBOX_BASE_URL:
            raise ValueError("PayPal client is restricted to the sandbox base URL")
        self._client_id = client_id.strip() if client_id else None
        self._client_secret = (
            client_secret.strip() if client_secret else None
        )
        self._webhook_id = webhook_id.strip() if webhook_id else None
        self._base_url = PAYPAL_SANDBOX_BASE_URL
        self._timeout = timeout_ms / 1000.0
        self._max_retries = max_retries
        self._retry_backoff_seconds = retry_backoff_seconds
        self._token_skew_seconds = token_skew_seconds
        self._return_url = return_url
        self._cancel_url = cancel_url
        self._transport = transport
        self._time = time_source or time.monotonic
        self._sleep = sleep or asyncio.sleep
        self._client: httpx.AsyncClient | None = None
        self._access_token: str | None = None
        self._token_expires_at = 0.0

    @property
    def configured(self) -> bool:
        return bool(self._client_id and self._client_secret)

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                timeout=httpx.Timeout(self._timeout),
                headers={"Accept": "application/json"},
                transport=self._transport,
            )
        return self._client

    # ------------------------------------------------------------------
    # OAuth
    # ------------------------------------------------------------------
    async def _get_access_token(self, *, force: bool = False) -> str:
        if not self.configured:
            raise PayPalGatewayError(
                "PayPal sandbox credentials are not configured.",
                status=PayPalStatus.NOT_CONFIGURED,
            )

        now = self._time()
        if (
            not force
            and self._access_token
            and now < self._token_expires_at - self._token_skew_seconds
        ):
            return self._access_token

        assert self._client_id is not None
        assert self._client_secret is not None
        response = await self._send(
            "POST",
            "/v1/oauth2/token",
            auth=(self._client_id, self._client_secret),
            data={"grant_type": "client_credentials"},
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        if response.status_code in {400, 401, 403}:
            raise PayPalGatewayError(
                "PayPal rejected the sandbox OAuth credentials.",
                status=PayPalStatus.REJECTED,
            )
        if response.status_code >= 400:
            raise PayPalGatewayError(
                "PayPal OAuth token request failed.",
                status=PayPalStatus.PROVIDER_ERROR,
            )

        try:
            payload = response.json()
        except (ValueError, TypeError) as exc:
            raise PayPalGatewayError(
                "PayPal returned an invalid OAuth response.",
                status=PayPalStatus.INVALID_RESPONSE,
                ambiguous=True,
            ) from exc

        if not isinstance(payload, dict):
            raise PayPalGatewayError(
                "PayPal returned an invalid OAuth response.",
                status=PayPalStatus.INVALID_RESPONSE,
                ambiguous=True,
            )

        token = payload.get("access_token")
        expires_in = payload.get("expires_in")
        if not isinstance(token, str) or not token or not isinstance(
            expires_in, (int, float)
        ):
            raise PayPalGatewayError(
                "PayPal returned an invalid OAuth response.",
                status=PayPalStatus.INVALID_RESPONSE,
                ambiguous=True,
            )
        if expires_in <= 0:
            raise PayPalGatewayError(
                "PayPal returned an invalid OAuth response.",
                status=PayPalStatus.INVALID_RESPONSE,
                ambiguous=True,
            )

        self._access_token = token
        self._token_expires_at = now + float(expires_in)
        return token

    def _invalidate_token(self) -> None:
        self._access_token = None
        self._token_expires_at = 0.0

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------
    async def _send(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        last_transport_error: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                response = await self._http().request(method, path, **kwargs)
            except httpx.TimeoutException as exc:
                last_transport_error = exc
                if attempt < self._max_retries:
                    await self._sleep(
                        self._retry_backoff_seconds * (2**attempt)
                    )
                    continue
                raise PayPalGatewayError(
                    "PayPal request timed out.",
                    status=PayPalStatus.TIMEOUT,
                    ambiguous=True,
                ) from exc
            except httpx.TransportError as exc:
                last_transport_error = exc
                if attempt < self._max_retries:
                    await self._sleep(
                        self._retry_backoff_seconds * (2**attempt)
                    )
                    continue
                raise PayPalGatewayError(
                    "PayPal could not be reached.",
                    status=PayPalStatus.PROVIDER_ERROR,
                    ambiguous=True,
                ) from exc

            if response.status_code == 429 or response.status_code >= 500:
                if attempt < self._max_retries:
                    await self._sleep(
                        self._retry_backoff_seconds * (2**attempt)
                    )
                    continue
                status = (
                    PayPalStatus.RATE_LIMITED
                    if response.status_code == 429
                    else PayPalStatus.PROVIDER_ERROR
                )
                raise PayPalGatewayError(
                    "PayPal is temporarily unavailable.",
                    status=status,
                    ambiguous=True,
                )
            return response

        # Defensive: the loop always returns or raises.
        raise PayPalGatewayError(
            "PayPal could not be reached.",
            status=PayPalStatus.PROVIDER_ERROR,
            ambiguous=True,
        ) from last_transport_error

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        token = await self._get_access_token()
        headers = {"Authorization": f"Bearer {token}"}
        if extra_headers:
            headers.update(extra_headers)
        response = await self._send(method, path, headers=headers, json=json)

        if response.status_code == 401:
            # One bounded refresh attempt; never loop indefinitely.
            self._invalidate_token()
            token = await self._get_access_token(force=True)
            headers["Authorization"] = f"Bearer {token}"
            response = await self._send(
                method, path, headers=headers, json=json
            )

        if response.status_code >= 400:
            safe_name = _safe_error_name(response)
            logger.warning(
                "paypal_request_rejected",
                extra={
                    "paypal_status": PayPalStatus.REJECTED.value,
                    "error_type": safe_name,
                },
            )
            raise PayPalGatewayError(
                f"PayPal rejected the request ({safe_name}).",
                status=PayPalStatus.REJECTED,
            )

        try:
            payload = response.json()
        except (ValueError, TypeError) as exc:
            raise PayPalGatewayError(
                "PayPal returned an invalid response.",
                status=PayPalStatus.INVALID_RESPONSE,
                ambiguous=True,
            ) from exc
        if not isinstance(payload, dict):
            raise PayPalGatewayError(
                "PayPal returned an invalid response.",
                status=PayPalStatus.INVALID_RESPONSE,
                ambiguous=True,
            )
        return payload

    # ------------------------------------------------------------------
    # Orders
    # ------------------------------------------------------------------
    async def create_order(
        self,
        *,
        request_id: str,
        amount: Decimal,
        currency: str,
        custom_id: str,
        description: str,
    ) -> PayPalOrderResult:
        purchase_unit: dict[str, Any] = {
            "reference_id": custom_id,
            "custom_id": custom_id,
            "description": description[:127],
            "amount": {
                "currency_code": currency,
                "value": f"{amount:.2f}",
            },
        }
        application_context: dict[str, Any] = {
            "brand_name": "AgentPay Sentinel",
            "shipping_preference": "NO_SHIPPING",
            "user_action": "PAY_NOW",
        }
        if self._return_url:
            application_context["return_url"] = self._return_url
        if self._cancel_url:
            application_context["cancel_url"] = self._cancel_url

        payload = await self._request_json(
            "POST",
            "/v2/checkout/orders",
            json={
                "intent": "CAPTURE",
                "purchase_units": [purchase_unit],
                "application_context": application_context,
            },
            extra_headers={"PayPal-Request-Id": request_id},
        )
        return self._order_result(payload)

    async def get_order(self, order_id: str) -> PayPalOrderResult:
        payload = await self._request_json(
            "GET",
            f"/v2/checkout/orders/{quote(order_id, safe='')}",
        )
        return self._order_result(payload)

    async def capture_order(
        self,
        *,
        order_id: str,
        request_id: str,
        custom_id: str,
    ) -> PayPalCaptureResult:
        payload = await self._request_json(
            "POST",
            f"/v2/checkout/orders/{quote(order_id, safe='')}/capture",
            json={},
            extra_headers={"PayPal-Request-Id": request_id},
        )
        order = self._order_result(payload)
        if order.capture_id is None or order.capture_status is None:
            raise PayPalGatewayError(
                "PayPal capture response did not include a capture record.",
                status=PayPalStatus.INVALID_RESPONSE,
                ambiguous=True,
            )
        if order.amount is None or order.currency is None:
            raise PayPalGatewayError(
                "PayPal capture response did not include an amount.",
                status=PayPalStatus.INVALID_RESPONSE,
                ambiguous=True,
            )
        if order.order_id != order_id:
            raise PayPalGatewayError(
                "PayPal capture response referenced a different order.",
                status=PayPalStatus.INVALID_RESPONSE,
                ambiguous=True,
            )
        if order.custom_id != custom_id:
            raise PayPalGatewayError(
                "PayPal capture response was not bound to this transaction.",
                status=PayPalStatus.INVALID_RESPONSE,
                ambiguous=True,
            )
        return PayPalCaptureResult(
            order_id=order.order_id,
            capture_id=order.capture_id,
            capture_status=order.capture_status,
            order_status=order.status,
            amount=order.amount,
            currency=order.currency,
            custom_id=order.custom_id,
        )

    def _order_result(self, payload: dict[str, Any]) -> PayPalOrderResult:
        order_id = _string(payload.get("id"))
        status = _string(payload.get("status"))
        if order_id is None or status is None:
            raise PayPalGatewayError(
                "PayPal returned an incomplete order.",
                status=PayPalStatus.INVALID_RESPONSE,
                ambiguous=True,
            )

        units = payload.get("purchase_units")
        unit: dict[str, Any] = {}
        if isinstance(units, list) and units and isinstance(units[0], dict):
            unit = units[0]

        amount_data = unit.get("amount")
        amount = None
        currency = None
        if isinstance(amount_data, dict):
            amount = _decimal(amount_data.get("value"))
            currency = _string(amount_data.get("currency_code"))

        custom_id = _string(unit.get("custom_id")) or _string(
            unit.get("reference_id")
        )

        approval_url = None
        links = payload.get("links")
        if isinstance(links, list):
            for link in links:
                if not isinstance(link, dict):
                    continue
                rel = _string(link.get("rel"))
                href = _string(link.get("href"))
                if href and rel in {"approve", "payer-action"}:
                    approval_url = href
                    break

        capture_id = None
        capture_status = None
        payments = unit.get("payments")
        if isinstance(payments, dict):
            captures = payments.get("captures")
            if (
                isinstance(captures, list)
                and captures
                and isinstance(captures[0], dict)
            ):
                capture = captures[0]
                capture_id = _string(capture.get("id"))
                capture_status = _string(capture.get("status"))
                capture_amount = capture.get("amount")
                if isinstance(capture_amount, dict):
                    amount = _decimal(capture_amount.get("value")) or amount
                    currency = (
                        _string(capture_amount.get("currency_code")) or currency
                    )

        return PayPalOrderResult(
            order_id=order_id,
            status=status,
            amount=amount,
            currency=currency,
            approval_url=approval_url,
            custom_id=custom_id,
            capture_id=capture_id,
            capture_status=capture_status,
        )

    # ------------------------------------------------------------------
    # Webhooks
    # ------------------------------------------------------------------
    async def verify_webhook_signature(
        self,
        *,
        transmission_id: str,
        transmission_time: str,
        cert_url: str,
        auth_algo: str,
        transmission_sig: str,
        webhook_event: dict[str, Any],
    ) -> bool:
        if not self.configured or not self._webhook_id:
            return False
        if not all(
            (
                transmission_id,
                transmission_time,
                cert_url,
                auth_algo,
                transmission_sig,
            )
        ):
            return False

        try:
            payload = await self._request_json(
                "POST",
                "/v1/notifications/verify-webhook-signature",
                json={
                    "auth_algo": auth_algo,
                    "cert_url": cert_url,
                    "transmission_id": transmission_id,
                    "transmission_sig": transmission_sig,
                    "transmission_time": transmission_time,
                    "webhook_id": self._webhook_id,
                    "webhook_event": webhook_event,
                },
            )
        except PayPalGatewayError:
            # Any verification failure fails closed. The event is not trusted.
            return False

        return payload.get("verification_status") == "SUCCESS"


__all__ = ["PayPalClient"]
