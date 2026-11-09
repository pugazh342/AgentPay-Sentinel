"""Optional live PayPal **sandbox** connectivity test.

This test is skipped unless the operator explicitly opts in:

    AGENTPAY_RUN_PAYPAL_LIVE=1

and the sandbox client ID/secret are configured (see ``.env.example``).

It performs only order creation and order lookup. It deliberately never
captures, so no money moves even in the sandbox.
"""

from __future__ import annotations

import asyncio
import os
from decimal import Decimal
from uuid import uuid4

import pytest

from app.config import Settings
from app.paypal.client import PayPalClient

pytestmark = pytest.mark.skipif(
    os.environ.get("AGENTPAY_RUN_PAYPAL_LIVE") != "1",
    reason=(
        "Live PayPal sandbox test requires explicit opt-in via "
        "AGENTPAY_RUN_PAYPAL_LIVE=1"
    ),
)


def test_sandbox_order_creation_and_lookup_without_capture() -> None:
    settings = Settings()
    if not settings.paypal_configured:
        pytest.skip("PayPal sandbox credentials are not configured")

    custom_id = str(uuid4())

    async def main() -> None:
        client = PayPalClient(
            client_id=settings.paypal_client_id_value,
            client_secret=settings.paypal_client_secret_value,
            webhook_id=settings.paypal_webhook_id_value,
            base_url=settings.paypal_base_url,
            timeout_ms=settings.paypal_timeout_ms,
            max_retries=settings.paypal_max_retries,
            retry_backoff_seconds=settings.paypal_retry_backoff_seconds,
            token_skew_seconds=settings.paypal_token_skew_seconds,
            return_url=settings.paypal_return_url,
            cancel_url=settings.paypal_cancel_url,
        )
        try:
            created = await client.create_order(
                request_id=f"agentpay-live-{custom_id}",
                amount=Decimal("1.00"),
                currency="USD",
                custom_id=custom_id,
                description="AgentPay Sentinel sandbox connectivity test",
            )
            assert created.order_id
            assert created.approval_url is not None
            assert created.amount == Decimal("1.00")
            assert created.currency == "USD"
            assert created.custom_id == custom_id

            looked_up = await client.get_order(created.order_id)
            assert looked_up.order_id == created.order_id
            assert looked_up.custom_id == custom_id
            assert looked_up.amount == Decimal("1.00")
            assert looked_up.currency == "USD"

            # No capture is attempted. The sandbox order remains unapproved and
            # will expire; no funds can move from this test.
        finally:
            await client.aclose()

    asyncio.run(main())
