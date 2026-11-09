"""Optional live-Gemini adversarial evaluation (never part of standard CI).

Standard test runs skip this module. To execute it deliberately:

    AGENTPAY_RUN_GEMINI_ADVERSARIAL=1
    GEMINI_API_KEY=...   (or AGENTPAY_GEMINI_API_KEY)

The test only exercises the advisory analysis provider. It never creates a
PayPal order, captures a payment, or asserts that the model refuses an attack;
deterministic-policy guarantees are covered by the offline scenarios.
"""

from __future__ import annotations

import os
from decimal import Decimal
from uuid import uuid4

import pytest

from app.ai.gemini_provider import GeminiThreatProvider
from app.domain.threat import ThreatAnalysisInput
from tests.adversarial.ai_fixtures import get_fixture

pytestmark = pytest.mark.skipif(
    os.environ.get("AGENTPAY_RUN_GEMINI_ADVERSARIAL") != "1"
    or not (os.getenv("GEMINI_API_KEY") or os.getenv("AGENTPAY_GEMINI_API_KEY")),
    reason=(
        "Live adversarial Gemini evaluation requires explicit opt-in via "
        "AGENTPAY_RUN_GEMINI_ADVERSARIAL=1 and a configured API key"
    ),
)


LIVE_FIXTURES = ("AI-FX-DIRECT-001", "AI-FX-INDIRECT-001")


@pytest.mark.parametrize("fixture_id", LIVE_FIXTURES)
def test_live_gemini_returns_validated_structured_assessment(
    fixture_id: str,
) -> None:
    fixture = get_fixture(fixture_id)
    provider = GeminiThreatProvider(
        api_key=os.getenv("GEMINI_API_KEY")
        or os.getenv("AGENTPAY_GEMINI_API_KEY"),
        model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
        timeout_ms=30_000,
        max_retries=1,
        retry_backoff_seconds=1.0,
    )
    result = provider.analyze(
        ThreatAnalysisInput(
            transaction_id=uuid4(),
            purpose="Purchase one pair of running shoes",
            authorized_category="footwear",
            merchant_id="merchant_shoes",
            amount=Decimal("800.00"),
            currency="USD",
            quantity=1,
            product_description=fixture.text,
        )
    )

    assert result.provider_status.value == "OK"
    assert result.payload is not None
    assert 0 <= result.payload.risk_score <= 100
