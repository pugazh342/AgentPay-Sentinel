"""Optional live Gemini smoke test.

Skipped unless GEMINI_API_KEY is present. Normal unit tests never call Gemini.
"""

from __future__ import annotations

import os
from decimal import Decimal
from uuid import uuid4

import pytest

from app.ai.gemini_provider import GeminiThreatProvider
from app.domain.enums import ProviderStatus
from app.domain.threat import ThreatAnalysisInput

pytestmark = pytest.mark.skipif(
    not os.getenv("GEMINI_API_KEY"),
    reason="GEMINI_API_KEY is not configured",
)


def test_live_gemini_returns_structured_assessment() -> None:
    provider = GeminiThreatProvider(
        api_key=os.environ["GEMINI_API_KEY"],
        model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
        timeout_ms=30_000,
        max_retries=1,
        retry_backoff_seconds=1.0,
    )
    analysis_input = ThreatAnalysisInput(
        transaction_id=uuid4(),
        purpose="Purchase one pair of running shoes",
        authorized_category="footwear",
        merchant_id="merchant_shoes",
        amount=Decimal("80.00"),
        currency="USD",
        quantity=1,
        product_title="Trail running shoes",
        product_description="Lightweight neutral running shoes.",
        merchant_name="Example Shoes",
        agent_reasoning="Matches the authorized footwear category.",
        transaction_context="One pair within the authorized maximum.",
    )

    result = provider.analyze(analysis_input)

    assert result.provider_status is ProviderStatus.OK
    assert result.payload is not None
    assert 0 <= result.payload.risk_score <= 100
