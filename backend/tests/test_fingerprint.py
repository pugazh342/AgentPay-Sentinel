"""HMAC fingerprint canonicalization, determinism and tamper tests."""

from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

import pytest

from app.domain.entities import PurchaseIntent
from app.domain.errors import ConfigurationFailure
from app.logging_config import JsonFormatter
from app.security.fingerprint import MIN_SECRET_BYTES, FingerprintService

SECRET = "fingerprint-test-secret-0123456789abcdef"
NOW = datetime(2026, 1, 10, 9, 30, 0, tzinfo=UTC)


def _intent() -> PurchaseIntent:
    return PurchaseIntent(
        intent_id=uuid4(),
        user_id="user_1",
        purpose="Buy running shoes",
        merchant_id="merchant_1",
        product_category="footwear",
        max_amount=Decimal("800.00"),
        currency="USD",
        max_quantity=1,
        require_approval=True,
        created_at=NOW,
        expires_at=NOW + timedelta(hours=2),
    )


def _signed_intent() -> tuple[PurchaseIntent, FingerprintService]:
    service = FingerprintService(SECRET)
    intent = _intent()
    return replace(intent, fingerprint=service.fingerprint_intent(intent)), service


def test_fingerprint_is_hmac_sha256_hex() -> None:
    intent, service = _signed_intent()

    expected = hmac.new(
        SECRET.encode(),
        FingerprintService.canonical_payload(intent),
        hashlib.sha256,
    ).hexdigest()

    assert intent.fingerprint == expected
    assert len(intent.fingerprint) == 64
    assert service.verify_intent(intent) is True


def test_canonical_payload_is_deterministic() -> None:
    intent, _ = _signed_intent()

    first = FingerprintService.canonical_payload(intent)
    second = FingerprintService.canonical_payload(intent)

    assert first == second
    assert b'"max_amount":"800.00"' in first
    assert b'"currency":"USD"' in first
    assert b"fingerprint" not in first


def test_verification_uses_constant_time_comparison(monkeypatch) -> None:
    intent, service = _signed_intent()
    calls: list[tuple[str, str]] = []

    def fake_compare_digest(left: str, right: str) -> bool:
        calls.append((left, right))
        return left == right

    monkeypatch.setattr("app.security.fingerprint.hmac.compare_digest", fake_compare_digest)

    assert service.verify_intent(intent) is True
    assert calls and calls[0][0] == intent.fingerprint


@pytest.mark.parametrize(
    ("field", "tampered_value"),
    [
        ("intent_id", uuid4()),
        ("user_id", "attacker"),
        ("purpose", "Tampered purpose"),
        ("merchant_id", "attacker_merchant"),
        ("product_category", "electronics"),
        ("max_amount", Decimal("1200.00")),
        ("currency", "EUR"),
        ("max_quantity", 5),
        ("require_approval", False),
    ],
)
def test_every_security_field_tamper_invalidates_fingerprint(
    field: str, tampered_value: object
) -> None:
    intent, service = _signed_intent()
    tampered = replace(intent, **{field: tampered_value})

    assert service.verify_intent(tampered) is False


def test_timestamp_tamper_invalidates_fingerprint() -> None:
    intent, service = _signed_intent()

    assert service.verify_intent(
        replace(intent, created_at=intent.created_at + timedelta(seconds=1))
    ) is False
    assert service.verify_intent(
        replace(intent, expires_at=intent.expires_at + timedelta(seconds=1))
    ) is False


@pytest.mark.parametrize(
    "stored",
    ["", "0" * 64, "f" * 63, "z" * 64, "F" * 64, None],
)
def test_missing_or_malformed_stored_fingerprint_fails(stored: object) -> None:
    intent, service = _signed_intent()
    tampered = replace(intent, fingerprint=stored)  # type: ignore[arg-type]

    assert service.verify_intent(tampered) is False


@pytest.mark.parametrize(
    "secret",
    [
        None,
        "",
        "   ",
        "x" * (MIN_SECRET_BYTES - 1),
        " " + "x" * MIN_SECRET_BYTES,
        "x" * MIN_SECRET_BYTES + " ",
    ],
)
def test_invalid_secret_fails_closed(secret: str | None) -> None:
    service = FingerprintService(secret)

    assert service.configured is False
    assert service.configuration_error is not None
    with pytest.raises(ConfigurationFailure):
        service.fingerprint_intent(_intent())
    with pytest.raises(ConfigurationFailure):
        service.verify_intent(_intent())


def test_minimum_length_secret_is_accepted() -> None:
    service = FingerprintService("x" * MIN_SECRET_BYTES)

    assert service.configured is True
    assert service.configuration_error is None
    assert len(service.fingerprint_intent(_intent())) == 64


def test_structured_log_formatter_drops_unlisted_secret_fields() -> None:
    record = logging.LogRecord(
        name="agentpay.security",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="security_event",
        args=(),
        exc_info=None,
    )
    record.hmac_secret = SECRET
    record.reason_codes = ["ALL_CHECKS_PASSED"]

    formatted = JsonFormatter().format(record)

    assert SECRET not in formatted
    assert "ALL_CHECKS_PASSED" in formatted
