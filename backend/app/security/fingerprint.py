"""HMAC-SHA256 intent fingerprinting.

Canonicalization covers every security-relevant, immutable intent field. JSON
is serialized with sorted keys and fixed separators; money uses exact decimal
strings and timestamps use fixed-width UTC.

The secret is held only in memory, wrapped by pydantic ``SecretStr`` in
configuration, and never returned by the API or emitted in logs.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Final

from app.domain.entities import PurchaseIntent
from app.domain.errors import ConfigurationFailure
from app.domain.money import money_to_storage
from app.domain.time import canonical_timestamp

CANONICAL_VERSION: Final[int] = 1
MIN_SECRET_BYTES: Final[int] = 32
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class FingerprintService:
    """Creates and verifies HMAC-SHA256 intent fingerprints."""

    def __init__(self, secret: str | None) -> None:
        self._configuration_error: str | None = None
        self._secret = self._validate_secret(secret)

    @property
    def configured(self) -> bool:
        return self._secret is not None

    @property
    def configuration_error(self) -> str | None:
        """Safe diagnostic text. Never contains the secret."""

        return self._configuration_error

    def _validate_secret(self, secret: str | None) -> bytes | None:
        if secret is None or not secret.strip():
            self._configuration_error = "HMAC secret is not configured"
            return None
        if secret != secret.strip():
            self._configuration_error = (
                "HMAC secret must not contain leading or trailing whitespace"
            )
            return None
        if len(secret.encode("utf-8")) < MIN_SECRET_BYTES:
            self._configuration_error = (
                f"HMAC secret must be at least {MIN_SECRET_BYTES} bytes"
            )
            return None
        return secret.encode("utf-8")

    def _require_secret(self) -> bytes:
        if self._secret is None:
            raise ConfigurationFailure(
                "Security configuration is invalid; fingerprint operations are disabled"
            )
        return self._secret

    @staticmethod
    def canonical_payload(intent: PurchaseIntent) -> bytes:
        """Canonical JSON bytes over all security-relevant intent fields."""

        payload = {
            "canonical_version": CANONICAL_VERSION,
            "intent_id": str(intent.intent_id),
            "user_id": intent.user_id,
            "purpose": intent.purpose,
            "merchant_id": intent.merchant_id,
            "product_category": intent.product_category,
            "max_amount": money_to_storage(intent.max_amount),
            "currency": intent.currency,
            "max_quantity": intent.max_quantity,
            "require_approval": intent.require_approval,
            "created_at": canonical_timestamp(intent.created_at),
            "expires_at": canonical_timestamp(intent.expires_at),
        }
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def fingerprint_intent(self, intent: PurchaseIntent) -> str:
        """Return a lowercase hex HMAC-SHA256 fingerprint."""

        secret = self._require_secret()
        return hmac.new(
            secret,
            self.canonical_payload(intent),
            hashlib.sha256,
        ).hexdigest()

    def verify_intent(self, intent: PurchaseIntent) -> bool:
        """Constant-time verification of a stored intent fingerprint.

        Invalid or missing stored fingerprints fail verification. A missing
        server secret raises ConfigurationFailure so callers fail closed.
        """

        secret = self._require_secret()
        stored = intent.fingerprint
        if not stored or not _HEX_DIGEST.fullmatch(stored):
            return False
        expected = hmac.new(
            secret,
            self.canonical_payload(intent),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(stored, expected)
