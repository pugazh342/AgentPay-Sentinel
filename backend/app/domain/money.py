"""Exact monetary helpers.

Money is always represented as ``decimal.Decimal``. Floats are never accepted
for financial calculations or persistence.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation

MONEY_EXPONENT = Decimal("0.01")
SUPPORTED_CURRENCIES = frozenset({"USD", "EUR", "GBP", "CAD", "AUD"})


def normalize_money(value: Decimal) -> Decimal:
    """Validate and normalize a positive monetary value to two decimal places.

    The value must be finite, strictly positive and have no fractional digits
    beyond cents. Values are never silently rounded.
    """

    if not isinstance(value, Decimal):
        raise ValueError("amount must be a Decimal")
    if not value.is_finite():
        raise ValueError("amount must be finite")
    if value <= 0:
        raise ValueError("amount must be greater than zero")
    if value.as_tuple().exponent < -2:
        raise ValueError("amount must not have more than two decimal places")
    try:
        return value.quantize(MONEY_EXPONENT)
    except InvalidOperation as exc:  # pragma: no cover - guarded by max_digits
        raise ValueError("amount is outside the supported range") from exc


def money_to_storage(value: Decimal) -> str:
    """Serialize money as an exact decimal string for SQLite persistence."""

    return format(normalize_money(value), "f")


def money_from_storage(value: str) -> Decimal:
    """Parse a decimal string from persistence without using float."""

    try:
        parsed = Decimal(value)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError("stored amount is not a valid decimal") from exc
    return normalize_money(parsed)


def normalize_currency(value: str) -> str:
    """Validate and canonicalize a supported ISO-style currency code."""

    if not isinstance(value, str):
        raise ValueError("currency must be a string")
    code = value.strip().upper()
    if code not in SUPPORTED_CURRENCIES:
        raise ValueError(
            "unsupported currency; supported codes are "
            + ", ".join(sorted(SUPPORTED_CURRENCIES))
        )
    return code
