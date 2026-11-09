"""UTC timestamp helpers.

All timestamps in AgentPay Sentinel are timezone-aware UTC values. Naive
datetimes are rejected rather than guessed at.
"""

from __future__ import annotations

from datetime import UTC, datetime


def ensure_utc(value: datetime) -> datetime:
    """Return a timezone-aware UTC datetime.

    Raises:
        ValueError: if the value is naive or has no UTC offset.
    """

    if not isinstance(value, datetime):
        raise ValueError("timestamp must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC)


def utc_now() -> datetime:
    """Current time as an aware UTC datetime."""

    return datetime.now(UTC)


def canonical_timestamp(value: datetime) -> str:
    """Stable UTC representation used for HMAC canonicalization."""

    utc_value = ensure_utc(value)
    return utc_value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
