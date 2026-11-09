"""Clock port and production implementation."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from app.domain.time import utc_now


class Clock(Protocol):
    """Injectable time source used by authorization logic and tests."""

    def now(self) -> datetime:
        """Return the current aware UTC datetime."""


class SystemClock:
    """Production clock."""

    def now(self) -> datetime:
        return utc_now()
