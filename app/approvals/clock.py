"""Injectable UTC clock for deterministic approval deadline tests."""

from datetime import datetime, timezone
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class UtcClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)
