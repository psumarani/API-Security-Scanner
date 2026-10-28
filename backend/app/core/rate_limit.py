"""Small in-memory sliding-window rate limiter.

Limits are per process. That is adequate for a single-instance deployment; a multi-instance
deployment would need a shared store, which is intentionally out of scope for this project.
"""

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable

from fastapi import Request

from app.core.config import get_settings
from app.core.errors import RateLimitExceeded


class SlidingWindowLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._clock = clock

    def _prune(self, key: str, window: float, now: float) -> deque[float]:
        events = self._events[key]
        while events and events[0] <= now - window:
            events.popleft()
        if not events:
            self._events.pop(key, None)
            return deque()
        return events

    def hit(self, key: str, limit: int, window: float) -> bool:
        """Record an event. Returns False if the limit was already reached (event not recorded)."""
        with self._lock:
            now = self._clock()
            events = self._prune(key, window, now)
            if len(events) >= limit:
                return False
            self._events[key].append(now)
            return True

    def count(self, key: str, window: float) -> int:
        with self._lock:
            return len(self._prune(key, window, self._clock()))

    def retry_after(self, key: str, window: float) -> int:
        with self._lock:
            now = self._clock()
            events = self._prune(key, window, now)
            if not events:
                return 1
            return max(1, int(events[0] + window - now) + 1)

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._events.clear()
            else:
                self._events.pop(key, None)


limiter = SlidingWindowLimiter()


def client_ip(request: Request) -> str:
    """Peer address. Forwarded headers are deliberately ignored: they are client-controlled."""
    return request.client.host if request.client else "unknown"


def _enforce(key: str, limit: int, window: float, message: str) -> None:
    if not limiter.hit(key, limit, window):
        raise RateLimitExceeded(
            message, headers={"Retry-After": str(limiter.retry_after(key, window))}
        )


def login_rate_limit(request: Request) -> None:
    settings = get_settings()
    _enforce(
        f"login-ip:{client_ip(request)}",
        settings.auth_rate_limit_login_per_minute,
        60,
        "Too many login attempts. Try again later.",
    )


def register_rate_limit(request: Request) -> None:
    settings = get_settings()
    _enforce(
        f"register-ip:{client_ip(request)}",
        settings.auth_rate_limit_register_per_minute,
        60,
        "Too many registration attempts. Try again later.",
    )
