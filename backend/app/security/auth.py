"""Single-operator authentication primitives for hackathon demo.

Stateless signed session cookie + double-submit CSRF token.
No plaintext password storage; verification against PBKDF2-SHA256 hash from env.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any

SESSION_COOKIE = "aps_session"
CSRF_COOKIE = "aps_csrf"
CSRF_HEADER = "x-csrf-token"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def hash_password(password: str, *, iterations: int = 260_000) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return (
        f"pbkdf2_sha256${iterations}${_b64url_encode(salt)}${_b64url_encode(dk)}"
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, iter_s, salt_s, dk_s = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iter_s)
        salt = _b64url_decode(salt_s)
        expected = _b64url_decode(dk_s)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def _sign(payload_b64: str, secret: str) -> str:
    sig = hmac.new(secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).digest()
    return _b64url_encode(sig)


def create_session_token(*, username: str, secret: str, ttl_seconds: int) -> str:
    now = int(time.time())
    payload = {"sub": username, "iat": now, "exp": now + ttl_seconds, "nonce": secrets.token_hex(8)}
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    return f"{payload_b64}.{_sign(payload_b64, secret)}"


def verify_session_token(token: str, secret: str) -> dict[str, Any] | None:
    try:
        payload_b64, sig = token.rsplit(".", 1)
        expected = _sign(payload_b64, secret)
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(_b64url_decode(payload_b64))
        if not isinstance(payload, dict):
            return None
        exp = int(payload.get("exp", 0))
        if exp < int(time.time()):
            return None
        sub = payload.get("sub")
        if not isinstance(sub, str) or not sub:
            return None
        return payload
    except Exception:
        return None


def create_csrf_token(secret: str) -> str:
    raw = secrets.token_urlsafe(32)
    return f"{raw}.{_sign(raw, secret)}"


def verify_csrf_token(token: str, secret: str) -> bool:
    try:
        raw, sig = token.rsplit(".", 1)
        expected = _sign(raw, secret)
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False


@dataclass
class LoginRateLimiter:
    max_attempts: int = 5
    window_seconds: int = 300

    def __post_init__(self) -> None:
        self._events: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            events = [t for t in self._events.get(key, []) if t >= cutoff]
            if len(events) >= self.max_attempts:
                self._events[key] = events
                return False
            events.append(now)
            self._events[key] = events
            return True

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)