"""One-use browser pairing and process-local control sessions."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

Clock = Callable[[], datetime]
TokenFactory = Callable[[], str]


class PairingError(ValueError):
    """Pairing or control-session validation failed closed."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class IssuedControlSession:
    """The raw cookie value returned once to the protected HTTP route."""

    token: str
    absolute_expires_at: datetime


@dataclass(frozen=True)
class AuthenticatedControlSession:
    """Non-secret session metadata safe for internal authorization decisions."""

    created_at: datetime
    last_seen_at: datetime
    absolute_expires_at: datetime


@dataclass(frozen=True)
class _StoredControlSession:
    token_sha256: bytes
    created_at: datetime
    last_seen_at: datetime
    absolute_expires_at: datetime


def generate_pairing_capability() -> str:
    """Generate a capability with 256 bits of cryptographic randomness."""

    return secrets.token_urlsafe(32)


class PairingService:
    """Exchange one short-lived capability for one HttpOnly browser session."""

    def __init__(
        self,
        pairing_capability: str,
        *,
        clock: Clock | None = None,
        session_token_factory: TokenFactory | None = None,
        pairing_ttl: timedelta = timedelta(minutes=5),
        inactivity_ttl: timedelta = timedelta(minutes=30),
        absolute_ttl: timedelta = timedelta(hours=8),
    ) -> None:
        if not 32 <= len(pairing_capability) <= 512:
            raise ValueError("pairing capability must contain 32-512 characters")
        if (
            pairing_ttl <= timedelta(0)
            or inactivity_ttl <= timedelta(0)
            or absolute_ttl <= timedelta(0)
        ):
            raise ValueError("pairing and session TTLs must be positive")
        if inactivity_ttl > absolute_ttl:
            raise ValueError("inactivity TTL cannot exceed absolute TTL")

        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._session_token_factory = session_token_factory or (
            lambda: secrets.token_urlsafe(32)
        )
        self._pairing_capability_sha256: bytes | None = _digest(
            pairing_capability
        )
        self._pairing_expires_at = self._now() + pairing_ttl
        self._inactivity_ttl = inactivity_ttl
        self._absolute_ttl = absolute_ttl
        self._session: _StoredControlSession | None = None
        self._lock = threading.Lock()

    def exchange(self, capability: str) -> IssuedControlSession:
        """Consume the exact capability and return a new raw cookie value once."""

        candidate_digest = _digest(capability)
        with self._lock:
            now = self._now()
            stored_digest = self._pairing_capability_sha256
            comparable = stored_digest or bytes(hashlib.sha256().digest_size)
            matches = hmac.compare_digest(comparable, candidate_digest)
            if (
                stored_digest is None
                or now >= self._pairing_expires_at
                or not matches
            ):
                raise PairingError("control:pairing_invalid_or_expired")

            raw_session = self._session_token_factory()
            if not 32 <= len(raw_session) <= 512:
                raise PairingError("control:session_generation_failed")
            absolute_expires_at = now + self._absolute_ttl
            self._session = _StoredControlSession(
                token_sha256=_digest(raw_session),
                created_at=now,
                last_seen_at=now,
                absolute_expires_at=absolute_expires_at,
            )
            self._pairing_capability_sha256 = None
            return IssuedControlSession(
                token=raw_session,
                absolute_expires_at=absolute_expires_at,
            )

    def authenticate(self, session_token: str | None) -> AuthenticatedControlSession:
        """Validate and refresh the paired session without retaining its raw token."""

        candidate_digest = _digest(session_token or "")
        with self._lock:
            now = self._now()
            stored = self._session
            comparable = (
                stored.token_sha256
                if stored is not None
                else bytes(hashlib.sha256().digest_size)
            )
            matches = hmac.compare_digest(comparable, candidate_digest)
            if (
                stored is None
                or not matches
                or now >= stored.absolute_expires_at
                or now >= stored.last_seen_at + self._inactivity_ttl
            ):
                if stored is not None and (
                    now >= stored.absolute_expires_at
                    or now >= stored.last_seen_at + self._inactivity_ttl
                ):
                    self._session = None
                raise PairingError("control:session_invalid_or_expired")

            refreshed = _StoredControlSession(
                token_sha256=stored.token_sha256,
                created_at=stored.created_at,
                last_seen_at=now,
                absolute_expires_at=stored.absolute_expires_at,
            )
            self._session = refreshed
            return _public_session(refreshed)

    def logout(self, session_token: str | None) -> bool:
        """Invalidate the current session when the exact cookie is presented."""

        candidate_digest = _digest(session_token or "")
        with self._lock:
            stored = self._session
            comparable = (
                stored.token_sha256
                if stored is not None
                else bytes(hashlib.sha256().digest_size)
            )
            matches = hmac.compare_digest(comparable, candidate_digest)
            if stored is None or not matches:
                return False
            self._session = None
            return True

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("pairing clock must return a timezone-aware datetime")
        return now.astimezone(timezone.utc)


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def _public_session(
    session: _StoredControlSession,
) -> AuthenticatedControlSession:
    return AuthenticatedControlSession(
        created_at=session.created_at,
        last_seen_at=session.last_seen_at,
        absolute_expires_at=session.absolute_expires_at,
    )
