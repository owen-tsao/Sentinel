"""Exact-request confirmation fingerprinting and local token store."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from uuid import uuid4

from sentinel.decision.policy import CONFIRMABLE_VERDICTS
from sentinel.decision.rules import Verdict

ConfirmationIdFactory = Callable[[], str]
TokenFactory = Callable[[], str]
Clock = Callable[[], datetime]

DEFAULT_PENDING_TTL = timedelta(minutes=15)
DEFAULT_TOKEN_TTL = timedelta(minutes=5)
DEFAULT_MAX_PENDING_CONFIRMATIONS = 1_000
DEFAULT_MAX_TOKENS = 1_000


@dataclass(frozen=True)
class ConfirmationRequest:
    context: str
    command: str
    environment: str
    shell_type: str
    recent_actions: list[dict[str, Any]]
    session_id: str
    agent_id: str
    user_id: str


@dataclass(frozen=True)
class PendingConfirmation:
    confirmation_id: str
    fingerprint: str
    request: ConfirmationRequest
    verdict: Verdict
    created_at: datetime


@dataclass(frozen=True)
class ConfirmationToken:
    token: str
    confirmation_id: str
    fingerprint: str
    issued_at: datetime
    consumed_at: datetime | None = None


class InMemoryConfirmationStore:
    """Local Week 7 approval store.

    This is intentionally process-local. It gives the API a safe contract for
    exact request approval before adding persistence or signed tokens later.
    """

    def __init__(
        self,
        *,
        confirmation_id_factory: ConfirmationIdFactory | None = None,
        token_factory: TokenFactory | None = None,
        clock: Clock | None = None,
        pending_ttl: timedelta = DEFAULT_PENDING_TTL,
        token_ttl: timedelta = DEFAULT_TOKEN_TTL,
        max_pending_confirmations: int = DEFAULT_MAX_PENDING_CONFIRMATIONS,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> None:
        if pending_ttl <= timedelta(0):
            raise ValueError("pending_ttl must be positive")
        if token_ttl <= timedelta(0):
            raise ValueError("token_ttl must be positive")
        if max_pending_confirmations <= 0:
            raise ValueError("max_pending_confirmations must be positive")
        if max_tokens <= 0:
            raise ValueError("max_tokens must be positive")

        self._confirmation_id_factory = confirmation_id_factory or _new_confirmation_id
        self._token_factory = token_factory or _new_token
        self._clock = clock or _utc_now
        self._pending_ttl = pending_ttl
        self._token_ttl = token_ttl
        self._max_pending_confirmations = max_pending_confirmations
        self._max_tokens = max_tokens
        self._pending_by_id: dict[str, PendingConfirmation] = {}
        self._tokens_by_value: dict[str, ConfirmationToken] = {}
        # Endpoints run on a thread pool. Every read-modify-write path shares the
        # same lock so approvals, expiry, eviction, and one-use consumption are atomic.
        self._lock = threading.Lock()

    def create_pending(self, request: ConfirmationRequest, verdict: Verdict) -> PendingConfirmation:
        if verdict not in CONFIRMABLE_VERDICTS:
            raise ValueError(f"verdict is not confirmable: {verdict}")

        with self._lock:
            now = self._now()
            self._purge_expired(now)
            self._evict_oldest(self._pending_by_id, self._max_pending_confirmations)
            pending = PendingConfirmation(
                confirmation_id=self._confirmation_id_factory(),
                fingerprint=fingerprint_confirmation_request(request),
                request=request,
                verdict=verdict,
                created_at=now,
            )
            self._pending_by_id[pending.confirmation_id] = pending
            return pending

    def get_pending(self, confirmation_id: str) -> PendingConfirmation | None:
        with self._lock:
            self._purge_expired(self._now())
            return self._pending_by_id.get(confirmation_id)

    def approve(self, confirmation_id: str) -> ConfirmationToken | None:
        with self._lock:
            now = self._now()
            self._purge_expired(now)
            pending = self._pending_by_id.pop(confirmation_id, None)
            if pending is None:
                return None

            self._evict_oldest(self._tokens_by_value, self._max_tokens)
            token = ConfirmationToken(
                token=self._token_factory(),
                confirmation_id=pending.confirmation_id,
                fingerprint=pending.fingerprint,
                issued_at=now,
            )
            self._tokens_by_value[token.token] = token
            return token

    def consume_token(self, token_value: str, request: ConfirmationRequest) -> bool:
        request_fingerprint = fingerprint_confirmation_request(request)
        with self._lock:
            self._purge_expired(self._now())
            token = self._tokens_by_value.get(token_value)
            if token is None:
                return False
            if not hmac.compare_digest(token.fingerprint, request_fingerprint):
                # Mismatched fingerprint does not burn the token: the approved
                # exact request should still be executable after a bad attempt.
                return False
            del self._tokens_by_value[token_value]
            return True

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("confirmation clock must return a timezone-aware datetime")
        return now

    def _purge_expired(self, now: datetime) -> None:
        expired_pending = [
            confirmation_id
            for confirmation_id, pending in self._pending_by_id.items()
            if now >= pending.created_at + self._pending_ttl
        ]
        for confirmation_id in expired_pending:
            del self._pending_by_id[confirmation_id]

        expired_tokens = [
            token_value
            for token_value, token in self._tokens_by_value.items()
            if now >= token.issued_at + self._token_ttl
        ]
        for token_value in expired_tokens:
            del self._tokens_by_value[token_value]

    @staticmethod
    def _evict_oldest(items: dict[str, Any], capacity: int) -> None:
        while len(items) >= capacity:
            del items[next(iter(items))]


def fingerprint_confirmation_request(request: ConfirmationRequest) -> str:
    """Return a stable digest for the exact request a human approved."""

    payload = {
        "agent_id": request.agent_id,
        "command": request.command,
        "context": request.context,
        "environment": request.environment,
        "recent_actions": request.recent_actions,
        "session_id": request.session_id,
        "shell_type": request.shell_type,
        "user_id": request.user_id,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _new_confirmation_id() -> str:
    return str(uuid4())


def _new_token() -> str:
    return secrets.token_urlsafe(32)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)
