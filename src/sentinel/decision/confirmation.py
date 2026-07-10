"""Exact-request confirmation fingerprinting and local token store."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from sentinel.decision.policy import CONFIRMABLE_VERDICTS
from sentinel.decision.rules import Verdict

ConfirmationIdFactory = Callable[[], str]
TokenFactory = Callable[[], str]


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
    ) -> None:
        self._confirmation_id_factory = confirmation_id_factory or _new_confirmation_id
        self._token_factory = token_factory or _new_token
        self._pending_by_id: dict[str, PendingConfirmation] = {}
        self._tokens_by_value: dict[str, ConfirmationToken] = {}
        # Endpoints run on a thread pool, so token consumption must be atomic to
        # prevent a one-use token from being spent twice by concurrent requests.
        self._lock = threading.Lock()

    def create_pending(self, request: ConfirmationRequest, verdict: Verdict) -> PendingConfirmation:
        if verdict not in CONFIRMABLE_VERDICTS:
            raise ValueError(f"verdict is not confirmable: {verdict}")

        pending = PendingConfirmation(
            confirmation_id=self._confirmation_id_factory(),
            fingerprint=fingerprint_confirmation_request(request),
            request=request,
            verdict=verdict,
            created_at=_utc_now(),
        )
        self._pending_by_id[pending.confirmation_id] = pending
        return pending

    def get_pending(self, confirmation_id: str) -> PendingConfirmation | None:
        return self._pending_by_id.get(confirmation_id)

    def approve(self, confirmation_id: str) -> ConfirmationToken | None:
        pending = self._pending_by_id.pop(confirmation_id, None)
        if pending is None:
            return None

        token = ConfirmationToken(
            token=self._token_factory(),
            confirmation_id=pending.confirmation_id,
            fingerprint=pending.fingerprint,
            issued_at=_utc_now(),
        )
        self._tokens_by_value[token.token] = token
        return token

    def consume_token(self, token_value: str, request: ConfirmationRequest) -> bool:
        request_fingerprint = fingerprint_confirmation_request(request)
        with self._lock:
            token = self._tokens_by_value.get(token_value)
            if token is None:
                return False
            if not hmac.compare_digest(token.fingerprint, request_fingerprint):
                # Mismatched fingerprint does not burn the token: the approved
                # exact request should still be executable after a bad attempt.
                return False
            del self._tokens_by_value[token_value]
            return True


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
