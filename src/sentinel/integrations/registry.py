"""Server-owned adapter session registry.

One adapter session exists per adapter kind for the single supervision
session. Only the SHA-256 of the capability is kept; comparison is constant
time; every restart or explicit rotation invalidates the previous capability.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from .models import (
    CURSOR_WEEK12_PROFILE,
    AdapterSession,
    AgentConnection,
    CapabilityProfile,
    IssuedAdapterCapability,
)


class AdapterSessionError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class AdapterSessionRegistry:
    """Process-local registry; nothing here survives a restart by design."""

    def __init__(
        self,
        *,
        supervision_session_id: str,
        profile: CapabilityProfile = CURSOR_WEEK12_PROFILE,
        default_lifetime: timedelta = timedelta(hours=8),
    ) -> None:
        if default_lifetime <= timedelta(0):
            raise ValueError("default_lifetime must be positive")
        self._supervision_session_id = supervision_session_id
        self._profile = profile
        self._default_lifetime = default_lifetime
        self._sessions: dict[str, AdapterSession] = {}
        self._current: dict[str, str] = {}
        self._connection = AgentConnection(host=profile.host)
        self._lock = threading.Lock()

    @property
    def profile(self) -> CapabilityProfile:
        return self._profile

    @property
    def connection(self) -> AgentConnection:
        with self._lock:
            return AgentConnection(**vars(self._connection))

    def issue(
        self,
        *,
        adapter_kind: str,
        tool_family: str,
        lifetime: timedelta | None = None,
        now: datetime | None = None,
    ) -> IssuedAdapterCapability:
        """Issue or rotate the one capability for this adapter kind."""

        issued_at = now or datetime.now(timezone.utc)
        capability = secrets.token_urlsafe(32)
        session = AdapterSession(
            adapter_session_id=str(uuid4()),
            adapter_kind=adapter_kind,
            tool_family=tool_family,
            supervision_session_id=self._supervision_session_id,
            capability_sha256=_sha256(capability),
            issued_at=issued_at,
            expires_at=issued_at + (lifetime or self._default_lifetime),
        )
        with self._lock:
            current_id = self._current.get(adapter_kind)
            if current_id is not None:
                previous = self._sessions[current_id]
                if previous.revoked_at is None:
                    self._sessions[current_id] = AdapterSession(
                        **{**vars(previous), "revoked_at": issued_at}
                    )
            self._sessions[session.adapter_session_id] = session
            self._current[adapter_kind] = session.adapter_session_id
        return IssuedAdapterCapability(capability=capability, session=session)

    def revoke(self, adapter_kind: str, *, now: datetime | None = None) -> None:
        with self._lock:
            current_id = self._current.get(adapter_kind)
            current = self._sessions.get(current_id) if current_id else None
            if current is not None and current.revoked_at is None:
                self._sessions[current_id] = AdapterSession(
                    **{**vars(current), "revoked_at": now or datetime.now(timezone.utc)}
                )
                self._connection.status = "disconnected"

    def authenticate(self, bearer: str | None, *, now: datetime | None = None) -> AdapterSession:
        """Resolve the adapter session for a presented bearer or fail closed."""

        moment = now or datetime.now(timezone.utc)
        if not bearer or not isinstance(bearer, str) or len(bearer) > 256:
            self._record_rejection()
            raise AdapterSessionError("adapter:capability_missing")
        presented = _sha256(bearer)
        with self._lock:
            for session in self._sessions.values():
                if hmac.compare_digest(session.capability_sha256, presented):
                    if session.revoked_at is not None:
                        self._connection.rejected_calls += 1
                        raise AdapterSessionError("adapter:capability_revoked")
                    if moment >= session.expires_at:
                        self._connection.rejected_calls += 1
                        raise AdapterSessionError("adapter:capability_expired")
                    return session
            self._connection.rejected_calls += 1
        raise AdapterSessionError("adapter:capability_unknown")

    def current(self, adapter_kind: str) -> AdapterSession | None:
        """The active session for one adapter kind, or None if revoked or absent."""

        with self._lock:
            current_id = self._current.get(adapter_kind)
            session = self._sessions.get(current_id) if current_id else None
        if session is None or session.revoked_at is not None:
            return None
        return session

    def record_call(self, *, tool: str, verdict: str, now: datetime | None = None) -> None:
        with self._lock:
            self._connection.status = "connected"
            self._connection.last_seen_at = now or datetime.now(timezone.utc)
            self._connection.last_tool = tool
            self._connection.last_verdict = verdict
            self._connection.mediated_calls += 1

    def _record_rejection(self) -> None:
        with self._lock:
            self._connection.rejected_calls += 1
