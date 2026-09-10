"""Bounded server-owned envelopes for protected approval retries."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Generic, TypeVar

from sentinel.actions import CanonicalAction
from sentinel.approval import (
    ApprovalBinding,
    InMemoryApprovalService,
    PendingApproval,
)

Clock = Callable[[], datetime]
RetryResult = TypeVar("RetryResult")


class ApprovalCoordinatorError(RuntimeError):
    """A pending approval cannot be safely acted upon."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class ApprovalExecutionEnvelope:
    """Exact process-local request retained only until approve, deny, or expiry."""

    approval_id: str
    binding: ApprovalBinding
    attempt_id: str
    agent_id: str
    user_id: str
    raw_command: str
    cwd: str
    recent_actions_json: str
    operation: str
    targets: tuple[str, ...]
    effects: tuple[str, ...]
    canonical_command: str
    workspace: str
    reasons: tuple[str, ...]
    created_at: datetime
    expires_at: datetime
    family: str = "shell"
    tool: str | None = None
    arguments_json: str = "{}"

    def recent_actions(self) -> list[dict[str, object]]:
        return json.loads(self.recent_actions_json)


@dataclass(frozen=True)
class ApprovalRetryResult(Generic[RetryResult]):
    envelope: ApprovalExecutionEnvelope
    retry_result: RetryResult


class InMemoryApprovalCoordinator:
    """Own pending raw commands so browsers never handle approval tokens."""

    def __init__(
        self,
        approval_service: InMemoryApprovalService,
        *,
        clock: Clock | None = None,
        envelope_ttl: timedelta = timedelta(minutes=15),
        capacity: int = 1_000,
    ) -> None:
        if envelope_ttl <= timedelta(0):
            raise ValueError("approval envelope TTL must be positive")
        if capacity <= 0:
            raise ValueError("approval envelope capacity must be positive")
        self._approval_service = approval_service
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._envelope_ttl = envelope_ttl
        self._capacity = capacity
        self._envelopes: dict[str, ApprovalExecutionEnvelope] = {}
        self._lock = threading.Lock()

    def record(
        self,
        pending: PendingApproval,
        *,
        attempt_id: str,
        agent_id: str,
        user_id: str,
        raw_command: str,
        cwd: str,
        recent_actions: list[dict[str, object]],
        action: CanonicalAction,
        workspace: str,
        reasons: list[str],
        arguments: dict[str, object] | None = None,
    ) -> ApprovalExecutionEnvelope:
        """Bind one pending approval ID to its first exact execution attempt."""

        if not attempt_id.strip():
            raise ApprovalCoordinatorError("approval:attempt_id_required")
        recent_actions_json = json.dumps(
            recent_actions,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        arguments_json = json.dumps(
            arguments or {},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        now = self._now()
        created_at = pending.created_at.astimezone(timezone.utc)
        envelope = ApprovalExecutionEnvelope(
            approval_id=pending.approval_id,
            binding=pending.binding,
            attempt_id=attempt_id,
            agent_id=agent_id,
            user_id=user_id,
            raw_command=raw_command,
            cwd=cwd,
            recent_actions_json=recent_actions_json,
            operation=action.operation,
            targets=tuple(action.targets),
            effects=tuple(sorted(action.effects)),
            canonical_command=action.canonical_command or raw_command,
            workspace=workspace,
            reasons=tuple(reasons),
            created_at=created_at,
            expires_at=created_at + self._envelope_ttl,
            family=action.family,
            tool=action.tool,
            arguments_json=arguments_json,
        )
        with self._lock:
            self._purge(now)
            existing = self._envelopes.get(pending.approval_id)
            if existing is not None:
                if existing.binding != pending.binding:
                    raise ApprovalCoordinatorError(
                        "approval:envelope_binding_conflict"
                    )
                return existing
            if len(self._envelopes) >= self._capacity:
                raise ApprovalCoordinatorError("approval:envelope_capacity_full")
            self._envelopes[pending.approval_id] = envelope
            return envelope

    def list_pending(self) -> list[ApprovalExecutionEnvelope]:
        """Return only envelopes whose non-authorizing request still exists."""

        pending_ids = {
            pending.approval_id
            for pending in self._approval_service.list_pending()
        }
        with self._lock:
            self._purge(self._now())
            return [
                envelope
                for approval_id, envelope in self._envelopes.items()
                if approval_id in pending_ids
            ]

    def get_pending(
        self,
        approval_id: str,
    ) -> ApprovalExecutionEnvelope | None:
        if self._approval_service.get_pending(approval_id) is None:
            return None
        with self._lock:
            self._purge(self._now())
            return self._envelopes.get(approval_id)

    def approve(
        self,
        approval_id: str,
        *,
        retry: Callable[[ApprovalExecutionEnvelope, str], RetryResult],
        approver_id: str,
        approver_channel: str,
    ) -> ApprovalRetryResult[RetryResult]:
        """Issue internally, retry once, then discard any unconsumed token."""

        envelope = self._claim(approval_id)
        try:
            token = self._approval_service.issue(
                approval_id,
                approver_id=approver_id,
                approver_channel=approver_channel,
            )
        except Exception:
            self._restore(envelope)
            raise
        if token is None:
            raise ApprovalCoordinatorError("approval:request_unavailable")
        try:
            result = retry(envelope, token.token)
            return ApprovalRetryResult(
                envelope=envelope,
                retry_result=result,
            )
        finally:
            self._approval_service.discard_token(token.token)

    def deny(
        self,
        approval_id: str,
        *,
        denial_observer: Callable[[PendingApproval], None],
    ) -> ApprovalExecutionEnvelope:
        """Record denial durably, remove the raw envelope, and launch nothing."""

        envelope = self._claim(approval_id)
        try:
            denied = self._approval_service.deny(
                approval_id,
                denial_observer=denial_observer,
            )
        except Exception:
            self._restore(envelope)
            raise
        if denied is None:
            raise ApprovalCoordinatorError("approval:request_unavailable")
        return envelope

    def invalidate(self, approval_id: str) -> bool:
        """Discard an approval whose authority is no longer current."""

        with self._lock:
            self._purge(self._now())
            envelope = self._envelopes.pop(approval_id, None)
        invalidated = self._approval_service.invalidate(approval_id)
        return envelope is not None or invalidated

    def invalidate_where(
        self,
        predicate: Callable[[ApprovalBinding], bool],
    ) -> int:
        """Discard all envelopes and authority selected by server state."""

        with self._lock:
            self._purge(self._now())
            approval_ids = {
                approval_id
                for approval_id, envelope in self._envelopes.items()
                if predicate(envelope.binding)
            }
            for approval_id in approval_ids:
                del self._envelopes[approval_id]
        invalidated = self._approval_service.invalidate_where(predicate)
        return max(len(approval_ids), invalidated)

    def _claim(self, approval_id: str) -> ApprovalExecutionEnvelope:
        with self._lock:
            self._purge(self._now())
            envelope = self._envelopes.pop(approval_id, None)
        if envelope is None:
            raise ApprovalCoordinatorError("approval:request_unavailable")
        return envelope

    def _restore(self, envelope: ApprovalExecutionEnvelope) -> None:
        now = self._now()
        if now >= envelope.expires_at:
            return
        with self._lock:
            if len(self._envelopes) < self._capacity:
                self._envelopes.setdefault(envelope.approval_id, envelope)

    def _purge(self, now: datetime) -> None:
        for approval_id, envelope in list(self._envelopes.items()):
            if now >= envelope.expires_at:
                del self._envelopes[approval_id]

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("approval coordinator clock must be timezone-aware")
        return now.astimezone(timezone.utc)
