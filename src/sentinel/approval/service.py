"""One-use approvals issued only through a protected in-process channel."""

from __future__ import annotations

import hmac
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Callable
from uuid import uuid4

from pydantic import BaseModel, Field

Clock = Callable[[], datetime]
IdFactory = Callable[[], str]
IssueObserver = Callable[["ApprovalToken"], None]
ConsumeObserver = Callable[["ApprovalToken"], None]


class ApprovalCapacityError(RuntimeError):
    """Pending approval capacity is full without discarding valid requests."""


class _FrozenStrictModel(BaseModel):
    """Pydantic v1/v2 compatible immutable strict model."""

    if hasattr(BaseModel, "model_validate"):
        model_config = {"extra": "forbid", "frozen": True}
    else:
        class Config:
            extra = "forbid"
            allow_mutation = False


class ApprovalBinding(_FrozenStrictModel):
    """Every authority-bearing field covered by one approval."""

    contract_id: str = Field(..., min_length=1, max_length=500)
    contract_version: int = Field(..., ge=1)
    authority_epoch: int = Field(..., ge=1)
    action_fingerprint: str = Field(..., min_length=1, max_length=500)
    environment: str = Field(..., min_length=1, max_length=500)
    session_id: str = Field(..., min_length=1, max_length=500)


class PendingApproval(_FrozenStrictModel):
    approval_id: str = Field(..., min_length=1)
    binding: ApprovalBinding
    created_at: datetime


class ApprovalToken(_FrozenStrictModel):
    token: str = Field(..., min_length=1)
    approval_id: str = Field(..., min_length=1)
    binding: ApprovalBinding
    issued_at: datetime
    approver_id: str = Field(..., min_length=1)
    approver_channel: str = Field(..., min_length=1)


class InMemoryApprovalService:
    """Thread-safe local approval handoff with exact binding and one-use tokens."""

    def __init__(
        self,
        *,
        clock: Clock | None = None,
        approval_id_factory: IdFactory | None = None,
        token_factory: IdFactory | None = None,
        pending_ttl: timedelta = timedelta(minutes=15),
        token_ttl: timedelta = timedelta(minutes=5),
        capacity: int = 1_000,
        issue_observer: IssueObserver | None = None,
    ) -> None:
        if pending_ttl <= timedelta(0) or token_ttl <= timedelta(0):
            raise ValueError("approval TTLs must be positive")
        if capacity <= 0:
            raise ValueError("approval capacity must be positive")
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._approval_id_factory = approval_id_factory or (lambda: str(uuid4()))
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        self._pending_ttl = pending_ttl
        self._token_ttl = token_ttl
        self._capacity = capacity
        self._issue_observer = issue_observer
        self._pending: dict[str, PendingApproval] = {}
        self._tokens: dict[str, ApprovalToken] = {}
        self._lock = threading.Lock()

    def request(self, binding: ApprovalBinding) -> PendingApproval:
        """Create a non-authorizing approval request for a confirmable action."""

        with self._lock:
            now = self._now()
            self._purge(now)
            self._purge_stale_authority(binding)
            for existing in self._pending.values():
                if _bindings_match(existing.binding, binding):
                    return existing
            if len(self._pending) >= self._capacity:
                raise ApprovalCapacityError("pending approval capacity is full")
            pending = PendingApproval(
                approval_id=self._approval_id_factory(),
                binding=binding,
                created_at=now,
            )
            self._pending[pending.approval_id] = pending
            return pending

    def issue(
        self,
        approval_id: str,
        *,
        approver_id: str,
        approver_channel: str,
    ) -> ApprovalToken | None:
        """Issue authority from a protected caller; this is never an HTTP route."""

        if not approver_id.strip() or not approver_channel.strip():
            raise ValueError("approver identity and channel are required")
        with self._lock:
            now = self._now()
            self._purge(now)
            pending = self._pending.get(approval_id)
            if pending is None:
                return None
            token = ApprovalToken(
                token=self._token_factory(),
                approval_id=pending.approval_id,
                binding=pending.binding,
                issued_at=now,
                approver_id=approver_id,
                approver_channel=approver_channel,
            )
            if self._issue_observer is not None:
                self._issue_observer(token)
            self._pending.pop(approval_id)
            self._evict(self._tokens)
            self._tokens[token.token] = token
            return token

    def set_issue_observer(self, observer: IssueObserver) -> None:
        """Attach the protected audit sink before any approval is issued."""

        with self._lock:
            if self._tokens:
                raise RuntimeError("cannot change approval observer after token issuance")
            self._issue_observer = observer

    def consume(
        self,
        token_value: str,
        binding: ApprovalBinding,
        *,
        consume_observer: ConsumeObserver | None = None,
    ) -> bool:
        """Atomically consume only after any admission observer succeeds."""

        with self._lock:
            self._purge(self._now())
            token = self._tokens.get(token_value)
            if token is None or not _bindings_match(token.binding, binding):
                return False
            if consume_observer is not None:
                consume_observer(token)
            del self._tokens[token_value]
            return True

    def has_token(self, token_value: str) -> bool:
        """Inspection helper for protected harnesses and tests."""

        with self._lock:
            self._purge(self._now())
            return token_value in self._tokens

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("approval clock must return a timezone-aware datetime")
        return now.astimezone(timezone.utc)

    def _purge(self, now: datetime) -> None:
        for approval_id, pending in list(self._pending.items()):
            if now >= pending.created_at + self._pending_ttl:
                del self._pending[approval_id]
        for token_value, token in list(self._tokens.items()):
            if now >= token.issued_at + self._token_ttl:
                del self._tokens[token_value]

    def _purge_stale_authority(self, current: ApprovalBinding) -> None:
        def stale(binding: ApprovalBinding) -> bool:
            return (
                binding.contract_id == current.contract_id
                and binding.session_id == current.session_id
                and (
                    binding.contract_version != current.contract_version
                    or binding.authority_epoch != current.authority_epoch
                )
            )

        for approval_id, pending in list(self._pending.items()):
            if stale(pending.binding):
                del self._pending[approval_id]
        for token_value, token in list(self._tokens.items()):
            if stale(token.binding):
                del self._tokens[token_value]

    def _evict(self, values: dict[str, object]) -> None:
        while len(values) >= self._capacity:
            del values[next(iter(values))]


def _bindings_match(first: ApprovalBinding, second: ApprovalBinding) -> bool:
    left = "\x00".join(
        (
            first.contract_id,
            str(first.contract_version),
            str(first.authority_epoch),
            first.action_fingerprint,
            first.environment,
            first.session_id,
        )
    )
    right = "\x00".join(
        (
            second.contract_id,
            str(second.contract_version),
            str(second.authority_epoch),
            second.action_fingerprint,
            second.environment,
            second.session_id,
        )
    )
    return hmac.compare_digest(left, right)
