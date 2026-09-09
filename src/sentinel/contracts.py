"""Task-scoped authority contracts and their in-memory lifecycle store.

The small ``InMemoryAcceptedContractStore`` at the bottom remains the single-use
OpenClaw spike API. ``InMemoryContractStore`` is the persistent, versioned task
authority used by the Week 10 contract core.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock, local
from typing import Any, Callable, Iterator, Literal, Optional, TypeVar
from uuid import uuid4

from pydantic import BaseModel, Field, root_validator, validator

from sentinel.platforms import AudiencePolicy, ProviderScope

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows lacks advisory file locking.
    fcntl = None  # type: ignore[assignment]

ActionOperation = Literal[
    "read",
    "write",
    "delete",
    "execute",
    "network",
    "external_communication",
    "credential_access",
]
ContractEnvironment = Literal["sandbox", "dev", "staging", "production"]
MaximumScope = Literal["exact", "directory", "workspace"]
ContractLifecycleState = Literal[
    "proposed",
    "pending_review",
    "active",
    "rejected",
    "superseded",
    "suspended",
    "expired",
    "revoked",
]
AuthorizationSource = Literal["trusted_user", "trusted_host", "protected_local_ui"]
PreflightStatus = Literal["not_required", "complete", "needs_clarification"]
TemplateProvenance = Literal["trusted_user", "protected_local_ui"]


class _StrictModel(BaseModel):
    """Pydantic v1/v2 compatible base that rejects unknown fields."""

    if hasattr(BaseModel, "model_validate"):
        model_config = {"extra": "forbid"}
    else:
        class Config:
            extra = "forbid"


class ContractObligations(_StrictModel):
    """Machine-checkable safety steps required before an action may run."""

    dry_run_required: bool = False
    rollback_required: bool = False
    transaction_required: bool = False
    backup_required: bool = False


class ActionContract(_StrictModel):
    """Reviewed, machine-checkable boundary for a proposed agent action.

    Existing spike fields remain required and unchanged. The added effect and
    obligation fields make new deterministic matching possible without parsing
    human-readable review notes.
    """

    objective: str = Field(..., min_length=1, max_length=2_000)
    allowed_operations: set[ActionOperation] = Field(..., min_length=1)
    allowed_tools: set[str] = Field(..., min_length=1)
    exact_targets: list[str] = Field(..., min_length=1)
    environment: ContractEnvironment
    maximum_scope: MaximumScope
    expected_side_effects: list[str] = Field(..., min_length=1)
    allowed_effects: set[str] = Field(default_factory=set)
    forbidden_operations: set[ActionOperation] = Field(default_factory=set)
    forbidden_effects: list[str] = Field(
        ...,
        min_length=1,
        description="Human-readable review notes; use forbidden_effect_codes for enforcement.",
    )
    forbidden_effect_codes: set[str] = Field(default_factory=set)
    rollback_plan: str = Field(..., min_length=1, max_length=2_000)
    dry_run_required: bool
    rollback_required: bool = False
    transaction_required: bool = False
    backup_required: bool = False
    obligations: Optional[ContractObligations] = None
    environment_context: dict[str, str] = Field(default_factory=dict)
    provider_scope: Optional[ProviderScope] = None
    audience_policy: Optional[AudiencePolicy] = None
    approved_payload_sha256: Optional[str] = Field(
        default=None,
        min_length=64,
        max_length=64,
    )
    source_prompt_sha256: Optional[str] = Field(
        default=None,
        min_length=64,
        max_length=64,
        description=(
            "Non-authorizing provenance hash for a control prompt; "
            "never an executable payload binding."
        ),
    )
    authorization_reference: str = Field(..., min_length=1, max_length=500)
    version: int = Field(default=1, ge=1)
    expires_at: datetime

    @validator("expires_at")
    def _normalize_expiry(cls, value: datetime) -> datetime:
        return _as_utc(value)

    @validator("approved_payload_sha256", "source_prompt_sha256")
    def _sha256_hex(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.lower()
        if any(character not in "0123456789abcdef" for character in normalized):
            raise ValueError("SHA-256 values must be lowercase hexadecimal")
        return normalized

    @validator(
        "allowed_operations",
        "allowed_tools",
        "exact_targets",
        "expected_side_effects",
        "forbidden_effects",
    )
    def _require_nonempty_collection(cls, value: Any) -> Any:
        if not value:
            raise ValueError("collection must not be empty")
        return value

    def effective_obligations(self) -> ContractObligations:
        """Combine legacy top-level flags with the structured obligations."""

        nested = self.obligations or ContractObligations()
        return ContractObligations(
            dry_run_required=self.dry_run_required or nested.dry_run_required,
            rollback_required=self.rollback_required or nested.rollback_required,
            transaction_required=self.transaction_required or nested.transaction_required,
            backup_required=self.backup_required or nested.backup_required,
        )


class _FrozenModel(_StrictModel):
    """Pydantic v1/v2 compatible immutable base."""

    if hasattr(BaseModel, "model_validate"):
        model_config = {"extra": "forbid", "frozen": True}
    else:
        class Config:
            extra = "forbid"
            allow_mutation = False


class ContractRecord(_FrozenModel):
    """Immutable snapshot of one contract version and lifecycle state."""

    contract_id: str = Field(..., min_length=1)
    task_id: str = Field(..., min_length=1)
    session_id: str = Field(..., min_length=1)
    version: int = Field(..., ge=1)
    authority_epoch: int = Field(..., ge=0)
    authority_event_id: Optional[str] = None
    status: ContractLifecycleState
    contract: ActionContract
    authorization_source: AuthorizationSource
    authorization_reference: str = Field(..., min_length=1, max_length=500)
    parent_contract_id: Optional[str] = None
    parent_version: Optional[int] = Field(default=None, ge=1)
    supersedes_version: Optional[int] = Field(default=None, ge=1)
    superseded_by_version: Optional[int] = Field(default=None, ge=1)
    preflight_status: PreflightStatus = "complete"
    created_at: datetime
    updated_at: datetime
    expires_at: datetime

    @validator("created_at", "updated_at", "expires_at")
    def _normalize_record_time(cls, value: datetime) -> datetime:
        return _as_utc(value)


class TrustedPromptEnvelope(_StrictModel):
    """Host-proven direct-user event; authority still requires one-time consumption."""

    event_id: str = Field(..., min_length=1, max_length=500)
    nonce: str = Field(..., min_length=16, max_length=500)
    host_id: str = Field(..., min_length=1, max_length=500)
    session_id: str = Field(..., min_length=1, max_length=500)
    channel: str = Field(..., min_length=1, max_length=200)
    prompt: str = Field(..., min_length=1, max_length=32_000)
    purpose: Literal["task_transition", "amendment_decision", "task_reactivation"]
    contract_id: Optional[str] = None
    contract_version: Optional[int] = Field(default=None, ge=1)
    decision: Optional[Literal["approve", "reject", "reactivate"]] = None
    issued_at: datetime
    expires_at: datetime
    authenticated: Literal[True] = True

    @validator("issued_at", "expires_at")
    def _normalize_envelope_time(cls, value: datetime) -> datetime:
        return _as_utc(value)

    @root_validator(skip_on_failure=True)
    def _expiry_follows_issue(cls, values: dict[str, Any]) -> dict[str, Any]:
        issued_at = values.get("issued_at")
        expires_at = values.get("expires_at")
        if issued_at and expires_at and expires_at <= issued_at:
            raise ValueError("expires_at must be after issued_at")
        purpose = values.get("purpose")
        if purpose in {"amendment_decision", "task_reactivation"}:
            if not values.get("contract_id") or not values.get("contract_version"):
                raise ValueError("lifecycle events require contract_id and contract_version")
        if purpose == "amendment_decision" and values.get("decision") not in {
            "approve",
            "reject",
        }:
            raise ValueError("amendment decisions must be approve or reject")
        if purpose == "task_reactivation" and values.get("decision") != "reactivate":
            raise ValueError("task reactivation requires the reactivate decision")
        return values


class ConsumedTrustedEvent(_FrozenModel):
    """Receipt proving a trusted event passed binding and replay checks."""

    event_id: str
    nonce: str
    consumer_id: str
    receipt_id: str
    host_id: str
    session_id: str
    channel: str
    purpose: Literal["task_transition", "amendment_decision", "task_reactivation"]
    contract_id: Optional[str] = None
    contract_version: Optional[int] = None
    decision: Optional[Literal["approve", "reject", "reactivate"]] = None
    consumed_at: datetime
    expires_at: datetime


class TrustedEventError(ValueError):
    """Trusted prompt validation failed with a stable reason code."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class InMemoryTrustedEventConsumer:
    """Atomically accepts each correctly bound trusted host event once."""

    def __init__(
        self,
        *,
        host_id: str | None = None,
        session_id: str | None = None,
        channel: str | None = None,
    ) -> None:
        self._host_id = host_id
        self._session_id = session_id
        self._channel = channel
        self._consumer_id = str(uuid4())
        self._event_ids: set[str] = set()
        self._nonces: set[str] = set()
        self._receipts: dict[str, ConsumedTrustedEvent] = {}
        self._lock = RLock()

    @property
    def binding(self) -> tuple[str | None, str | None, str | None]:
        return (self._host_id, self._session_id, self._channel)

    def consume(
        self,
        envelope: TrustedPromptEnvelope,
        *,
        expected_host_id: str | None = None,
        expected_session_id: str | None = None,
        expected_channel: str | None = None,
        now: datetime | None = None,
    ) -> ConsumedTrustedEvent:
        """Validate provenance bindings and atomically reject event or nonce replay."""

        checked = _revalidate_model(TrustedPromptEnvelope, envelope)
        current = _as_utc(now or datetime.now(timezone.utc))
        host_id = self._resolve_binding(self._host_id, expected_host_id)
        session_id = self._resolve_binding(self._session_id, expected_session_id)
        channel = self._resolve_binding(self._channel, expected_channel)
        if not host_id or not session_id or not channel:
            raise TrustedEventError("trusted_event:binding_required")
        if checked.host_id != host_id:
            raise TrustedEventError("trusted_event:host_mismatch")
        if checked.session_id != session_id:
            raise TrustedEventError("trusted_event:session_mismatch")
        if checked.channel != channel:
            raise TrustedEventError("trusted_event:channel_mismatch")
        if checked.issued_at > current:
            raise TrustedEventError("trusted_event:not_yet_valid")
        if checked.expires_at <= current:
            raise TrustedEventError("trusted_event:expired")

        receipt_id = str(uuid4())
        with self._lock:
            if checked.event_id in self._event_ids or checked.nonce in self._nonces:
                raise TrustedEventError("trusted_event:replayed")
            self._event_ids.add(checked.event_id)
            self._nonces.add(checked.nonce)
            receipt = ConsumedTrustedEvent(
                event_id=checked.event_id,
                nonce=checked.nonce,
                consumer_id=self._consumer_id,
                receipt_id=receipt_id,
                host_id=checked.host_id,
                session_id=checked.session_id,
                channel=checked.channel,
                purpose=checked.purpose,
                contract_id=checked.contract_id,
                contract_version=checked.contract_version,
                decision=checked.decision,
                consumed_at=current,
                expires_at=checked.expires_at,
            )
            self._receipts[receipt_id] = receipt
            return _copy_model(receipt)

    def claim(
        self,
        receipt: ConsumedTrustedEvent,
        *,
        expected_session_id: str,
        expected_channel: str | None = None,
        expected_purpose: str,
        expected_contract_id: str,
        expected_contract_version: int,
        expected_decision: str,
        now: datetime | None = None,
    ) -> ConsumedTrustedEvent:
        """Atomically bind one issued receipt to one authority transition."""

        checked = _revalidate_model(ConsumedTrustedEvent, receipt)
        current = _as_utc(now or datetime.now(timezone.utc))
        if checked.consumer_id != self._consumer_id:
            raise TrustedEventError("trusted_event:invalid_receipt")
        if checked.session_id != expected_session_id:
            raise TrustedEventError("trusted_event:session_mismatch")
        if expected_channel is not None and checked.channel != expected_channel:
            raise TrustedEventError("trusted_event:channel_mismatch")
        if (
            checked.purpose != expected_purpose
            or checked.contract_id != expected_contract_id
            or checked.contract_version != expected_contract_version
            or checked.decision != expected_decision
        ):
            raise TrustedEventError("trusted_event:authority_binding_mismatch")
        if checked.expires_at <= current:
            raise TrustedEventError("trusted_event:expired")
        with self._lock:
            issued = self._receipts.get(checked.receipt_id)
            if issued is None or issued != checked:
                raise TrustedEventError("trusted_event:invalid_or_used_receipt")
            self._receipts.pop(checked.receipt_id)
        return checked

    def _has_unclaimed_receipt(self, receipt: ConsumedTrustedEvent) -> bool:
        """Return whether this consumer can still claim an exact receipt."""

        checked = _revalidate_model(ConsumedTrustedEvent, receipt)
        with self._lock:
            return self._receipts.get(checked.receipt_id) == checked

    def _restore_unclaimed_receipt(self, receipt: ConsumedTrustedEvent) -> None:
        """Restore a claim when its enclosing durable transaction rolls back."""

        checked = _revalidate_model(ConsumedTrustedEvent, receipt)
        if checked.consumer_id != self._consumer_id:
            return
        with self._lock:
            self._receipts.setdefault(checked.receipt_id, checked)

    @staticmethod
    def _resolve_binding(configured: str | None, expected: str | None) -> str | None:
        if configured is not None and expected is not None and configured != expected:
            raise TrustedEventError("trusted_event:binding_conflict")
        return configured or expected


# A descriptive alias for callers that use the full model name.
InMemoryTrustedPromptConsumer = InMemoryTrustedEventConsumer


class TaskTemplateDefaults(_StrictModel):
    """Contract-shaped defaults that intentionally omit live authority fields."""

    objective: str = Field(..., min_length=1, max_length=2_000)
    allowed_operations: set[ActionOperation] = Field(..., min_length=1)
    allowed_tools: set[str] = Field(..., min_length=1)
    exact_targets: list[str] = Field(default_factory=list)
    environment: Optional[ContractEnvironment] = None
    maximum_scope: MaximumScope = "exact"
    allowed_effects: set[str] = Field(default_factory=set)
    forbidden_operations: set[ActionOperation] = Field(default_factory=set)
    forbidden_effect_codes: set[str] = Field(default_factory=set)
    obligations: ContractObligations = Field(default_factory=ContractObligations)
    rollback_plan: Optional[str] = Field(default=None, max_length=2_000)

    @validator("allowed_operations", "allowed_tools")
    def _require_nonempty_default(cls, value: Any) -> Any:
        if not value:
            raise ValueError("collection must not be empty")
        return value


class TaskTemplate(_FrozenModel):
    """Reviewed convenience data. A template is never active authority."""

    template_id: str = Field(..., min_length=1)
    version: int = Field(default=1, ge=1)
    name: str = Field(..., min_length=1, max_length=200)
    normalized_task_pattern: str = Field(..., min_length=1, max_length=2_000)
    contract_defaults: TaskTemplateDefaults
    provenance: TemplateProvenance
    last_reviewed_at: datetime
    authorizes_actions: Literal[False] = False

    @validator("last_reviewed_at")
    def _normalize_review_time(cls, value: datetime) -> datetime:
        return _as_utc(value)


@dataclass(frozen=True)
class AuthorityQuarantine:
    """Durable marker for an authority transition with unverified completion."""

    quarantine_id: str
    reason: str
    transition: str
    session_id: str | None
    task_id: str | None
    contract_id: str | None
    contract_version: int | None
    previous_contract_id: str | None
    previous_contract_version: int | None
    previous_authority_epoch: int | None
    created_at: datetime


class ContractStoreError(ValueError):
    """Base error for deterministic lifecycle failures."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class ContractConflictError(ContractStoreError):
    """Compare-and-swap precondition did not match current state."""


class InvalidContractTransition(ContractStoreError):
    """Requested lifecycle edge is not allowed."""


class InMemoryContractStore:
    """Thread-safe, persistent task authority with compare-and-swap updates."""

    def __init__(
        self,
        *,
        trusted_event_consumer: InMemoryTrustedEventConsumer | None = None,
    ) -> None:
        self._records: dict[str, dict[int, ContractRecord]] = {}
        self._task_contracts: dict[str, str] = {}
        self._active_tasks: dict[str, str] = {}
        self._authority_quarantine: AuthorityQuarantine | None = None
        self._trusted_event_consumer = trusted_event_consumer
        self._lock = RLock()

    @contextmanager
    def authority_quarantine_guard(
        self,
        quarantine: AuthorityQuarantine,
    ) -> Iterator[None]:
        """Set a process-local transition marker before mutating authority."""

        with self._lock:
            if self._authority_quarantine is not None:
                raise ContractConflictError("authority:quarantined")
            self._authority_quarantine = quarantine
            yield

    @contextmanager
    def authority_quarantine_recovery_guard(
        self,
        quarantine_id: str,
    ) -> Iterator[None]:
        """Serialize recovery against the matching process-local marker."""

        with self._lock:
            quarantine = self._authority_quarantine
            if quarantine is None or quarantine.quarantine_id != quarantine_id:
                raise ContractConflictError("authority:quarantine_changed")
            yield

    def get_authority_quarantine(self) -> AuthorityQuarantine | None:
        with self._lock:
            return self._authority_quarantine

    def peek_active(self, session_id: str) -> ContractRecord | None:
        """Read the active snapshot without applying expiry side effects."""

        with self._lock:
            record = self._active_record_locked(session_id)
            return _copy_contract_record(record) if record is not None else None

    def clear_authority_quarantine(self, quarantine_id: str) -> None:
        with self._lock:
            quarantine = self._authority_quarantine
            if quarantine is None or quarantine.quarantine_id != quarantine_id:
                raise ContractConflictError("authority:quarantine_changed")
            self._authority_quarantine = None

    def set_trusted_event_consumer(
        self,
        consumer: InMemoryTrustedEventConsumer,
    ) -> InMemoryTrustedEventConsumer:
        """Bind one protected event consumer without permitting replacement."""

        with self._lock:
            if self._trusted_event_consumer is not None:
                if self._trusted_event_consumer.binding != consumer.binding:
                    raise TrustedEventError(
                        "trusted_event:consumer_already_configured"
                    )
                return self._trusted_event_consumer
            self._trusted_event_consumer = consumer
            return consumer

    def create(
        self,
        contract: ActionContract,
        *,
        session_id: str,
        authorization_source: AuthorizationSource,
        created_at: datetime,
        task_id: str | None = None,
        contract_id: str | None = None,
        status: Literal["proposed", "pending_review", "active"] = "proposed",
        expected_active_task_id: str | None = None,
        preflight_status: PreflightStatus = "complete",
        trusted_event: ConsumedTrustedEvent | None = None,
    ) -> ContractRecord:
        """Create a draft or activate an exactly bound trusted task transition."""

        if not session_id.strip():
            raise ValueError("session_id must not be empty")
        if status == "pending_review":
            raise InvalidContractTransition("contract:initial_pending_review")
        checked = _copy_contract(contract, version=1)
        current = _as_utc(created_at)
        if status == "active" and checked.expires_at <= current:
            raise InvalidContractTransition("contract:expired")
        new_task_id = task_id or str(uuid4())
        new_contract_id = contract_id or str(uuid4())
        with self._lock:
            if new_task_id in self._task_contracts or new_contract_id in self._records:
                raise ContractConflictError("contract:identifier_conflict")
            active_task = (
                self._expire_active_task_if_needed_locked(
                    session_id,
                    expected_active_task_id=expected_active_task_id,
                    now=current,
                )
                if status == "active"
                else self._active_tasks.get(session_id)
            )
            if status == "active":
                if contract_id is None:
                    raise TrustedEventError("trusted_event:contract_id_required")
                if trusted_event is None:
                    self._require_event_consumer_locked()
                    raise TrustedEventError("trusted_event:receipt_required")
                consumer = self._require_event_consumer_locked()
                consumer.claim(
                    trusted_event,
                    expected_session_id=session_id,
                    expected_purpose="task_transition",
                    expected_contract_id=new_contract_id,
                    expected_contract_version=1,
                    expected_decision="approve",
                    now=current,
                )
                checked = _copy_contract(
                    checked,
                    version=1,
                    authorization_reference=trusted_event.event_id,
                )
                authorization_source = _authorization_source_for_event(trusted_event)
            record = ContractRecord(
                contract_id=new_contract_id,
                task_id=new_task_id,
                session_id=session_id,
                version=1,
                authority_epoch=1 if status == "active" else 0,
                authority_event_id=(
                    trusted_event.event_id
                    if status == "active" and trusted_event is not None
                    else None
                ),
                status=status,
                contract=checked,
                authorization_source=authorization_source,
                authorization_reference=checked.authorization_reference,
                preflight_status=preflight_status,
                created_at=current,
                updated_at=current,
                expires_at=checked.expires_at,
            )
            if status == "active":
                if active_task:
                    self._replace_status_locked(
                        self._active_record_locked(session_id),
                        "suspended",
                        updated_at=current,
                        advance_authority_epoch=True,
                    )
                self._active_tasks[session_id] = new_task_id
            self._records[new_contract_id] = {1: record}
            self._task_contracts[new_task_id] = new_contract_id
            return _copy_contract_record(record)

    def create_active(self, contract: ActionContract, **kwargs: Any) -> ContractRecord:
        """Convenience wrapper requiring a trusted task-transition receipt."""

        return self.create(contract, status="active", **kwargs)

    @contextmanager
    def execution_guard(
        self,
        contract_id: str,
        *,
        expected_version: int,
        expected_authority_epoch: int,
        session_id: str,
        now: datetime | None = None,
    ) -> Iterator[ContractRecord]:
        """Hold lifecycle state stable from final admission through execution."""

        with self._lock:
            current = _as_utc(now or datetime.now(timezone.utc))
            record = self._require_version_locked(contract_id, expected_version)
            if record.expires_at <= current:
                self._replace_status_locked(
                    record,
                    "expired",
                    updated_at=current,
                    advance_authority_epoch=True,
                )
                raise InvalidContractTransition("contract:expired")
            if (
                record.status != "active"
                or record.authority_epoch != expected_authority_epoch
                or self._active_tasks.get(session_id) != record.task_id
                or record.session_id != session_id
            ):
                raise ContractConflictError("contract:execution_admission_stale")
            yield _copy_contract_record(record)

    def activate_proposed(
        self,
        contract_id: str,
        *,
        expected_version: int,
        expected_active_task_id: str | None,
        trusted_event: ConsumedTrustedEvent,
        activated_at: datetime,
    ) -> ContractRecord:
        """Activate an initial proposal using one exactly bound trusted receipt."""

        current = _as_utc(activated_at)
        with self._lock:
            record = self._require_version_locked(contract_id, expected_version)
            if record.status != "proposed" or record.version != 1:
                raise InvalidContractTransition("contract:cannot_activate")
            if record.expires_at <= current:
                self._replace_status_locked(record, "expired", updated_at=current)
                raise InvalidContractTransition("contract:expired")
            active_task = self._expire_active_task_if_needed_locked(
                record.session_id,
                expected_active_task_id=expected_active_task_id,
                now=current,
            )
            consumer = self._require_event_consumer_locked()
            consumer.claim(
                trusted_event,
                expected_session_id=record.session_id,
                expected_purpose="task_transition",
                expected_contract_id=contract_id,
                expected_contract_version=1,
                expected_decision="approve",
                now=current,
            )
            if active_task:
                self._replace_status_locked(
                    self._active_record_locked(record.session_id),
                    "suspended",
                    updated_at=current,
                    advance_authority_epoch=True,
                )
            replacement = self._replace_status_locked(
                record,
                "active",
                updated_at=current,
                authority_epoch=1,
                authority_event_id=trusted_event.event_id,
            )
            self._active_tasks[record.session_id] = record.task_id
            return _copy_contract_record(replacement)

    def amend(
        self,
        contract_id: str,
        contract: ActionContract,
        *,
        expected_version: int,
        authorization_source: AuthorizationSource,
        created_at: datetime,
        sensitive: bool | None = None,
        preflight_status: PreflightStatus = "complete",
        trusted_event: ConsumedTrustedEvent | None = None,
    ) -> ContractRecord:
        """Add one immutable version; sensitive versions remain non-authorizing."""

        current = _as_utc(created_at)
        with self._lock:
            versions = self._require_versions_locked(contract_id)
            active = self._active_record_locked(next(iter(versions.values())).session_id)
            if (
                active is None
                or active.contract_id != contract_id
                or active.version != expected_version
            ):
                raise ContractConflictError("contract:stale_version")
            if any(record.status == "pending_review" for record in versions.values()):
                raise ContractConflictError("contract:pending_version_exists")
            parent = active
            new_version = max(versions) + 1
            checked = _copy_contract(
                contract,
                version=new_version,
                authorization_reference=parent.authorization_reference,
            )
            if parent.expires_at <= current or checked.expires_at <= current:
                if parent.expires_at <= current:
                    self._replace_status_locked(
                        parent,
                        "expired",
                        updated_at=current,
                        advance_authority_epoch=True,
                    )
                    self._active_tasks.pop(parent.session_id, None)
                raise InvalidContractTransition("contract:expired")
            requires_review = bool(sensitive) or _is_sensitive_expansion(
                parent.contract,
                checked,
            )
            status: ContractLifecycleState = (
                "pending_review" if requires_review else "active"
            )
            record_authorization_source = parent.authorization_source
            record_authorization_reference = parent.authorization_reference
            authority_event_id = parent.authority_event_id
            if not requires_review:
                if trusted_event is None:
                    self._require_event_consumer_locked()
                    raise TrustedEventError("trusted_event:receipt_required")
                consumer = self._require_event_consumer_locked()
                consumer.claim(
                    trusted_event,
                    expected_session_id=parent.session_id,
                    expected_purpose="amendment_decision",
                    expected_contract_id=contract_id,
                    expected_contract_version=new_version,
                    expected_decision="approve",
                    now=current,
                )
                checked = _copy_contract(
                    checked,
                    version=new_version,
                    authorization_reference=trusted_event.event_id,
                )
                record_authorization_source = _authorization_source_for_event(
                    trusted_event
                )
                record_authorization_reference = trusted_event.event_id
                authority_event_id = trusted_event.event_id
            record = ContractRecord(
                contract_id=contract_id,
                task_id=parent.task_id,
                session_id=parent.session_id,
                version=new_version,
                authority_epoch=(
                    parent.authority_epoch
                    if requires_review
                    else parent.authority_epoch + 1
                ),
                authority_event_id=authority_event_id,
                status=status,
                contract=checked,
                authorization_source=record_authorization_source,
                authorization_reference=record_authorization_reference,
                parent_contract_id=contract_id,
                parent_version=parent.version,
                supersedes_version=None if requires_review else parent.version,
                preflight_status=preflight_status,
                created_at=current,
                updated_at=current,
                expires_at=checked.expires_at,
            )
            if not requires_review:
                self._replace_status_locked(
                    parent,
                    "superseded",
                    updated_at=current,
                    superseded_by_version=new_version,
                    advance_authority_epoch=True,
                )
            versions[new_version] = record
            return _copy_contract_record(record)

    def decide_pending(
        self,
        contract_id: str,
        version: int,
        *,
        approve: bool,
        expected_active_version: int,
        decided_at: datetime,
        trusted_event: ConsumedTrustedEvent,
    ) -> ContractRecord:
        """Approve or reject a sensitive version without weakening CAS checks."""

        current = _as_utc(decided_at)
        with self._lock:
            versions = self._require_versions_locked(contract_id)
            pending = versions.get(version)
            if pending is None:
                raise ContractStoreError("contract:not_found")
            if pending.status != "pending_review":
                raise InvalidContractTransition("contract:not_pending")
            active = self._active_record_locked(pending.session_id)
            if (
                active is None
                or active.contract_id != contract_id
                or active.version != expected_active_version
            ):
                raise ContractConflictError("contract:stale_version")
            consumer = self._require_event_consumer_locked()
            consumer.claim(
                trusted_event,
                expected_session_id=pending.session_id,
                expected_channel="protected_local_ui",
                expected_purpose="amendment_decision",
                expected_contract_id=contract_id,
                expected_contract_version=version,
                expected_decision="approve" if approve else "reject",
                now=current,
            )
            if pending.expires_at <= current:
                self._replace_status_locked(
                    pending,
                    "expired",
                    updated_at=current,
                    advance_authority_epoch=True,
                )
                raise InvalidContractTransition("contract:expired")
            if active.expires_at <= current:
                self._replace_status_locked(
                    active,
                    "expired",
                    updated_at=current,
                    advance_authority_epoch=True,
                )
                self._active_tasks.pop(active.session_id, None)
                raise InvalidContractTransition("contract:expired")
            if approve:
                self._replace_status_locked(
                    active,
                    "superseded",
                    updated_at=current,
                    superseded_by_version=pending.version,
                    advance_authority_epoch=True,
                )
                replacement = self._replace_status_locked(
                    pending,
                    "active",
                    updated_at=current,
                    supersedes_version=active.version,
                    authority_epoch=active.authority_epoch + 1,
                    authority_event_id=trusted_event.event_id,
                )
            else:
                replacement = self._replace_status_locked(
                    pending,
                    "rejected",
                    updated_at=current,
                )
            return _copy_contract_record(replacement)

    def suspend(
        self,
        contract_id: str,
        *,
        expected_version: int,
        suspended_at: datetime,
    ) -> ContractRecord:
        current = _as_utc(suspended_at)
        with self._lock:
            record = self._require_version_locked(contract_id, expected_version)
            if record.status != "active":
                raise InvalidContractTransition("contract:inactive")
            if self._active_tasks.get(record.session_id) != record.task_id:
                raise ContractConflictError("contract:stale_active_task")
            if record.expires_at <= current:
                replacement = self._replace_status_locked(
                    record,
                    "expired",
                    updated_at=current,
                    advance_authority_epoch=True,
                )
                self._active_tasks.pop(record.session_id, None)
                raise InvalidContractTransition("contract:expired")
            replacement = self._replace_status_locked(
                record,
                "suspended",
                updated_at=current,
                advance_authority_epoch=True,
            )
            self._active_tasks.pop(record.session_id, None)
            return _copy_contract_record(replacement)

    def revoke(
        self,
        contract_id: str,
        *,
        expected_version: int,
        revoked_at: datetime,
    ) -> ContractRecord:
        current = _as_utc(revoked_at)
        with self._lock:
            record = self._require_version_locked(contract_id, expected_version)
            if record.status not in {"active", "suspended"}:
                raise InvalidContractTransition("contract:cannot_revoke")
            if record.expires_at <= current:
                replacement = self._replace_status_locked(
                    record,
                    "expired",
                    updated_at=current,
                    advance_authority_epoch=True,
                )
            else:
                replacement = self._replace_status_locked(
                    record,
                    "revoked",
                    updated_at=current,
                    advance_authority_epoch=True,
                )
            if self._active_tasks.get(record.session_id) == record.task_id:
                self._active_tasks.pop(record.session_id, None)
            return _copy_contract_record(replacement)

    def expire(
        self,
        contract_id: str,
        *,
        expected_version: int,
        now: datetime,
    ) -> ContractRecord:
        current = _as_utc(now)
        with self._lock:
            record = self._require_version_locked(contract_id, expected_version)
            if record.status not in {"active", "suspended"}:
                raise InvalidContractTransition("contract:cannot_expire")
            if record.expires_at > current:
                raise InvalidContractTransition("contract:not_expired")
            replacement = self._replace_status_locked(
                record,
                "expired",
                updated_at=current,
                advance_authority_epoch=True,
            )
            if self._active_tasks.get(record.session_id) == record.task_id:
                self._active_tasks.pop(record.session_id, None)
            return _copy_contract_record(replacement)

    def reactivate(
        self,
        contract_id: str,
        *,
        expected_version: int,
        expected_active_task_id: str | None,
        trusted_event: ConsumedTrustedEvent,
        reactivated_at: datetime,
    ) -> ContractRecord:
        """Reactivate only a suspended, unexpired task using a fresh event receipt."""

        current = _as_utc(reactivated_at)
        with self._lock:
            record = self._require_version_locked(contract_id, expected_version)
            if record.status != "suspended":
                raise InvalidContractTransition("contract:cannot_reactivate")
            if record.expires_at <= current:
                self._replace_status_locked(
                    record,
                    "expired",
                    updated_at=current,
                    advance_authority_epoch=True,
                )
                raise InvalidContractTransition("contract:expired")
            active_task = self._expire_active_task_if_needed_locked(
                record.session_id,
                expected_active_task_id=expected_active_task_id,
                now=current,
            )
            consumer = self._require_event_consumer_locked()
            consumer.claim(
                trusted_event,
                expected_session_id=record.session_id,
                expected_purpose="task_reactivation",
                expected_contract_id=contract_id,
                expected_contract_version=expected_version,
                expected_decision="reactivate",
                now=current,
            )
            if active_task:
                self._replace_status_locked(
                    self._active_record_locked(record.session_id),
                    "suspended",
                    updated_at=current,
                    advance_authority_epoch=True,
                )
            replacement = self._replace_status_locked(
                record,
                "active",
                updated_at=current,
                advance_authority_epoch=True,
                authority_event_id=trusted_event.event_id,
            )
            self._active_tasks[record.session_id] = record.task_id
            return _copy_contract_record(replacement)

    def get(self, contract_id: str, version: int | None = None) -> ContractRecord | None:
        with self._lock:
            versions = self._records.get(contract_id)
            if not versions:
                return None
            selected = versions.get(version if version is not None else max(versions))
            return _copy_contract_record(selected) if selected else None

    resolve = get

    def get_active(self, session_id: str, *, now: datetime | None = None) -> ContractRecord | None:
        current = _as_utc(now or datetime.now(timezone.utc))
        with self._lock:
            record = self._active_record_locked(session_id)
            if record and record.expires_at <= current:
                self._replace_status_locked(
                    record,
                    "expired",
                    updated_at=current,
                    advance_authority_epoch=True,
                )
                self._active_tasks.pop(session_id, None)
                return None
            return _copy_contract_record(record) if record else None

    def list_versions(self, contract_id: str) -> list[ContractRecord]:
        with self._lock:
            versions = self._records.get(contract_id, {})
            return [_copy_contract_record(versions[number]) for number in sorted(versions)]

    def _active_record_locked(self, session_id: str) -> ContractRecord | None:
        task_id = self._active_tasks.get(session_id)
        if not task_id:
            return None
        contract_id = self._task_contracts[task_id]
        active = [
            record
            for record in self._records[contract_id].values()
            if record.status == "active"
        ]
        return max(active, key=lambda item: item.version) if active else None

    def _expire_active_task_if_needed_locked(
        self,
        session_id: str,
        *,
        expected_active_task_id: str | None,
        now: datetime,
    ) -> str | None:
        active_task = self._active_tasks.get(session_id)
        if active_task != expected_active_task_id:
            raise ContractConflictError("contract:stale_active_task")
        active = self._active_record_locked(session_id)
        if active is not None and active.expires_at <= now:
            self._replace_status_locked(
                active,
                "expired",
                updated_at=now,
                advance_authority_epoch=True,
            )
            self._active_tasks.pop(session_id, None)
            return None
        return active_task

    def _require_versions_locked(self, contract_id: str) -> dict[int, ContractRecord]:
        versions = self._records.get(contract_id)
        if not versions:
            raise ContractStoreError("contract:not_found")
        return versions

    def _require_event_consumer_locked(self) -> InMemoryTrustedEventConsumer:
        if self._trusted_event_consumer is None:
            raise TrustedEventError("trusted_event:consumer_not_configured")
        return self._trusted_event_consumer

    def _require_version_locked(self, contract_id: str, version: int) -> ContractRecord:
        record = self._require_versions_locked(contract_id).get(version)
        if record is None:
            raise ContractConflictError("contract:stale_version")
        return record

    def _replace_status_locked(
        self,
        record: ContractRecord | None,
        status: ContractLifecycleState,
        *,
        updated_at: datetime,
        supersedes_version: int | None = None,
        superseded_by_version: int | None = None,
        authority_epoch: int | None = None,
        authority_event_id: str | None = None,
        advance_authority_epoch: bool = False,
    ) -> ContractRecord:
        if record is None:
            raise ContractStoreError("contract:not_found")
        replacement = _copy_model(
            record,
            update={
                "status": status,
                "updated_at": updated_at,
                "authority_epoch": (
                    record.authority_epoch + 1
                    if advance_authority_epoch
                    else (
                        authority_epoch
                        if authority_epoch is not None
                        else record.authority_epoch
                    )
                ),
                "authority_event_id": (
                    authority_event_id
                    if authority_event_id is not None
                    else record.authority_event_id
                ),
                "supersedes_version": (
                    supersedes_version
                    if supersedes_version is not None
                    else record.supersedes_version
                ),
                "superseded_by_version": (
                    superseded_by_version
                    if superseded_by_version is not None
                    else record.superseded_by_version
                ),
            },
        )
        self._records[record.contract_id][record.version] = replacement
        return replacement


_ResultT = TypeVar("_ResultT")


class SQLiteContractStore:
    """SQLite WAL contract store with transactional lifecycle snapshots.

    SQLite is the source of truth. Each write takes an immediate transaction,
    rebuilds the in-memory lifecycle view from that transaction's rows, applies
    the shared lifecycle rules, and persists only new versions and mutable
    lifecycle metadata before committing.
    """

    def __init__(
        self,
        database: str | Path,
        *,
        trusted_event_consumer: InMemoryTrustedEventConsumer | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._database = str(database)
        self._trusted_event_consumer = trusted_event_consumer
        self._lock = RLock()
        self._authority_lock_state = local()
        self._authority_lock_file = None
        if self._database != ":memory:" and fcntl is None:
            raise RuntimeError(
                "durable authority requires cross-process file locking"
            )
        if self._database != ":memory:":
            lock_path = Path(f"{self._database}.authority.lock")
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            self._authority_lock_file = lock_path.open("a+b")
        self._connection: sqlite3.Connection | None = sqlite3.connect(
            self._database,
            timeout=timeout_seconds,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(f"PRAGMA busy_timeout={int(timeout_seconds * 1_000)}")
        self._create_schema()

    @contextmanager
    def authority_quarantine_guard(
        self,
        quarantine: AuthorityQuarantine,
    ) -> Iterator[None]:
        """Persist a marker and serialize its authority transition."""

        with self._process_authority_guard(), self._lock:
            connection = self._require_connection()
            try:
                with connection:
                    connection.execute(
                        """
                        INSERT INTO authority_quarantine (
                            singleton_id, quarantine_id, reason, transition,
                            session_id, task_id, contract_id, contract_version,
                            previous_contract_id, previous_contract_version,
                            previous_authority_epoch, created_at
                        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            quarantine.quarantine_id,
                            quarantine.reason,
                            quarantine.transition,
                            quarantine.session_id,
                            quarantine.task_id,
                            quarantine.contract_id,
                            quarantine.contract_version,
                            quarantine.previous_contract_id,
                            quarantine.previous_contract_version,
                            quarantine.previous_authority_epoch,
                            _timestamp_text(quarantine.created_at),
                        ),
                    )
            except sqlite3.IntegrityError as exc:
                raise ContractConflictError("authority:quarantined") from exc
            previous = getattr(
                self._authority_lock_state,
                "quarantine_id",
                None,
            )
            self._authority_lock_state.quarantine_id = quarantine.quarantine_id
            try:
                yield
            finally:
                self._authority_lock_state.quarantine_id = previous

    @contextmanager
    def authority_quarantine_recovery_guard(
        self,
        quarantine_id: str,
    ) -> Iterator[None]:
        """Permit only recovery writes while a durable marker exists."""

        with self._process_authority_guard(), self._lock:
            quarantine = self._get_authority_quarantine_locked()
            if quarantine is None or quarantine.quarantine_id != quarantine_id:
                raise ContractConflictError("authority:quarantine_changed")
            previous = getattr(
                self._authority_lock_state,
                "quarantine_id",
                None,
            )
            self._authority_lock_state.quarantine_id = quarantine_id
            try:
                yield
            finally:
                self._authority_lock_state.quarantine_id = previous

    def get_authority_quarantine(self) -> AuthorityQuarantine | None:
        with self._process_authority_guard(), self._lock:
            return self._get_authority_quarantine_locked()

    def peek_active(self, session_id: str) -> ContractRecord | None:
        """Read the active snapshot without applying expiry side effects."""

        with self._process_authority_guard(), self._lock:
            snapshot = self._load_snapshot_locked()
            return snapshot.peek_active(session_id)

    def clear_authority_quarantine(self, quarantine_id: str) -> None:
        with self._process_authority_guard(), self._lock:
            connection = self._require_connection()
            with connection:
                cursor = connection.execute(
                    """
                    DELETE FROM authority_quarantine
                    WHERE singleton_id = 1 AND quarantine_id = ?
                    """,
                    (quarantine_id,),
                )
            if cursor.rowcount != 1:
                raise ContractConflictError("authority:quarantine_changed")

    def set_trusted_event_consumer(
        self,
        consumer: InMemoryTrustedEventConsumer,
    ) -> InMemoryTrustedEventConsumer:
        """Bind one protected event consumer without permitting replacement."""

        with self._lock:
            if self._trusted_event_consumer is not None:
                if self._trusted_event_consumer.binding != consumer.binding:
                    raise TrustedEventError(
                        "trusted_event:consumer_already_configured"
                    )
                return self._trusted_event_consumer
            self._trusted_event_consumer = consumer
            return consumer

    def create(
        self,
        contract: ActionContract,
        *,
        session_id: str,
        authorization_source: AuthorizationSource,
        created_at: datetime,
        task_id: str | None = None,
        contract_id: str | None = None,
        status: Literal["proposed", "pending_review", "active"] = "proposed",
        expected_active_task_id: str | None = None,
        preflight_status: PreflightStatus = "complete",
        trusted_event: ConsumedTrustedEvent | None = None,
    ) -> ContractRecord:
        return self._write(
            lambda store: store.create(
                contract,
                session_id=session_id,
                authorization_source=authorization_source,
                created_at=created_at,
                task_id=task_id,
                contract_id=contract_id,
                status=status,
                expected_active_task_id=expected_active_task_id,
                preflight_status=preflight_status,
                trusted_event=trusted_event,
            ),
            trusted_event=trusted_event,
        )

    def create_active(self, contract: ActionContract, **kwargs: Any) -> ContractRecord:
        return self.create(contract, status="active", **kwargs)

    @contextmanager
    def execution_guard(
        self,
        contract_id: str,
        *,
        expected_version: int,
        expected_authority_epoch: int,
        session_id: str,
        now: datetime | None = None,
    ) -> Iterator[ContractRecord]:
        """Serialize local lifecycle writes with one admitted execution."""

        with self._process_authority_guard(), self._lock:
            self._require_authority_quarantine_access_locked()
            self.get_active(session_id, now=now)
            snapshot = self._load_snapshot_locked()
            selected = snapshot.get(contract_id, expected_version)
            if selected is not None and selected.status == "expired":
                raise InvalidContractTransition("contract:expired")
            with snapshot.execution_guard(
                contract_id,
                expected_version=expected_version,
                expected_authority_epoch=expected_authority_epoch,
                session_id=session_id,
                now=now,
            ) as record:
                yield record

    def activate_proposed(
        self,
        contract_id: str,
        *,
        expected_version: int,
        expected_active_task_id: str | None,
        trusted_event: ConsumedTrustedEvent,
        activated_at: datetime,
    ) -> ContractRecord:
        return self._write(
            lambda store: store.activate_proposed(
                contract_id,
                expected_version=expected_version,
                expected_active_task_id=expected_active_task_id,
                trusted_event=trusted_event,
                activated_at=activated_at,
            ),
            trusted_event=trusted_event,
        )

    def amend(
        self,
        contract_id: str,
        contract: ActionContract,
        *,
        expected_version: int,
        authorization_source: AuthorizationSource,
        created_at: datetime,
        sensitive: bool | None = None,
        preflight_status: PreflightStatus = "complete",
        trusted_event: ConsumedTrustedEvent | None = None,
    ) -> ContractRecord:
        return self._write(
            lambda store: store.amend(
                contract_id,
                contract,
                expected_version=expected_version,
                authorization_source=authorization_source,
                created_at=created_at,
                sensitive=sensitive,
                preflight_status=preflight_status,
                trusted_event=trusted_event,
            ),
            trusted_event=trusted_event,
        )

    def decide_pending(
        self,
        contract_id: str,
        version: int,
        *,
        approve: bool,
        expected_active_version: int,
        decided_at: datetime,
        trusted_event: ConsumedTrustedEvent,
    ) -> ContractRecord:
        return self._write(
            lambda store: store.decide_pending(
                contract_id,
                version,
                approve=approve,
                expected_active_version=expected_active_version,
                decided_at=decided_at,
                trusted_event=trusted_event,
            ),
            trusted_event=trusted_event,
        )

    def suspend(
        self,
        contract_id: str,
        *,
        expected_version: int,
        suspended_at: datetime,
    ) -> ContractRecord:
        return self._write(
            lambda store: store.suspend(
                contract_id,
                expected_version=expected_version,
                suspended_at=suspended_at,
            )
        )

    def revoke(
        self,
        contract_id: str,
        *,
        expected_version: int,
        revoked_at: datetime,
    ) -> ContractRecord:
        return self._write(
            lambda store: store.revoke(
                contract_id,
                expected_version=expected_version,
                revoked_at=revoked_at,
            )
        )

    def expire(
        self,
        contract_id: str,
        *,
        expected_version: int,
        now: datetime,
    ) -> ContractRecord:
        return self._write(
            lambda store: store.expire(
                contract_id,
                expected_version=expected_version,
                now=now,
            )
        )

    def reactivate(
        self,
        contract_id: str,
        *,
        expected_version: int,
        expected_active_task_id: str | None,
        trusted_event: ConsumedTrustedEvent,
        reactivated_at: datetime,
    ) -> ContractRecord:
        return self._write(
            lambda store: store.reactivate(
                contract_id,
                expected_version=expected_version,
                expected_active_task_id=expected_active_task_id,
                trusted_event=trusted_event,
                reactivated_at=reactivated_at,
            ),
            trusted_event=trusted_event,
        )

    def get(self, contract_id: str, version: int | None = None) -> ContractRecord | None:
        with self._lock:
            return self._load_snapshot_locked().get(contract_id, version)

    resolve = get

    def get_active(
        self,
        session_id: str,
        *,
        now: datetime | None = None,
    ) -> ContractRecord | None:
        return self._write(lambda store: store.get_active(session_id, now=now))

    def list_versions(self, contract_id: str) -> list[ContractRecord]:
        with self._lock:
            return self._load_snapshot_locked().list_versions(contract_id)

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
            if self._authority_lock_file is not None:
                self._authority_lock_file.close()
                self._authority_lock_file = None

    def __enter__(self) -> SQLiteContractStore:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _write(
        self,
        operation: Callable[[InMemoryContractStore], _ResultT],
        *,
        trusted_event: ConsumedTrustedEvent | None = None,
    ) -> _ResultT:
        """Apply one lifecycle operation and its complete delta atomically."""

        receipt_lock = (
            self._trusted_event_consumer._lock
            if trusted_event is not None and self._trusted_event_consumer is not None
            else nullcontext()
        )
        with self._process_authority_guard(), self._lock, receipt_lock:
            connection = self._require_connection()
            self._require_authority_quarantine_access_locked()
            receipt_was_available = (
                trusted_event is not None
                and self._trusted_event_consumer is not None
                and self._trusted_event_consumer._has_unclaimed_receipt(trusted_event)
            )
            domain_error: Exception | None = None
            result: _ResultT | None = None
            connection.execute("BEGIN IMMEDIATE")
            try:
                snapshot = self._load_snapshot_locked()
                if (
                    trusted_event is not None
                    and self._trusted_event_was_persisted_locked(trusted_event)
                ):
                    domain_error = TrustedEventError("trusted_event:replayed")
                else:
                    try:
                        result = operation(snapshot)
                    except (ContractStoreError, TrustedEventError, ValueError) as exc:
                        # Some lifecycle failures intentionally persist a terminal
                        # state, such as discovering expiry while approving.
                        domain_error = exc
                receipt_was_claimed = (
                    receipt_was_available
                    and trusted_event is not None
                    and self._trusted_event_consumer is not None
                    and not self._trusted_event_consumer._has_unclaimed_receipt(
                        trusted_event
                    )
                )
                if receipt_was_claimed:
                    self._insert_trusted_event_consumption_locked(trusted_event)
                self._sync_snapshot_locked(snapshot)
                connection.commit()
            except Exception:
                connection.rollback()
                if (
                    receipt_was_available
                    and trusted_event is not None
                    and self._trusted_event_consumer is not None
                    and not self._trusted_event_consumer._has_unclaimed_receipt(trusted_event)
                ):
                    self._trusted_event_consumer._restore_unclaimed_receipt(trusted_event)
                raise

            if domain_error is not None:
                raise domain_error
            return result  # type: ignore[return-value]

    @contextmanager
    def _process_authority_guard(self) -> Iterator[None]:
        lock_file = self._authority_lock_file
        if lock_file is None or fcntl is None:
            yield
            return
        depth = getattr(self._authority_lock_state, "depth", 0)
        if depth == 0:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        self._authority_lock_state.depth = depth + 1
        try:
            yield
        finally:
            remaining = self._authority_lock_state.depth - 1
            self._authority_lock_state.depth = remaining
            if remaining == 0:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _get_authority_quarantine_locked(self) -> AuthorityQuarantine | None:
        row = self._require_connection().execute(
            """
            SELECT
                quarantine_id, reason, transition, session_id, task_id,
                contract_id, contract_version, previous_contract_id,
                previous_contract_version, previous_authority_epoch, created_at
            FROM authority_quarantine
            WHERE singleton_id = 1
            """
        ).fetchone()
        if row is None:
            return None
        return AuthorityQuarantine(
            quarantine_id=row["quarantine_id"],
            reason=row["reason"],
            transition=row["transition"],
            session_id=row["session_id"],
            task_id=row["task_id"],
            contract_id=row["contract_id"],
            contract_version=row["contract_version"],
            previous_contract_id=row["previous_contract_id"],
            previous_contract_version=row["previous_contract_version"],
            previous_authority_epoch=row["previous_authority_epoch"],
            created_at=_as_utc(datetime.fromisoformat(row["created_at"])),
        )

    def _require_authority_quarantine_access_locked(self) -> None:
        quarantine = self._get_authority_quarantine_locked()
        if quarantine is None:
            return
        allowed_id = getattr(self._authority_lock_state, "quarantine_id", None)
        if allowed_id != quarantine.quarantine_id:
            raise ContractConflictError("authority:quarantined")

    def _trusted_event_was_persisted_locked(
        self,
        trusted_event: ConsumedTrustedEvent,
    ) -> bool:
        row = self._require_connection().execute(
            """
            SELECT 1
            FROM trusted_event_consumptions
            WHERE event_id = ? OR nonce = ?
            LIMIT 1
            """,
            (trusted_event.event_id, trusted_event.nonce),
        ).fetchone()
        return row is not None

    def _insert_trusted_event_consumption_locked(
        self,
        trusted_event: ConsumedTrustedEvent,
    ) -> None:
        self._require_connection().execute(
            """
            INSERT INTO trusted_event_consumptions (
                event_id, nonce, receipt_id, consumer_id, session_id,
                channel, purpose, contract_id, contract_version, decision,
                consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                trusted_event.event_id,
                trusted_event.nonce,
                trusted_event.receipt_id,
                trusted_event.consumer_id,
                trusted_event.session_id,
                trusted_event.channel,
                trusted_event.purpose,
                trusted_event.contract_id,
                trusted_event.contract_version,
                trusted_event.decision,
                _timestamp_text(trusted_event.consumed_at),
            ),
        )

    def _load_snapshot_locked(self) -> InMemoryContractStore:
        snapshot = InMemoryContractStore(
            trusted_event_consumer=self._trusted_event_consumer,
        )
        rows = self._require_connection().execute(
            """
            SELECT contract_id, task_id, session_id, version, authority_epoch,
                   authority_event_id, status,
                   contract_json, authorization_source, authorization_reference,
                   parent_contract_id, parent_version, supersedes_version,
                   superseded_by_version, preflight_status, created_at,
                   updated_at, expires_at
            FROM contract_records
            ORDER BY contract_id, version
            """
        ).fetchall()
        for row in rows:
            record = _sqlite_row_to_contract_record(row)
            snapshot._records.setdefault(record.contract_id, {})[record.version] = record
            snapshot._task_contracts[record.task_id] = record.contract_id
            if record.status == "active":
                snapshot._active_tasks[record.session_id] = record.task_id
        return snapshot

    def _sync_snapshot_locked(self, snapshot: InMemoryContractStore) -> None:
        connection = self._require_connection()
        persisted_states = {
            (row["contract_id"], row["version"]): (
                row["status"],
                row["updated_at"],
                row["authority_epoch"],
                row["authority_event_id"],
                row["supersedes_version"],
                row["superseded_by_version"],
            )
            for row in connection.execute(
                """
                SELECT contract_id, version, status, updated_at,
                       authority_epoch, authority_event_id,
                       supersedes_version, superseded_by_version
                FROM contract_records
                """
            ).fetchall()
        }
        persisted_keys = set(persisted_states)
        persisted_lineages = {
            row["contract_id"]
            for row in connection.execute(
                "SELECT contract_id FROM contract_lineages"
            ).fetchall()
        }

        records = [
            record
            for versions in snapshot._records.values()
            for record in versions.values()
        ]
        for record in records:
            if record.contract_id not in persisted_lineages:
                connection.execute(
                    """
                    INSERT INTO contract_lineages (
                        contract_id, task_id, session_id
                    ) VALUES (?, ?, ?)
                    """,
                    (record.contract_id, record.task_id, record.session_id),
                )
                persisted_lineages.add(record.contract_id)

        existing = [
            record
            for record in records
            if (record.contract_id, record.version) in persisted_keys
        ]
        # Vacate constrained states before assigning a different active or
        # pending row, avoiding transient uniqueness failures in one delta.
        existing.sort(
            key=lambda record: (
                record.status == "active",
                record.status == "pending_review",
                record.contract_id,
                record.version,
            )
        )
        for record in existing:
            new_state = (
                record.status,
                _timestamp_text(record.updated_at),
                record.authority_epoch,
                record.authority_event_id,
                record.supersedes_version,
                record.superseded_by_version,
            )
            if persisted_states[(record.contract_id, record.version)] == new_state:
                continue
            connection.execute(
                """
                UPDATE contract_records
                SET status = ?, updated_at = ?, authority_epoch = ?,
                    authority_event_id = ?, supersedes_version = ?,
                    superseded_by_version = ?
                WHERE contract_id = ? AND version = ?
                """,
                (
                    *new_state,
                    record.contract_id,
                    record.version,
                ),
            )

        new_records = [
            record
            for record in records
            if (record.contract_id, record.version) not in persisted_keys
        ]
        new_records.sort(key=lambda record: record.status == "active")
        for record in new_records:
            self._insert_record_locked(record)

    def _insert_record_locked(self, record: ContractRecord) -> None:
        self._require_connection().execute(
            """
            INSERT INTO contract_records (
                contract_id, task_id, session_id, version, authority_epoch,
                authority_event_id, status,
                contract_json, authorization_source, authorization_reference,
                parent_contract_id, parent_version, supersedes_version,
                superseded_by_version, preflight_status, created_at,
                updated_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.contract_id,
                record.task_id,
                record.session_id,
                record.version,
                record.authority_epoch,
                record.authority_event_id,
                record.status,
                _contract_json(record.contract),
                record.authorization_source,
                record.authorization_reference,
                record.parent_contract_id,
                record.parent_version,
                record.supersedes_version,
                record.superseded_by_version,
                record.preflight_status,
                _timestamp_text(record.created_at),
                _timestamp_text(record.updated_at),
                _timestamp_text(record.expires_at),
            ),
        )

    def _create_schema(self) -> None:
        connection = self._require_connection()
        with connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS contract_lineages (
                    contract_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL UNIQUE,
                    session_id TEXT NOT NULL,
                    UNIQUE (contract_id, task_id, session_id)
                );

                CREATE TABLE IF NOT EXISTS contract_records (
                    contract_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    version INTEGER NOT NULL CHECK (version >= 1),
                    authority_epoch INTEGER NOT NULL DEFAULT 0
                        CHECK (authority_epoch >= 0),
                    authority_event_id TEXT,
                    status TEXT NOT NULL CHECK (status IN (
                        'proposed', 'pending_review', 'active', 'rejected',
                        'superseded', 'suspended', 'expired', 'revoked'
                    )),
                    contract_json TEXT NOT NULL,
                    authorization_source TEXT NOT NULL,
                    authorization_reference TEXT NOT NULL,
                    parent_contract_id TEXT,
                    parent_version INTEGER,
                    supersedes_version INTEGER,
                    superseded_by_version INTEGER,
                    preflight_status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    PRIMARY KEY (contract_id, version),
                    FOREIGN KEY (contract_id, task_id, session_id)
                        REFERENCES contract_lineages(contract_id, task_id, session_id)
                        ON DELETE RESTRICT
                );

                CREATE UNIQUE INDEX IF NOT EXISTS uq_contract_active_session
                ON contract_records(session_id)
                WHERE status = 'active';

                CREATE UNIQUE INDEX IF NOT EXISTS uq_contract_pending_lineage
                ON contract_records(contract_id)
                WHERE status = 'pending_review';

                CREATE INDEX IF NOT EXISTS idx_contract_task
                ON contract_records(task_id);

                CREATE INDEX IF NOT EXISTS idx_contract_session
                ON contract_records(session_id);

                CREATE TABLE IF NOT EXISTS trusted_event_consumptions (
                    event_id TEXT PRIMARY KEY,
                    nonce TEXT NOT NULL UNIQUE,
                    receipt_id TEXT NOT NULL UNIQUE,
                    consumer_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    contract_id TEXT,
                    contract_version INTEGER,
                    decision TEXT,
                    consumed_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS authority_quarantine (
                    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                    quarantine_id TEXT NOT NULL UNIQUE,
                    reason TEXT NOT NULL,
                    transition TEXT NOT NULL,
                    session_id TEXT,
                    task_id TEXT,
                    contract_id TEXT,
                    contract_version INTEGER,
                    previous_contract_id TEXT,
                    previous_contract_version INTEGER,
                    previous_authority_epoch INTEGER,
                    created_at TEXT NOT NULL
                );

                CREATE TRIGGER IF NOT EXISTS protect_contract_record_snapshot
                BEFORE UPDATE ON contract_records
                WHEN OLD.contract_id != NEW.contract_id
                  OR OLD.task_id != NEW.task_id
                  OR OLD.session_id != NEW.session_id
                  OR OLD.version != NEW.version
                  OR OLD.contract_json != NEW.contract_json
                  OR OLD.authorization_source != NEW.authorization_source
                  OR OLD.authorization_reference != NEW.authorization_reference
                  OR OLD.parent_contract_id IS NOT NEW.parent_contract_id
                  OR OLD.parent_version IS NOT NEW.parent_version
                  OR OLD.preflight_status != NEW.preflight_status
                  OR OLD.created_at != NEW.created_at
                  OR OLD.expires_at != NEW.expires_at
                BEGIN
                    SELECT RAISE(ABORT, 'contract version snapshots are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS prevent_contract_record_delete
                BEFORE DELETE ON contract_records
                BEGIN
                    SELECT RAISE(ABORT, 'contract version snapshots are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS prevent_contract_lineage_update
                BEFORE UPDATE ON contract_lineages
                BEGIN
                    SELECT RAISE(ABORT, 'contract lineages are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS prevent_contract_lineage_delete
                BEFORE DELETE ON contract_lineages
                BEGIN
                    SELECT RAISE(ABORT, 'contract lineages are immutable');
                END;
                """
            )
            columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(contract_records)"
                ).fetchall()
            }
            if "authority_epoch" not in columns:
                connection.execute(
                    """
                    ALTER TABLE contract_records
                    ADD COLUMN authority_epoch INTEGER NOT NULL DEFAULT 1
                    CHECK (authority_epoch >= 0)
                    """
                )
            if "authority_event_id" not in columns:
                connection.execute(
                    "ALTER TABLE contract_records ADD COLUMN authority_event_id TEXT"
                )
            migration_time = _timestamp_text(datetime.now(timezone.utc))
            connection.execute(
                """
                UPDATE contract_records
                SET status = 'suspended',
                    authority_epoch = authority_epoch + 1,
                    updated_at = ?
                WHERE status = 'active' AND authority_event_id IS NULL
                """,
                (migration_time,),
            )
            connection.execute(
                """
                UPDATE contract_records
                SET status = 'rejected', updated_at = ?
                WHERE status = 'pending_review' AND version = 1
                """,
                (migration_time,),
            )

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise sqlite3.OperationalError("SQLite connection is unavailable")
        return self._connection


@dataclass(frozen=True)
class AcceptedContract:
    """Contract loaded from the trusted approval-side store."""

    contract_id: str
    contract: ActionContract
    approver_id: str
    accepted_at: datetime


class InMemoryAcceptedContractStore:
    """Legacy single-use spike store; preserved for current OpenClaw tests."""

    def __init__(self) -> None:
        self._records: dict[str, AcceptedContract] = {}
        self._lock = RLock()

    def accept(self, contract: ActionContract, *, approver_id: str, accepted_at: datetime) -> AcceptedContract:
        """Record acceptance; production callers must expose this only to a separate approver channel."""

        if not approver_id.strip():
            raise ValueError("approver_id must not be empty")
        record = AcceptedContract(
            contract_id=str(uuid4()),
            contract=_copy_contract(contract),
            approver_id=approver_id,
            accepted_at=accepted_at,
        )
        with self._lock:
            self._records[record.contract_id] = record
        return _copy_record(record)

    def resolve(self, contract_id: str) -> AcceptedContract | None:
        with self._lock:
            record = self._records.get(contract_id)
        return _copy_record(record) if record else None

    def consume(self, contract_id: str) -> AcceptedContract | None:
        """Atomically consume one accepted contract so it cannot be replayed."""

        with self._lock:
            record = self._records.pop(contract_id, None)
        return _copy_record(record) if record else None


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _model_payload(model: BaseModel) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="python", warnings=False)
    return model.dict()


def _revalidate_model(model_type: type[BaseModel], model: BaseModel) -> Any:
    return model_type(**_model_payload(model))


def _copy_model(model: BaseModel, *, update: dict[str, Any] | None = None) -> Any:
    payload = _model_payload(model)
    payload.update(update or {})
    return type(model)(**payload)


def _copy_contract(
    contract: ActionContract,
    *,
    version: int | None = None,
    authorization_reference: str | None = None,
) -> ActionContract:
    payload = _model_payload(contract)
    if version is not None:
        payload["version"] = version
    if authorization_reference is not None:
        payload["authorization_reference"] = authorization_reference
    return ActionContract(**payload)


def _copy_contract_record(record: ContractRecord) -> ContractRecord:
    payload = _model_payload(record)
    payload["contract"] = _copy_contract(record.contract)
    return ContractRecord(**payload)


def _contract_json(contract: ActionContract) -> str:
    if hasattr(contract, "model_dump"):
        payload = contract.model_dump(mode="json", warnings=False)
    else:
        payload = json.loads(contract.json())
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _timestamp_text(value: datetime) -> str:
    return _as_utc(value).isoformat(timespec="microseconds")


def _authorization_source_for_event(
    trusted_event: ConsumedTrustedEvent,
) -> AuthorizationSource:
    if trusted_event.channel == "protected_local_ui":
        return "protected_local_ui"
    return "trusted_user"


def _sqlite_row_to_contract_record(row: sqlite3.Row) -> ContractRecord:
    return ContractRecord(
        contract_id=row["contract_id"],
        task_id=row["task_id"],
        session_id=row["session_id"],
        version=row["version"],
        authority_epoch=row["authority_epoch"],
        authority_event_id=row["authority_event_id"],
        status=row["status"],
        contract=ActionContract(**json.loads(row["contract_json"])),
        authorization_source=row["authorization_source"],
        authorization_reference=row["authorization_reference"],
        parent_contract_id=row["parent_contract_id"],
        parent_version=row["parent_version"],
        supersedes_version=row["supersedes_version"],
        superseded_by_version=row["superseded_by_version"],
        preflight_status=row["preflight_status"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        expires_at=row["expires_at"],
    )


def _is_sensitive_expansion(previous: ActionContract, proposed: ActionContract) -> bool:
    """Conservatively identify privilege additions that require review."""

    environment_rank = {"sandbox": 0, "dev": 1, "staging": 2, "production": 3}
    if (
        _contract_requires_provider_profile(previous)
        and not _provider_profile_complete(previous)
        and _provider_profile_complete(proposed)
    ):
        return True
    if environment_rank[proposed.environment] > environment_rank[previous.environment]:
        return True
    if proposed.environment_context != previous.environment_context:
        return True
    if (
        previous.provider_scope is not None
        and proposed.provider_scope != previous.provider_scope
    ):
        return True
    if _is_audience_expansion(
        previous.audience_policy,
        proposed.audience_policy,
    ):
        return True
    if (
        previous.approved_payload_sha256 is not None
        and proposed.approved_payload_sha256
        != previous.approved_payload_sha256
    ):
        return True
    if proposed.expires_at > previous.expires_at:
        return True
    if proposed.maximum_scope in {"directory", "workspace"} and (
        previous.maximum_scope == "exact"
        or (
            previous.maximum_scope == "directory"
            and proposed.maximum_scope == "workspace"
        )
    ):
        return True
    if proposed.allowed_operations - previous.allowed_operations:
        return True
    if proposed.allowed_effects - previous.allowed_effects:
        return True
    if previous.allowed_effects and not proposed.allowed_effects:
        return True
    if proposed.allowed_tools - previous.allowed_tools:
        return True
    if set(proposed.exact_targets) - set(previous.exact_targets):
        return True
    if previous.forbidden_operations - proposed.forbidden_operations:
        return True
    if previous.forbidden_effect_codes - proposed.forbidden_effect_codes:
        return True
    old_obligations = previous.effective_obligations()
    new_obligations = proposed.effective_obligations()
    return any(
        getattr(old_obligations, field) and not getattr(new_obligations, field)
        for field in (
            "dry_run_required",
            "rollback_required",
            "transaction_required",
            "backup_required",
        )
    )


def _is_audience_expansion(
    previous: AudiencePolicy | None,
    proposed: AudiencePolicy | None,
) -> bool:
    if previous is None:
        return False
    if proposed is None:
        return True
    for field in (
        "allow_external",
        "allow_guests",
        "allow_public",
        "allow_broadcast",
        "allow_recipient_expansion",
    ):
        if not getattr(previous, field) and getattr(proposed, field):
            return True
    old_max = previous.maximum_recipient_count
    new_max = proposed.maximum_recipient_count
    if old_max is not None and (new_max is None or new_max > old_max):
        return True
    for field in ("allowed_recipient_ids", "allowed_audience_resource_ids"):
        old_ids = getattr(previous, field)
        new_ids = getattr(proposed, field)
        if old_ids is not None and new_ids is None:
            return True
        if old_ids is not None and new_ids is not None and new_ids - old_ids:
            return True
    return False


def _contract_requires_provider_profile(contract: ActionContract) -> bool:
    provider_tools = {"slack", "gmail", "google_calendar", "google_drive"}
    communication_effects = {
        "external_send",
        "calendar_invite",
        "share_read",
        "share_write",
        "public_share",
        "portal_publish",
        "court_file",
        "audience_change",
        "recipient_expansion",
    }
    return (
        "external_communication" in contract.allowed_operations
        or bool(contract.allowed_tools.intersection(provider_tools))
        or bool(contract.allowed_effects.intersection(communication_effects))
    )


def _provider_profile_complete(contract: ActionContract) -> bool:
    policy = contract.audience_policy
    return bool(
        contract.provider_scope is not None
        and policy is not None
        and contract.approved_payload_sha256 is not None
        and (
            policy.allowed_recipient_ids is not None
            or policy.allowed_audience_resource_ids is not None
        )
    )


def _copy_record(record: AcceptedContract) -> AcceptedContract:
    return AcceptedContract(
        contract_id=record.contract_id,
        contract=_copy_contract(record.contract),
        approver_id=record.approver_id,
        accepted_at=record.accepted_at,
    )
