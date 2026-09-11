"""Process-local proposal store plus the one service that mutates it.

Invariants the service enforces:

- one pending proposal per supervision session; a newer one supersedes the
  older, which is recorded and can never be confirmed;
- every proposed field is checked against the immutable startup ceiling at
  proposal time *and* again at confirmation time by the contract builder;
- proposals expire after a short window so stale intent cannot be confirmed
  hours later;
- terminal drafts are kept in a bounded history for the Activity view.

The service writes audit events but grants nothing. Confirmation is recorded
only after the caller has already activated a contract through the authority
service; the proposal is evidence of intent, not a source of authority.
"""

from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Callable
from uuid import uuid4

from sentinel.audit.base import AuditStore, AuditStoreError
from sentinel.audit.models import AuditEvent
from sentinel.control.workspace import SupervisionBinding
from sentinel.proposals.models import (
    MAX_PROPOSAL_TARGETS,
    MAX_TASK_DURATION_MINUTES,
    ProposalFacts,
    ProposalResolution,
    ProposalStateError,
    ProposalValidationError,
    TaskProposal,
)
from sentinel.supervision import SupervisionPolicyBinding

PROPOSAL_AGENT_ID = "cursor_mcp_adapter"
DEFAULT_PROPOSAL_TTL = timedelta(minutes=15)
HISTORY_LIMIT = 50

# Contract operations map onto the fixture operations the ceiling classifies.
CONTRACT_TO_FIXTURE_OPERATION = {"read": "issue_read", "write": "issue_add_note"}


class InMemoryTaskProposalStore:
    """Single-pending-per-session store with a bounded terminal history."""

    def __init__(self, *, history_limit: int = HISTORY_LIMIT) -> None:
        self._lock = threading.RLock()
        self._pending: dict[str, TaskProposal] = {}
        self._by_id: dict[str, TaskProposal] = {}
        self._history: dict[str, deque[TaskProposal]] = {}
        self._counts: dict[str, int] = {}
        self._history_limit = history_limit

    def next_number(self, session_id: str) -> int:
        with self._lock:
            self._counts[session_id] = self._counts.get(session_id, 0) + 1
            return self._counts[session_id]

    def pending(self, session_id: str) -> TaskProposal | None:
        with self._lock:
            return self._pending.get(session_id)

    def get(self, draft_id: str) -> TaskProposal | None:
        with self._lock:
            return self._by_id.get(draft_id)

    def put_pending(self, proposal: TaskProposal) -> None:
        with self._lock:
            self._pending[proposal.supervision_session_id] = proposal
            self._by_id[proposal.draft_id] = proposal

    def retire(self, proposal: TaskProposal) -> None:
        """Move a now-terminal proposal out of pending and into bounded history."""

        with self._lock:
            session_id = proposal.supervision_session_id
            if self._pending.get(session_id) is not None and self._pending[session_id].draft_id == proposal.draft_id:
                del self._pending[session_id]
            self._by_id[proposal.draft_id] = proposal
            history = self._history.setdefault(session_id, deque(maxlen=self._history_limit))
            history.appendleft(proposal)
            # Keep the id index bounded to what history still remembers.
            remembered = {item.draft_id for item in history} | {
                item.draft_id for item in self._pending.values()
            }
            for stale in [key for key in self._by_id if key not in remembered]:
                del self._by_id[stale]

    def history(self, session_id: str) -> list[TaskProposal]:
        with self._lock:
            return list(self._history.get(session_id, ()))


class TaskProposalService:
    def __init__(
        self,
        *,
        store: InMemoryTaskProposalStore,
        policy_binding: SupervisionPolicyBinding,
        supervision: SupervisionBinding,
        audit_store: AuditStore,
        environment: str,
        proposal_ttl: timedelta = DEFAULT_PROPOSAL_TTL,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if proposal_ttl <= timedelta(0):
            raise ValueError("proposal_ttl must be positive")
        self._store = store
        self._policy_binding = policy_binding
        self._supervision = supervision
        self._audit = audit_store
        self._environment = environment
        self._ttl = proposal_ttl
        self._now = clock or (lambda: datetime.now(timezone.utc))

    # -- reads ------------------------------------------------------------------------

    @property
    def session_id(self) -> str:
        return self._supervision.session_id

    def pending(self) -> TaskProposal | None:
        """The one pending proposal, or None. Expires it lazily if its window passed."""

        proposal = self._store.pending(self.session_id)
        if proposal is None:
            return None
        if proposal.is_expired(self._now()):
            self._expire(proposal)
            return None
        return proposal

    def get(self, draft_id: str) -> TaskProposal | None:
        proposal = self._store.get(draft_id)
        if proposal is None or proposal.supervision_session_id != self.session_id:
            return None
        if proposal.state == "pending" and proposal.is_expired(self._now()):
            return self._expire(proposal)
        return proposal

    def history(self) -> list[TaskProposal]:
        self.pending()  # sweep an expired pending draft into history first
        return self._store.history(self.session_id)

    # -- agent intake -----------------------------------------------------------------

    def validate(self, facts: ProposalFacts) -> None:
        """Check every proposed field against the immutable ceiling. Raises."""

        policy = self._policy_binding.policy
        now = self._now()
        if self._policy_binding.is_expired(now):
            raise ProposalValidationError(
                "supervision:ceiling_expired", "The startup ceiling has expired.",
                guidance="Ask the user to restart Sentinel.",
            )
        fixture_operation = CONTRACT_TO_FIXTURE_OPERATION.get(facts.operation)
        permitted = policy.ordinary_operations | policy.confirm_operations
        if fixture_operation is None or fixture_operation in policy.forbidden_operations or fixture_operation not in permitted:
            raise ProposalValidationError(
                "supervision:operation_forbidden",
                f"The startup ceiling does not allow tasks with operation {facts.operation!r}.",
                guidance="Propose operation 'read' or 'write' only.", field="operation",
            )
        if not facts.exact_targets:
            raise ProposalValidationError(
                "proposal:targets_required", "At least one issue ID is required.",
                guidance="List the exact fixture issue IDs the task needs, for example ['SPIKE-1'].", field="issue_ids",
            )
        if len(facts.exact_targets) > MAX_PROPOSAL_TARGETS:
            raise ProposalValidationError(
                "proposal:too_many_targets", f"A proposal may name at most {MAX_PROPOSAL_TARGETS} issues.",
                guidance="Propose only the issues this task actually needs.", field="issue_ids",
            )
        for target in facts.exact_targets:
            if not policy.issue_in_scope(target):
                raise ProposalValidationError(
                    "supervision:issue_out_of_scope",
                    f"Issue {target!r} is outside the startup ceiling's allowed identifiers.",
                    guidance="Only fixture issues matching the ceiling pattern can be proposed; ask the user if you need another.",
                    field="issue_ids",
                )
        if facts.task_duration_minutes < 1 or facts.task_duration_minutes > MAX_TASK_DURATION_MINUTES:
            raise ProposalValidationError(
                "proposal:duration_invalid", f"minutes must be between 1 and {MAX_TASK_DURATION_MINUTES}.",
                guidance="Propose a duration in whole minutes within that range.", field="minutes",
            )
        remaining = self._policy_binding.expires_at - now
        if timedelta(minutes=facts.task_duration_minutes) > remaining:
            remaining_minutes = max(1, int(remaining.total_seconds() // 60))
            raise ProposalValidationError(
                "proposal:duration_exceeds_ceiling",
                f"The task would outlive the startup ceiling; at most {remaining_minutes} minutes remain.",
                guidance=f"Propose minutes <= {remaining_minutes}.", field="minutes",
            )

    def propose(self, facts: ProposalFacts, *, request_id: str, adapter_session_id: str | None) -> tuple[TaskProposal, TaskProposal | None]:
        """Validate and store one proposal, superseding any pending one. Returns (new, superseded)."""

        self.validate(facts)
        now = self._now()
        policy_sha256 = self._policy_binding.content_sha256
        previous = self.pending()
        proposal = TaskProposal(
            draft_id=f"draft-{uuid4()}",
            supervision_session_id=self.session_id,
            policy_sha256=policy_sha256,
            source="agent_mcp",
            operation=facts.operation,
            exact_targets=tuple(facts.exact_targets),
            environment=self._environment,
            task_duration_minutes=facts.task_duration_minutes,
            content_sha256=facts.content_sha256(environment=self._environment, policy_sha256=policy_sha256),
            state="pending",
            proposal_number=self._store.next_number(self.session_id),
            created_at=now,
            proposal_expires_at=now + self._ttl,
        )
        superseded = None
        if previous is not None:
            superseded = previous.resolved("superseded", "newer_proposal", at=now, superseded_by=proposal.draft_id)
            self._store.retire(superseded)
            self._write("task_proposal_superseded", superseded, request_id=request_id,
                        extra={"superseded_by": proposal.draft_id})
        self._store.put_pending(proposal)
        self._write("task_proposed", proposal, request_id=request_id,
                    extra={"adapter_session_id": adapter_session_id})
        return proposal, superseded

    # -- human resolution -------------------------------------------------------------

    def require_confirmable(self, draft_id: str) -> TaskProposal:
        """Return the pending draft or raise a precise `ProposalStateError`."""

        proposal = self.get(draft_id)
        if proposal is None:
            raise ProposalStateError("proposal:not_found", "No such task proposal in this session.")
        if proposal.state != "pending":
            raise ProposalStateError(
                f"proposal:{proposal.state}",
                f"This proposal is {proposal.state} and can no longer be confirmed.",
            )
        if proposal.policy_sha256 != self._policy_binding.content_sha256:
            raise ProposalStateError("proposal:ceiling_changed", "The startup ceiling changed since this was proposed.")
        return proposal

    def confirm(self, draft_id: str, *, contract_id: str, task_id: str, request_id: str) -> TaskProposal:
        """Record that the human activated a contract built from this draft."""

        proposal = self.require_confirmable(draft_id)
        confirmed = proposal.resolved(
            "confirmed", "confirmed", at=self._now(),
            confirmed_contract_id=contract_id, confirmed_task_id=task_id,
        )
        self._store.retire(confirmed)
        self._write("task_proposal_confirmed", confirmed, request_id=request_id,
                    extra={"contract_id": contract_id, "task_id": task_id})
        return confirmed

    def dismiss(self, draft_id: str, *, resolution: ProposalResolution, request_id: str) -> TaskProposal:
        proposal = self.require_confirmable(draft_id)
        state = "superseded" if resolution == "adjusted_in_full_form" else "dismissed"
        dismissed = proposal.resolved(state, resolution, at=self._now())
        self._store.retire(dismissed)
        self._write("task_proposal_dismissed", dismissed, request_id=request_id,
                    extra={"resolution": resolution})
        return dismissed

    # -- internals --------------------------------------------------------------------

    def _expire(self, proposal: TaskProposal) -> TaskProposal:
        expired = proposal.resolved("expired", "ttl_elapsed", at=self._now())
        self._store.retire(expired)
        self._write("task_proposal_expired", expired, request_id=None, extra={})
        return expired

    def _write(self, event_type: str, proposal: TaskProposal, *, request_id: str | None, extra: dict) -> None:
        details = {
            "draft_id": proposal.draft_id,
            "content_sha256": proposal.content_sha256,
            "source": proposal.source,
            "operation": proposal.operation,
            "targets": list(proposal.exact_targets),
            "task_duration_minutes": proposal.task_duration_minutes,
            "proposal_number": proposal.proposal_number,
            "state": proposal.state,
            "policy_sha256": proposal.policy_sha256,
            "family": "mcp",
            "tool": "sentinel_task_propose",
        }
        details.update({key: value for key, value in extra.items() if value is not None})
        verdict = {
            "task_proposed": "confirm_required",
            "task_proposal_confirmed": "allow",
        }.get(event_type, "block")
        try:
            self._audit.write(
                AuditEvent(
                    event_type=event_type, request_id=request_id, agent_id=PROPOSAL_AGENT_ID,
                    session_id=self.session_id, task_id=proposal.confirmed_task_id,
                    contract_id=proposal.confirmed_contract_id,
                    environment=self._environment,  # type: ignore[arg-type]
                    verdict=verdict,  # type: ignore[arg-type]
                    reason_codes=[f"proposal:{proposal.state}"],
                    details=details,
                )
            )
        except AuditStoreError:
            # Proposal telemetry is optional evidence. Authority is never derived
            # from these events, so a degraded audit store must not block intake.
            pass


def facts_from_arguments(operation: object, issue_ids: object, minutes: object) -> ProposalFacts:
    """Shape-check raw agent arguments into `ProposalFacts`. Ceiling checks come later."""

    if operation not in ("read", "write"):
        raise ProposalValidationError(
            "proposal:operation_invalid", "operation must be 'read' or 'write'.",
            guidance="Use 'read' to inspect issues or 'write' to add notes.", field="operation",
        )
    if not isinstance(issue_ids, list) or not issue_ids:
        raise ProposalValidationError(
            "proposal:targets_required", "issue_ids must be a non-empty list of issue IDs.",
            guidance="List the exact fixture issue IDs, for example ['SPIKE-1'].", field="issue_ids",
        )
    cleaned: list[str] = []
    for item in issue_ids:
        if not isinstance(item, str) or not item or len(item) > 64 or item != item.strip() or any(ch.isspace() for ch in item):
            raise ProposalValidationError(
                "proposal:target_invalid", "Every issue ID must be a short string without whitespace.",
                guidance="Use IDs exactly as the tracker shows them, for example SPIKE-1.", field="issue_ids",
            )
        if item not in cleaned:
            cleaned.append(item)
    if isinstance(minutes, bool) or not isinstance(minutes, int):
        raise ProposalValidationError(
            "proposal:duration_invalid", "minutes must be a whole number.",
            guidance=f"Propose a duration between 1 and {MAX_TASK_DURATION_MINUTES} minutes.", field="minutes",
        )
    return ProposalFacts(operation=operation, exact_targets=tuple(cleaned), task_duration_minutes=minutes)
