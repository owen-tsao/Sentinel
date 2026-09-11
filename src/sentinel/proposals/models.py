"""Agent task proposals: structured, ceiling-bounded, and never authority.

A proposal is the agent saying "I would like a task shaped like this". Sentinel
stores only the structured facts and a content hash. Nothing here grants
anything; a proposal becomes a task only when the human confirms it through the
protected browser route, which rebuilds the contract from these stored facts.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Literal, Optional

ProposalState = Literal["pending", "confirmed", "superseded", "dismissed", "expired"]
ProposalSource = Literal["agent_mcp"]
ProposalOperation = Literal["read", "write"]
ProposalResolution = Literal[
    "newer_proposal",
    "adjusted_in_full_form",
    "human_dismissed",
    "ttl_elapsed",
    "confirmed",
]

MAX_PROPOSAL_TARGETS = 20
MAX_TASK_DURATION_MINUTES = 1_440


class ProposalError(ValueError):
    """Base for proposal failures; `reason_code` is agent- and audit-facing."""

    def __init__(self, reason_code: str, reason: str, *, guidance: str = "", field: str | None = None) -> None:
        self.reason_code = reason_code
        self.reason = reason
        self.guidance = guidance
        self.field = field
        super().__init__(reason_code)


class ProposalValidationError(ProposalError):
    """The proposal asks for something the ceiling or the schema does not permit."""


class ProposalStateError(ProposalError):
    """The draft exists but is not in a state that allows the requested transition."""


@dataclass(frozen=True)
class ProposalFacts:
    """The structured facts an agent may state. Nothing else is accepted."""

    operation: ProposalOperation
    exact_targets: tuple[str, ...]
    task_duration_minutes: int

    def content_sha256(self, *, environment: str, policy_sha256: str) -> str:
        # Targets are sorted so two equivalent proposals hash identically; the
        # ceiling hash is included so a hash never matches across ceilings.
        payload = {
            "operation": self.operation,
            "exact_targets": sorted(self.exact_targets),
            "task_duration_minutes": self.task_duration_minutes,
            "environment": environment,
            "policy_sha256": policy_sha256,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()


@dataclass(frozen=True)
class TaskProposal:
    draft_id: str
    supervision_session_id: str
    policy_sha256: str
    source: ProposalSource
    operation: ProposalOperation
    exact_targets: tuple[str, ...]
    environment: str
    task_duration_minutes: int
    content_sha256: str
    state: ProposalState
    proposal_number: int
    created_at: datetime
    proposal_expires_at: datetime
    resolution: Optional[ProposalResolution] = None
    resolved_at: Optional[datetime] = None
    superseded_by: Optional[str] = None
    confirmed_contract_id: Optional[str] = None
    confirmed_task_id: Optional[str] = None

    @property
    def objective(self) -> str:
        """Server-derived summary. No agent prose is ever stored or shown."""

        return derive_objective(self.operation, self.exact_targets)

    @property
    def allowed_effects(self) -> tuple[str, ...]:
        return ("read",) if self.operation == "read" else ("read", "write")

    def is_expired(self, now: datetime) -> bool:
        return now >= self.proposal_expires_at

    def resolved(
        self,
        state: ProposalState,
        resolution: ProposalResolution,
        *,
        at: datetime,
        superseded_by: str | None = None,
        confirmed_contract_id: str | None = None,
        confirmed_task_id: str | None = None,
    ) -> "TaskProposal":
        return replace(
            self,
            state=state,
            resolution=resolution,
            resolved_at=at,
            superseded_by=superseded_by,
            confirmed_contract_id=confirmed_contract_id,
            confirmed_task_id=confirmed_task_id,
        )


def derive_objective(operation: ProposalOperation, targets: tuple[str, ...] | list[str]) -> str:
    verb = "Add notes to" if operation == "write" else "Read"
    return f"{verb} fixture issues {', '.join(targets)} through the Sentinel MCP tools."
