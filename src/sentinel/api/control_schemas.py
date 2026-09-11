"""Strict schemas for the protected local control routes."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

from sentinel.api.schemas import EvaluateResponse
from sentinel.audit import AuditEvent
from sentinel.contracts import (
    ActionOperation,
    ContractEnvironment,
    ContractRecord,
)


class StrictControlModel(BaseModel):
    if hasattr(BaseModel, "model_validate"):
        model_config = {"extra": "forbid"}
    else:
        class Config:
            extra = "forbid"


class PairExchangeRequest(StrictControlModel):
    capability: str = Field(..., min_length=32, max_length=512)


class PairExchangeResponse(StrictControlModel):
    paired: Literal[True] = True
    absolute_expires_at: datetime


class ControlWorkspaceResponse(StrictControlModel):
    name: str
    canonical_path: str
    identity_sha256: str = Field(..., min_length=64, max_length=64)


class ControlCheckResponse(StrictControlModel):
    status: Literal["ready", "unavailable"]
    detail: str


class ControlRuntimeStatus(StrictControlModel):
    backend: ControlCheckResponse
    workspace: ControlCheckResponse
    docker: ControlCheckResponse
    rules: ControlCheckResponse
    demo_mode: bool = False
    sample_repository: Optional[str] = None
    # Fixed at process startup; drafts for any other environment are rejected,
    # so the UI should offer only this one.
    execution_environment: Optional[
        Literal["sandbox", "dev", "staging", "production"]
    ] = None


class AgentConnectionResponse(StrictControlModel):
    """Observed adapter connection, derived only from authenticated calls."""

    host: str
    status: Literal["never_connected", "connected", "disconnected"]
    last_seen_at: Optional[datetime] = None
    last_tool: Optional[str] = None
    last_verdict: Optional[str] = None
    mediated_calls: int = 0
    rejected_calls: int = 0
    adapter_session_expires_at: Optional[datetime] = None


class FamilyCoverageResponse(StrictControlModel):
    """Per-family coverage; never summarised as a single protected state."""

    family: str
    status: Literal["mandatory", "advisory", "unsupported", "unavailable"]
    basis: str
    conditions: list[str] = Field(default_factory=list)
    known_bypasses: list[str] = Field(default_factory=list)


class CeilingStatusResponse(StrictControlModel):
    adapter_kind: str
    tool_family: str
    policy_sha256: str
    expires_at: datetime
    expired: bool


class IntegrationStatusResponse(StrictControlModel):
    """Everything the control center may show about the mandatory MCP path."""

    gateway: ControlCheckResponse
    hooks: ControlCheckResponse
    sandbox: ControlCheckResponse
    ceiling: CeilingStatusResponse
    agent: AgentConnectionResponse
    coverage: list[FamilyCoverageResponse]


class ControlStatusResponse(StrictControlModel):
    paired: Literal[True] = True
    supervision_session_id: str
    session_absolute_expires_at: datetime
    workspace: ControlWorkspaceResponse
    runtime: ControlRuntimeStatus
    ml_status: Literal["disabled"] = "disabled"
    mandatory_agent_connected: bool = False
    connection_message: str = "No mandatory agent connected."
    integration: Optional[IntegrationStatusResponse] = None


class LogoutResponse(StrictControlModel):
    logged_out: Literal[True] = True


class PendingApprovalResponse(StrictControlModel):
    approval_id: str
    attempt_id: str
    operation: str
    raw_command: str
    targets: list[str]
    effects: list[str]
    workspace: str
    task_id: str
    contract_id: str
    contract_version: int
    authority_epoch: int
    environment: str
    reasons: list[str]
    expires_at: datetime
    family: str = "shell"
    tool: Optional[str] = None
    arguments: dict[str, Any] = Field(default_factory=dict)


class ApprovalListResponse(StrictControlModel):
    approvals: list[PendingApprovalResponse]


class ApprovalDecisionRequest(StrictControlModel):
    typed_target: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=4_000,
    )


class ApprovalActionResponse(StrictControlModel):
    approval_id: str
    status: Literal["approved", "denied"]
    retry: Optional[EvaluateResponse] = None


class AcceptedContractDraft(StrictControlModel):
    operation: ActionOperation
    exact_targets: list[str] = Field(..., min_length=1, max_length=100)
    environment: ContractEnvironment
    expected_side_effects: list[str] = Field(..., min_length=1, max_length=100)
    allowed_effects: set[str] = Field(..., min_length=1, max_length=100)
    forbidden_operations: set[ActionOperation] = Field(default_factory=set)
    forbidden_effects: list[str] = Field(..., min_length=1, max_length=100)
    forbidden_effect_codes: set[str] = Field(default_factory=set)
    rollback_plan: str = Field(..., min_length=1, max_length=2_000)
    dry_run_required: bool
    rollback_required: bool = False
    transaction_required: bool = False
    backup_required: bool = False
    expires_in_minutes: int = Field(default=60, ge=1, le=1_440)
    tool_family: Literal["shell", "sentinel_issue_fixture"] = "shell"


class ContractDraftRequest(StrictControlModel):
    raw_prompt: str = Field(..., min_length=1, max_length=32_000)
    accepted_contract: Optional[AcceptedContractDraft] = None


class DraftSuggestionResponse(StrictControlModel):
    field: str
    value: Any
    source: Literal[
        "prompt_explicit",
        "prompt_inference",
        "deterministic_derivation",
        "safe_default",
    ]
    requires_review: Literal[True] = True


class DraftQuestionResponse(StrictControlModel):
    question_id: str
    field: str
    prompt: str


class ContractDraftResponse(StrictControlModel):
    prompt_sha256: str
    suggestions: list[DraftSuggestionResponse]
    questions: list[DraftQuestionResponse]
    proposed_contract: Optional[ContractRecord] = None


class TargetSuggestion(StrictControlModel):
    path: str
    kind: Literal["file", "directory"]


class TargetSuggestionsResponse(StrictControlModel):
    """Paths the task form can offer. Suggestions only: the server still
    validates every accepted target, so an omitted path is never a denial."""

    workspace_root: str
    paths: list[TargetSuggestion]
    truncated: bool = False
    fixture_issues: list[str] = Field(default_factory=list)


class ContractActivationRequest(StrictControlModel):
    contract_id: str = Field(..., min_length=1, max_length=500)
    expected_version: int = Field(..., ge=1)
    expected_active_task_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=500,
    )


class ContractActivationResponse(StrictControlModel):
    active_contract: ContractRecord


class ActiveAuthorityResponse(StrictControlModel):
    active_contract: Optional[ContractRecord] = None


class TaskProposalResponse(StrictControlModel):
    """One agent task proposal as stored by the server. Never contains agent prose."""

    draft_id: str
    state: Literal["pending", "confirmed", "superseded", "dismissed", "expired"]
    source: Literal["agent_mcp"]
    objective: str
    operation: Literal["read", "write"]
    exact_targets: list[str]
    environment: str
    allowed_effects: list[str]
    task_duration_minutes: int
    content_sha256: str = Field(..., min_length=64, max_length=64)
    proposal_number: int = Field(..., ge=1)
    created_at: datetime
    proposal_expires_at: datetime
    replaces_active_task: bool = False
    resolution: Optional[str] = None
    resolved_at: Optional[datetime] = None
    confirmed_contract_id: Optional[str] = None


class PendingProposalResponse(StrictControlModel):
    proposal: Optional[TaskProposalResponse] = None
    recent: list[TaskProposalResponse] = Field(default_factory=list)


class ProposalConfirmRequest(StrictControlModel):
    """Only a concurrency guard. Every authority fact comes from the stored draft.

    The field is required so that `null` unambiguously means "my view showed no
    active task"; omitting it is a 422, never a skipped check.
    """

    expected_active_task_id: Optional[str] = Field(
        ...,
        min_length=1,
        max_length=500,
    )


class ProposalConfirmResponse(StrictControlModel):
    draft_id: str
    active_contract: ContractRecord


class ProposalDismissResponse(StrictControlModel):
    draft_id: str
    state: Literal["dismissed", "superseded"]


class ProposalAdjustResponse(StrictControlModel):
    """Prefill for the full form. The draft is consumed the moment this is issued."""

    draft_id: str
    raw_prompt: str
    accepted_contract: AcceptedContractDraft


class AuditListResponse(StrictControlModel):
    events: list[AuditEvent]
