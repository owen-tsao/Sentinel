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


class ControlStatusResponse(StrictControlModel):
    paired: Literal[True] = True
    supervision_session_id: str
    session_absolute_expires_at: datetime
    workspace: ControlWorkspaceResponse
    runtime: ControlRuntimeStatus
    ml_status: Literal["disabled"] = "disabled"
    mandatory_agent_connected: Literal[False] = False
    connection_message: Literal["No mandatory agent connected."] = (
        "No mandatory agent connected."
    )


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


class AuditListResponse(StrictControlModel):
    events: list[AuditEvent]
