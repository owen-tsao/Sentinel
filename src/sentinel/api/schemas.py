"""Bounded Pydantic schemas for the Sentinel evaluation API."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, Field, validator

Environment = Literal["sandbox", "dev", "staging", "production"]
Verdict = Literal["allow", "warn", "confirm_required", "block"]
RiskTier = Literal["low", "medium", "high", "critical"]
RoutingPath = Literal["rules", "policy", "model", "combined", "confirmation", "contract", "approval"]
ShellType = Literal[
    "bash",
    "zsh",
    "sh",
    "python",
    "powershell",
    "aws_cli",
    "gcloud_cli",
    "kubectl",
    "terraform",
    "docker",
    "unknown",
]


class StrictModel(BaseModel):
    """Reject unknown authority-shaped fields instead of silently trusting them."""

    if hasattr(BaseModel, "model_validate"):
        model_config = {"extra": "forbid"}
    else:
        class Config:
            extra = "forbid"


class RecentAction(StrictModel):
    """Structured recent action context supplied by an agent session."""

    type: str = Field(..., min_length=1, max_length=100, description="Kind of action, such as command or file_read.")
    summary: str = Field(..., min_length=1, max_length=2_000, description="Short human-readable action summary.")
    sensitive_resources: list[str] = Field(
        default_factory=list,
        max_length=32,
        description="Sensitive resources touched by the action, such as credentials or production logs.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional extra context retained for future policy and audit logic.",
    )

    @validator("sensitive_resources")
    def _bounded_resources(cls, values: list[str]) -> list[str]:
        if any(not value.strip() or len(value) > 1_000 for value in values):
            raise ValueError("sensitive resources must contain 1-1000 characters")
        return values

    @validator("metadata")
    def _bounded_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > 32 or len(json.dumps(value, default=str)) > 10_000:
            raise ValueError("recent action metadata is too large")
        return value


class EvaluateRequest(StrictModel):
    """Legacy local-test request; it does not carry contract authority."""

    context: str = Field(..., min_length=1, max_length=10_000, description="User objective or task context for the proposed command.")
    command: str = Field(
        ...,
        min_length=1,
        max_length=32_000,
        description="Proposed shell command or tool action to evaluate. Capped well below OS argv limits so sandbox execution cannot fail with E2BIG.",
    )
    recent_actions: list[RecentAction] = Field(
        default_factory=list,
        max_length=20,
        description="Recent agent actions used for sequence-aware risk evaluation.",
    )
    environment: Environment = Field(..., description="Target environment for the proposed action.")
    shell_type: ShellType = Field(
        default="unknown",
        description="Executor or interpreter context. Kept out of model text until a future retraining step.",
    )
    session_id: str = Field(..., min_length=1, max_length=500, description="Agent session identifier.")
    agent_id: str = Field(..., min_length=1, max_length=500, description="Calling agent identifier.")
    user_id: str = Field(..., min_length=1, max_length=500, description="User or operator identifier.")
    user_confirmed: bool = Field(
        default=False,
        description="Legacy ignored claim retained only for request compatibility.",
    )
    confirmation_token: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=500,
        description="Legacy ignored token retained only for request compatibility.",
    )

    @validator("recent_actions")
    def _bounded_recent_actions(cls, value: list[RecentAction]) -> list[RecentAction]:
        if len(value) > 20:
            raise ValueError("recent_actions may contain at most 20 items")
        return value


class ShellActionRequest(StrictModel):
    """Untrusted shell proposal; canonical fields are derived on the server."""

    family: Literal["shell"]
    raw_command: str = Field(..., min_length=1, max_length=32_000)
    cwd: str = Field(default="/workspace", min_length=1, max_length=4_096)

    @validator("cwd")
    def _absolute_cwd(cls, value: str) -> str:
        if not Path(value).expanduser().is_absolute():
            raise ValueError("cwd must be an absolute path")
        return value


class ContractEvaluateRequest(StrictModel):
    """Contract-aware request shared by POST /evaluate and POST /execute."""

    contract_id: str = Field(..., min_length=1, max_length=500)
    version: int = Field(..., ge=1, le=2_147_483_647)
    attempt_id: Optional[str] = Field(default=None, min_length=1, max_length=500)
    session_id: str = Field(..., min_length=1, max_length=500)
    agent_id: str = Field(..., min_length=1, max_length=500)
    user_id: str = Field(..., min_length=1, max_length=500)
    action: ShellActionRequest
    approval_token: Optional[str] = Field(default=None, min_length=1, max_length=500)
    recent_actions: list[RecentAction] = Field(
        default_factory=list,
        max_length=20,
        description="Accepted only as untrusted compatibility input and ignored by authorization.",
    )

    @validator("recent_actions")
    def _bounded_recent_actions(cls, value: list[RecentAction]) -> list[RecentAction]:
        if len(value) > 20:
            raise ValueError("recent_actions may contain at most 20 items")
        return value

    @validator("attempt_id")
    def _attempt_id_must_not_be_blank(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not value.strip():
            raise ValueError("attempt_id must not be empty")
        return value


ApiRequest = Union[ContractEvaluateRequest, EvaluateRequest]


class ExecutionResult(StrictModel):
    """Structured output from a sandboxed command execution."""

    stdout: str = Field(default="", description="Captured standard output, capped by executor limits.")
    stderr: str = Field(default="", description="Captured standard error, capped by executor limits.")
    exit_code: Optional[int] = Field(default=None, description="Process exit code, or null if no process completed.")
    timed_out: bool = Field(default=False, description="Whether Sentinel stopped the command after the timeout.")
    duration_ms: int = Field(..., ge=0, description="Execution duration in milliseconds.")
    error: Optional[str] = Field(default=None, description="Sandbox or executor error, if execution could not complete normally.")
    stdout_truncated: bool = Field(default=False, description="Whether captured stdout was truncated.")
    stderr_truncated: bool = Field(default=False, description="Whether captured stderr was truncated.")


class EvaluateResponse(StrictModel):
    """Structured verdict returned by POST /evaluate."""

    request_id: str = Field(..., min_length=1)
    verdict: Verdict
    risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_tier: RiskTier
    reasons: list[str] = Field(default_factory=list)
    routing_path: RoutingPath
    agent_message: str = Field(..., min_length=1)
    suggested_safe_actions: list[str] = Field(default_factory=list)
    confirmation_id: Optional[str] = None
    approval_id: Optional[str] = None
    execution: Optional[ExecutionResult] = Field(
        default=None,
        description="Null for /evaluate; populated by /execute after an allowed sandbox run.",
    )


class HealthResponse(StrictModel):
    """Response body for GET /health."""

    status: Literal["ok", "degraded"]
    model_loaded: bool
    policy_loaded: bool
    audit_status: Literal["ok", "degraded"]
    model_path: Optional[str] = None
    model_detail: Optional[str] = None
    policy_detail: Optional[str] = None
    audit_detail: Optional[str] = None
    detail: Optional[str] = None

