"""Pydantic schemas for the Sentinel evaluation API."""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Environment = Literal["sandbox", "dev", "staging", "production"]
Verdict = Literal["allow", "warn", "confirm_required", "block"]
RiskTier = Literal["low", "medium", "high", "critical"]
RoutingPath = Literal["rules", "policy", "model", "combined", "confirmation"]
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


class RecentAction(BaseModel):
    """Structured recent action context supplied by an agent session."""

    type: str = Field(..., min_length=1, description="Kind of action, such as command, file_read, or confirmation.")
    summary: str = Field(..., min_length=1, description="Short human-readable action summary.")
    sensitive_resources: list[str] = Field(
        default_factory=list,
        description="Sensitive resources touched by the action, such as credentials or production logs.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional extra context retained for future policy and audit logic.",
    )


class EvaluateRequest(BaseModel):
    """Request body for POST /evaluate."""

    context: str = Field(..., min_length=1, description="User objective or task context for the proposed command.")
    command: str = Field(..., min_length=1, description="Proposed shell command or tool action to evaluate.")
    recent_actions: list[RecentAction] = Field(
        default_factory=list,
        description="Recent agent actions used for sequence-aware risk evaluation.",
    )
    environment: Environment = Field(..., description="Target environment for the proposed action.")
    shell_type: ShellType = Field(
        default="unknown",
        description="Executor or interpreter context. Kept out of model text until a future retraining step.",
    )
    session_id: str = Field(..., min_length=1, description="Agent session identifier.")
    agent_id: str = Field(..., min_length=1, description="Calling agent identifier.")
    user_id: str = Field(..., min_length=1, description="User or operator identifier.")
    user_confirmed: bool = Field(
        default=False,
        description="Whether a human claims to have confirmed this exact request. Full validation is Week 7 scope.",
    )
    confirmation_token: Optional[str] = Field(
        default=None,
        description="Optional exact-request confirmation token. Token validation is Week 7 scope.",
    )


class EvaluateResponse(BaseModel):
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
    execution: None = Field(
        default=None,
        description="Always null for Week 6 because /evaluate never executes commands.",
    )


class ConfirmRequest(BaseModel):
    """Request body for POST /confirm."""

    confirmation_id: str = Field(..., min_length=1, description="Pending confirmation identifier from /evaluate.")


class ConfirmResponse(BaseModel):
    """Response body for POST /confirm."""

    confirmation_id: str = Field(..., min_length=1)
    confirmation_token: str = Field(..., min_length=1)


class HealthResponse(BaseModel):
    """Response body for GET /health."""

    status: Literal["ok", "degraded"]
    model_loaded: bool
    model_path: Optional[str] = None
    detail: Optional[str] = None

