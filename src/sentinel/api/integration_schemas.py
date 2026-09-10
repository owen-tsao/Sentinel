"""Strict schemas for the adapter-facing integration route."""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class StrictIntegrationModel(BaseModel):
    if hasattr(BaseModel, "model_validate"):
        model_config = {"extra": "forbid"}
    else:
        class Config:
            extra = "forbid"


class McpCallRequest(StrictIntegrationModel):
    """Raw adapter input. No verdict, session, identity, or route can be selected here."""

    tool: str = Field(..., min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    attempt_id: str = Field(..., min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")


class McpCallResponse(StrictIntegrationModel):
    request_id: str
    verdict: Literal["allow", "confirm_required", "block"]
    reason_code: str
    reason: str
    reason_codes: list[str] = Field(default_factory=list)
    guidance: str = ""
    risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_tier: str
    attempt_id: str
    approval_id: Optional[str] = None
    operation_state: Optional[str] = None
    result: Optional[dict[str, Any]] = None
    coverage_status: Literal["mandatory", "advisory", "unsupported", "unavailable"]
