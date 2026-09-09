"""Typed audit event and query models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

AuditVerdict = Literal["allow", "warn", "confirm_required", "block"]
AuditEnvironment = Literal["sandbox", "dev", "staging", "production"]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class StrictModel(BaseModel):
    """Pydantic v1/v2 compatible base that rejects unknown fields."""

    if hasattr(BaseModel, "model_validate"):
        model_config = {"extra": "forbid"}
    else:
        class Config:
            extra = "forbid"


class AuditEvent(StrictModel):
    """One append-only security or lifecycle event."""

    event_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
    sequence_id: Optional[int] = Field(default=None, ge=1)
    event_type: str = Field(..., min_length=1)
    timestamp: datetime = Field(default_factory=_utc_now)
    request_id: Optional[str] = None
    user_id: Optional[str] = None
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    task_id: Optional[str] = None
    contract_id: Optional[str] = None
    contract_version: Optional[int] = Field(default=None, ge=1)
    environment: Optional[AuditEnvironment] = None
    verdict: Optional[AuditVerdict] = None
    reason_codes: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class AuditQuery(StrictModel):
    """Indexed filters supported by an audit backend."""

    event_type: Optional[str] = None
    verdict: Optional[AuditVerdict] = None
    environment: Optional[AuditEnvironment] = None
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    task_id: Optional[str] = None
    contract_id: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: Optional[int] = Field(default=None, ge=1, le=10_000)


class AuditHealth(StrictModel):
    """Storage health exposed without hiding buffered evidence."""

    status: Literal["ok", "degraded"]
    detail: Optional[str] = None
    fallback_event_count: int = Field(ge=0)
    fallback_capacity: int = Field(ge=0)
