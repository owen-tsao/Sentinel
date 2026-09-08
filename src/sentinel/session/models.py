"""Typed server-owned session state."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, root_validator, validator


MAX_ATTEMPT_RESPONSE_BYTES = 256 * 1024
ExecutionAttemptState = Literal[
    "reserved",
    "running",
    "completed",
    "failed",
    "unknown",
]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class StrictModel(BaseModel):
    """Pydantic v1/v2 compatible base that rejects unknown fields."""

    if hasattr(BaseModel, "model_validate"):
        model_config = {"extra": "forbid"}
    else:
        class Config:
            extra = "forbid"


class FrozenStrictModel(StrictModel):
    """Immutable strict model for authority-bearing attempt bindings."""

    if hasattr(BaseModel, "model_validate"):
        model_config = {"extra": "forbid", "frozen": True}
    else:
        class Config:
            extra = "forbid"
            allow_mutation = False


class ExecutionAttemptBinding(FrozenStrictModel):
    """Every field that makes one execution attempt unique and replay-safe."""

    attempt_id: str = Field(..., min_length=1, max_length=500)
    session_id: str = Field(..., min_length=1, max_length=500)
    task_id: str = Field(..., min_length=1, max_length=500)
    contract_id: str = Field(..., min_length=1, max_length=500)
    contract_version: int = Field(..., ge=1, le=2_147_483_647)
    authority_epoch: int = Field(..., ge=0, le=2_147_483_647)
    action_fingerprint: str = Field(..., min_length=64, max_length=64)
    environment: Literal["sandbox", "dev", "staging", "production"]

    @validator("attempt_id", "session_id", "task_id", "contract_id")
    def _identifier_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("attempt binding identifiers must not be blank")
        return value

    @validator("action_fingerprint")
    def _fingerprint_must_be_sha256(cls, value: str) -> str:
        normalized = value.lower()
        if any(character not in "0123456789abcdef" for character in normalized):
            raise ValueError("action_fingerprint must be lowercase hexadecimal")
        return normalized


class ExecutionAttempt(StrictModel):
    """Durable state for one exact executor admission."""

    binding: ExecutionAttemptBinding
    state: ExecutionAttemptState
    reserved_at: datetime
    updated_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    response_payload: Optional[dict[str, Any]] = None

    @property
    def attempt_id(self) -> str:
        return self.binding.attempt_id

    @validator("reserved_at", "updated_at", "started_at", "finished_at")
    def _normalize_timestamp(cls, value: Optional[datetime]) -> Optional[datetime]:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @validator("response_payload")
    def _response_must_be_bounded_json(
        cls,
        value: Optional[dict[str, Any]],
    ) -> Optional[dict[str, Any]]:
        if value is None:
            return None
        try:
            encoded = json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("response_payload must be JSON-safe") from exc
        if len(encoded) > MAX_ATTEMPT_RESPONSE_BYTES:
            raise ValueError("response_payload exceeds the bounded storage limit")
        return value

    @root_validator(skip_on_failure=True)
    def _state_fields_are_consistent(cls, values: dict[str, Any]) -> dict[str, Any]:
        state = values.get("state")
        response = values.get("response_payload")
        if state in {"completed", "failed"} and response is None:
            raise ValueError("terminal attempts require response_payload")
        if state not in {"completed", "failed"} and response is not None:
            raise ValueError("nonterminal attempts cannot have response_payload")
        return values


class SessionAction(StrictModel):
    """One action retained in a session's bounded recent-history window."""

    action_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
    action_type: str = Field(..., min_length=1)
    summary: str = Field(..., min_length=1)
    task_id: str = Field(..., min_length=1)
    timestamp: datetime = Field(default_factory=utc_now)
    sensitive_resources: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @validator("task_id")
    def _task_id_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("task_id must not be empty")
        return value
