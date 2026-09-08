"""Trusted facts and authority limits used by contextual contract policy.

These models are internal policy inputs. Public request schemas must never accept
them directly; adapters, protected review fixtures, and server-owned ledgers are
responsible for constructing them.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, root_validator, validator

from sentinel.contracts import ContractEnvironment


ContextEvidenceSource = Literal[
    "reviewed_fixture",
    "trusted_adapter",
    "trusted_filesystem",
    "server_ledger",
]


class StrictModel(BaseModel):
    """Reject unknown policy fields instead of silently ignoring them."""

    class Config:
        extra = "forbid"


class ActionMeasurement(StrictModel):
    """One measured quantity produced by the proposed action."""

    metric: str = Field(..., min_length=1, max_length=200)
    amount: Decimal = Field(..., ge=0)
    unit: str = Field(..., min_length=1, max_length=50)
    target: Optional[str] = Field(default=None, min_length=1, max_length=1_000)

    @validator("metric", "unit")
    def _normalize_identifier(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("measurement identifiers must not be blank")
        return normalized

    @validator("target")
    def _normalize_target(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("measurement target must not be blank")
        return normalized


class UsageRecord(ActionMeasurement):
    """One server-recorded prior use of a limited task resource."""

    task_id: str = Field(..., min_length=1, max_length=500)
    successful: bool = True


class AuthorizedCumulativeLimit(StrictModel):
    """A reviewed cumulative ceiling, kept separate from observed facts."""

    metric: str = Field(..., min_length=1, max_length=200)
    maximum: Decimal = Field(..., ge=0)
    unit: str = Field(..., min_length=1, max_length=50)
    target: Optional[str] = Field(default=None, min_length=1, max_length=1_000)

    @validator("metric", "unit")
    def _normalize_identifier(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("limit identifiers must not be blank")
        return normalized

    @validator("target")
    def _normalize_target(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("limit target must not be blank")
        return normalized


class ContractEvaluationFacts(StrictModel):
    """Trusted resolution facts about the exact proposed action."""

    resolved_targets: list[str] = Field(default_factory=list, max_length=1_000)
    resolved_effects: set[str] = Field(default_factory=set, max_length=1_000)
    dry_run_verified: Optional[bool] = None
    backup_verified: Optional[bool] = None
    rollback_verified: Optional[bool] = None
    transaction_verified: Optional[bool] = None
    measurements: list[ActionMeasurement] = Field(
        default_factory=list,
        max_length=100,
    )

    @validator("measurements", pre=True)
    def _bound_raw_measurements(cls, value: Any) -> Any:
        if len(value) > 100:
            raise ValueError("measurements may contain at most 100 items")
        return value

    @validator("resolved_targets", pre=True)
    def _bound_raw_targets(cls, value: Any) -> Any:
        if len(value) > 1_000:
            raise ValueError("resolved targets may contain at most 1000 items")
        return value

    @validator("resolved_targets")
    def _canonical_targets(cls, value: list[str]) -> list[str]:
        return sorted({target.strip() for target in value if target.strip()})

    @validator("resolved_effects", pre=True)
    def _bound_raw_effects(cls, value: Any) -> Any:
        if len(value) > 1_000:
            raise ValueError("resolved effects may contain at most 1000 items")
        return value

    @validator("resolved_effects")
    def _canonical_effects(cls, value: set[str]) -> set[str]:
        return {effect.strip().lower() for effect in value if effect.strip()}


class ContractEvaluationContext(StrictModel):
    """Evidence bound to one contract/action/session decision."""

    source: ContextEvidenceSource
    producer_id: str = Field(..., min_length=1, max_length=500)
    snapshot_revision: str = Field(..., min_length=1, max_length=500)
    action_fingerprint: str = Field(..., min_length=64, max_length=64)
    contract_id: str = Field(..., min_length=1, max_length=500)
    contract_version: int = Field(..., ge=1)
    authority_epoch: int = Field(..., ge=0)
    session_id: str = Field(..., min_length=1, max_length=500)
    task_id: str = Field(..., min_length=1, max_length=500)
    environment: ContractEnvironment
    observed_at: datetime
    valid_until: datetime
    facts: ContractEvaluationFacts = Field(default_factory=ContractEvaluationFacts)
    authorized_limits: list[AuthorizedCumulativeLimit] = Field(
        default_factory=list,
        max_length=100,
    )
    recent_usage: list[UsageRecord] = Field(default_factory=list, max_length=10_000)

    @validator("authorized_limits", pre=True)
    def _bound_raw_limits(cls, value: Any) -> Any:
        if len(value) > 100:
            raise ValueError("authorized limits may contain at most 100 items")
        return value

    @validator("recent_usage", pre=True)
    def _bound_raw_usage(cls, value: Any) -> Any:
        if len(value) > 10_000:
            raise ValueError("recent usage may contain at most 10000 items")
        return value

    @validator("action_fingerprint")
    def _sha256_hex(cls, value: str) -> str:
        normalized = value.lower()
        if any(character not in "0123456789abcdef" for character in normalized):
            raise ValueError("action_fingerprint must be lowercase hexadecimal")
        return normalized

    @validator("producer_id", "snapshot_revision")
    def _nonblank_identity(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("context evidence identity must not be blank")
        return normalized

    @validator("observed_at", "valid_until")
    def _normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @root_validator(skip_on_failure=True)
    def _validity_follows_observation(
        cls,
        values: dict[str, Any],
    ) -> dict[str, Any]:
        observed_at = values.get("observed_at")
        valid_until = values.get("valid_until")
        if observed_at and valid_until and valid_until <= observed_at:
            raise ValueError("valid_until must be after observed_at")
        return values
