"""Host-neutral canonical actions used by contract enforcement."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, validator

from sentinel.contracts import ActionOperation, ContractEnvironment
from sentinel.platforms import ResolvedActionEvidence

ActionFamily = Literal["shell", "file", "mcp", "git", "database", "cloud", "deployment"]


class StrictModel(BaseModel):
    """Pydantic v1/v2 compatible base that rejects unknown fields."""

    if hasattr(BaseModel, "model_validate"):
        model_config = {"extra": "forbid"}
    else:
        class Config:
            extra = "forbid"


class CanonicalAction(StrictModel):
    """One inspectable action including every target and expected effect."""

    family: ActionFamily
    tool: Optional[str] = None
    operation: ActionOperation
    targets: list[str] = Field(default_factory=list)
    audience_targets: list[str] = Field(default_factory=list)
    effects: set[str] = Field(default_factory=set)
    environment: ContractEnvironment
    environment_context: dict[str, str] = Field(default_factory=dict)
    dry_run: bool = False
    rollback_available: bool = False
    transaction: bool = False
    backup_available: bool = False
    payload_sha256: Optional[str] = Field(default=None, min_length=64, max_length=64)
    requested_execution_at: Optional[datetime] = None
    resolved_evidence: Optional[ResolvedActionEvidence] = None
    canonical_command: Optional[str] = None
    raw_command: Optional[str] = Field(default=None, max_length=32_000)

    @validator("targets", "audience_targets")
    def _canonical_targets(cls, value: list[str]) -> list[str]:
        cleaned = {item.strip() for item in value if item.strip()}
        return sorted(cleaned)

    @validator("effects")
    def _canonical_effects(cls, value: set[str]) -> set[str]:
        return {item.strip().lower() for item in value if item.strip()}

    @validator("payload_sha256")
    def _sha256_hex(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.lower()
        if any(character not in "0123456789abcdef" for character in normalized):
            raise ValueError("payload_sha256 must be lowercase hexadecimal")
        return normalized

    @validator("requested_execution_at")
    def _normalize_execution_time(
        cls,
        value: Optional[datetime],
    ) -> Optional[datetime]:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


def fingerprint_action(action: CanonicalAction) -> str:
    """Hash security-relevant canonical fields, including all targets/effects."""

    checked = CanonicalAction(**_model_payload(action))
    payload = {
        "family": checked.family,
        "tool": checked.tool,
        "operation": checked.operation,
        "targets": checked.targets,
        "audience_targets": checked.audience_targets,
        "effects": sorted(checked.effects),
        "environment": checked.environment,
        "environment_context": checked.environment_context,
        "dry_run": checked.dry_run,
        "rollback_available": checked.rollback_available,
        "transaction": checked.transaction,
        "backup_available": checked.backup_available,
        "payload_sha256": checked.payload_sha256,
        "requested_execution_at": (
            checked.requested_execution_at.isoformat()
            if checked.requested_execution_at is not None
            else None
        ),
        "resolved_evidence": (
            _json_model_payload(checked.resolved_evidence)
            if checked.resolved_evidence is not None
            else None
        ),
        "canonical_command": checked.canonical_command,
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def compute_action_evidence_binding(action: CanonicalAction) -> str:
    """Bind trusted evidence to the exact canonical request it describes."""

    checked = CanonicalAction(**_model_payload(action))
    if checked.resolved_evidence is None:
        raise ValueError("resolved evidence is required")
    evidence_payload = _json_model_payload(checked.resolved_evidence)
    evidence_payload.pop("action_binding_sha256", None)
    payload = {
        "family": checked.family,
        "tool": checked.tool,
        "operation": checked.operation,
        "targets": checked.targets,
        "audience_targets": checked.audience_targets,
        "effects": sorted(checked.effects),
        "environment": checked.environment,
        "environment_context": checked.environment_context,
        "payload_sha256": checked.payload_sha256,
        "requested_execution_at": (
            checked.requested_execution_at.isoformat()
            if checked.requested_execution_at is not None
            else None
        ),
        "canonical_command": checked.canonical_command,
        "resolved_evidence": evidence_payload,
    }
    execution_flags = {
        "dry_run": checked.dry_run,
        "rollback_available": checked.rollback_available,
        "transaction": checked.transaction,
        "backup_available": checked.backup_available,
    }
    # Preserve the reviewed v1 fixture hash for the implicit all-false tuple.
    # Any non-default tuple is explicit, so changing either direction invalidates it.
    if any(execution_flags.values()):
        payload.update(execution_flags)
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


canonical_action_fingerprint = fingerprint_action


def _model_payload(model: BaseModel) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="python", warnings=False)
    return model.dict()


def _json_model_payload(model: BaseModel) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="json", warnings=False)
    return json.loads(model.json())
