"""Provider-neutral facts resolved by trusted action adapters.

These models contain normalized facts, not caller claims. Current-state facts
describe what exists at retrieval time; they do not grant permission to perform
an action. HTTP request schemas must accept raw provider actions and let a
server-owned adapter populate evidence immediately before policy evaluation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, root_validator, validator


ProviderName = Literal["slack", "gmail", "google_calendar", "google_drive"]
AudienceKind = Literal[
    "channel",
    "direct_message",
    "group_message",
    "email",
    "calendar_event",
    "file",
]
EvidenceSourceType = Literal["provider_api", "official_schema_fixture"]
EvidencePhase = Literal["current_state", "projected_effect", "verified_postcondition"]


class StrictModel(BaseModel):
    """Reject unknown security fields instead of silently discarding them."""

    if hasattr(BaseModel, "model_validate"):
        model_config = {"extra": "forbid"}
    else:
        class Config:
            extra = "forbid"


class ProviderContext(StrictModel):
    """Stable provider identity bound to the credential used for execution."""

    provider: ProviderName
    tenant_id: str = Field(..., min_length=1, max_length=500)
    resource_account_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=500,
    )
    credential_principal_id: str = Field(..., min_length=1, max_length=500)
    actor_id: Optional[str] = Field(default=None, min_length=1, max_length=500)
    adapter_id: str = Field(..., min_length=1, max_length=500)


class ProviderScope(StrictModel):
    """Provider identity constraints explicitly accepted in a task contract."""

    provider: ProviderName
    tenant_id: str = Field(..., min_length=1, max_length=500)
    resource_account_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=500,
    )
    credential_principal_id: str = Field(..., min_length=1, max_length=500)
    actor_id: Optional[str] = Field(default=None, min_length=1, max_length=500)
    adapter_id: str = Field(..., min_length=1, max_length=500)


class AudiencePolicy(StrictModel):
    """Machine-checkable limits on who may receive or access an action."""

    allow_external: bool = False
    allow_guests: bool = False
    allow_public: bool = False
    allow_broadcast: bool = False
    allow_recipient_expansion: bool = False
    maximum_recipient_count: Optional[int] = Field(default=None, ge=1, le=100_000)
    allowed_recipient_ids: Optional[set[str]] = None
    allowed_audience_resource_ids: Optional[set[str]] = None

    @validator("allowed_recipient_ids", "allowed_audience_resource_ids", pre=True)
    def _bound_raw_allowed_ids(cls, value: Any) -> Any:
        if value is not None and len(value) > 10_000:
            raise ValueError("audience policy ID sets may contain at most 10000 items")
        return value

    @validator("allowed_recipient_ids", "allowed_audience_resource_ids")
    def _canonical_allowed_ids(
        cls,
        value: Optional[set[str]],
    ) -> Optional[set[str]]:
        if value is None:
            return None
        cleaned = {item.strip() for item in value if item.strip()}
        return cleaned


class AudienceSnapshot(StrictModel):
    """Fresh provider facts describing one resolved destination or resource."""

    resource_id: str = Field(..., min_length=1, max_length=1_000)
    canonical_target: str = Field(..., min_length=1, max_length=1_000)
    kind: AudienceKind
    tenant_id: str = Field(..., min_length=1, max_length=500)
    recipient_ids: list[str] = Field(default_factory=list, max_length=10_000)
    external_recipient_ids: list[str] = Field(default_factory=list, max_length=10_000)
    guest_recipient_ids: list[str] = Field(default_factory=list, max_length=10_000)
    recipient_count: int = Field(..., ge=0, le=100_000)
    is_public: bool = False
    is_external_shared: bool = False
    is_broadcast: bool = False
    allows_recipient_expansion: bool = False
    resolution_complete: bool = True
    state_version: Optional[str] = Field(default=None, min_length=1, max_length=500)

    @validator(
        "recipient_ids",
        "external_recipient_ids",
        "guest_recipient_ids",
        pre=True,
    )
    def _bound_raw_recipient_ids(cls, value: Any) -> Any:
        if len(value) > 10_000:
            raise ValueError("recipient ID lists may contain at most 10000 items")
        return value

    @validator(
        "recipient_ids",
        "external_recipient_ids",
        "guest_recipient_ids",
    )
    def _canonical_ids(cls, value: list[str]) -> list[str]:
        cleaned = {item.strip() for item in value if item.strip()}
        return sorted(cleaned)

    @root_validator(skip_on_failure=True)
    def _validate_recipient_sets(cls, values: dict[str, Any]) -> dict[str, Any]:
        recipients = set(values.get("recipient_ids") or [])
        external = set(values.get("external_recipient_ids") or [])
        guests = set(values.get("guest_recipient_ids") or [])
        if not external.issubset(recipients) or not guests.issubset(recipients):
            raise ValueError("external and guest recipients must be resolved recipients")
        if values.get("recipient_count", 0) < len(recipients):
            raise ValueError("recipient_count cannot be smaller than resolved recipients")
        if values.get("resolution_complete") and values.get("recipient_count") != len(
            recipients
        ):
            raise ValueError(
                "complete audience evidence must enumerate every recipient"
            )
        return values


class FactProvenance(StrictModel):
    """Where and when an adapter obtained the normalized provider facts."""

    source_type: EvidenceSourceType
    source_endpoint: str = Field(..., min_length=1, max_length=1_000)
    source_fields: list[str] = Field(..., min_length=1, max_length=100)
    documentation_url: str = Field(..., min_length=1, max_length=2_000)
    retrieved_at: datetime
    valid_until: datetime

    @validator("source_fields", pre=True)
    def _bound_raw_source_fields(cls, value: Any) -> Any:
        if len(value) > 100:
            raise ValueError("source_fields may contain at most 100 items")
        return value

    @validator("source_fields")
    def _canonical_fields(cls, value: list[str]) -> list[str]:
        cleaned = {item.strip() for item in value if item.strip()}
        if not cleaned:
            raise ValueError("source_fields must not be empty")
        return sorted(cleaned)

    @validator("documentation_url")
    def _official_https_url(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("documentation_url must use https")
        return value

    @validator("retrieved_at", "valid_until")
    def _normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @root_validator(skip_on_failure=True)
    def _expiry_follows_retrieval(cls, values: dict[str, Any]) -> dict[str, Any]:
        retrieved_at = values.get("retrieved_at")
        valid_until = values.get("valid_until")
        if retrieved_at and valid_until and valid_until <= retrieved_at:
            raise ValueError("valid_until must be after retrieved_at")
        return values


class ResolvedActionEvidence(StrictModel):
    """Adapter-resolved facts bound to one canonical action."""

    provider_context: ProviderContext
    audiences: list[AudienceSnapshot] = Field(default_factory=list, max_length=100)
    provenance: FactProvenance
    phase: EvidencePhase
    resolution_complete: bool = True
    metadata_sha256: str = Field(..., min_length=64, max_length=64)
    action_binding_sha256: str = Field(..., min_length=64, max_length=64)

    @validator("audiences", pre=True)
    def _bound_raw_audiences(cls, value: Any) -> Any:
        if len(value) > 100:
            raise ValueError("audiences may contain at most 100 items")
        return value

    @validator("audiences")
    def _canonical_audiences(
        cls,
        value: list[AudienceSnapshot],
    ) -> list[AudienceSnapshot]:
        resource_ids = [audience.resource_id for audience in value]
        if len(resource_ids) != len(set(resource_ids)):
            raise ValueError("audience resource IDs must be unique")
        return sorted(value, key=lambda audience: audience.resource_id)

    @validator("metadata_sha256", "action_binding_sha256")
    def _sha256_hex(cls, value: str) -> str:
        normalized = value.lower()
        if any(character not in "0123456789abcdef" for character in normalized):
            raise ValueError("metadata_sha256 must be lowercase hexadecimal")
        return normalized

    @root_validator(skip_on_failure=True)
    def _complete_evidence_requires_complete_audiences(
        cls,
        values: dict[str, Any],
    ) -> dict[str, Any]:
        if values.get("resolution_complete") and any(
            not audience.resolution_complete
            for audience in values.get("audiences") or []
        ):
            raise ValueError(
                "complete resolved evidence cannot contain an incomplete audience"
            )
        return values
