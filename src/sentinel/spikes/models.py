"""Sanitized result models for manual live metadata probes."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Literal

from pydantic import BaseModel, Field, root_validator, validator

from sentinel.actions import CanonicalAction


SpikeProvider = Literal["slack", "google_drive", "gmail", "google_calendar"]
SpikeStatus = Literal["complete", "incomplete"]


class StrictModel(BaseModel):
    class Config:
        extra = "forbid"


class FieldCoverage(StrictModel):
    required: list[str]
    present: list[str]
    missing: list[str]

    @validator("required", "present", "missing")
    def _canonical_fields(cls, value: list[str]) -> list[str]:
        return sorted({item.strip() for item in value if item.strip()})

    @root_validator(skip_on_failure=True)
    def _missing_fields_are_derived(
        cls,
        values: dict[str, object],
    ) -> dict[str, object]:
        required = set(values.get("required") or [])
        present = set(values.get("present") or [])
        missing = set(values.get("missing") or [])
        if missing != required - present:
            raise ValueError("missing fields must equal required fields minus present fields")
        return values


class ProbeSummary(StrictModel):
    """Safe-to-save spike summary, not proof of permission or enforcement."""

    schema_version: Literal["sentinel-live-metadata-spike-v1"] = (
        "sentinel-live-metadata-spike-v1"
    )
    production_enforcement: bool = False
    provider: SpikeProvider
    status: SpikeStatus
    adapter_id: str
    api_call_count: int = Field(..., ge=1, le=10_000)
    audience_count: int = Field(..., ge=0)
    recipient_count: int = Field(..., ge=0)
    external_recipient_count: int = Field(..., ge=0)
    guest_recipient_count: int = Field(..., ge=0)
    public_audience: bool
    resource_fingerprints: list[str] = Field(default_factory=list)
    field_coverage: FieldCoverage
    limitations: list[str] = Field(default_factory=list)

    @root_validator(skip_on_failure=True)
    def _complete_status_requires_full_coverage(
        cls,
        values: dict[str, object],
    ) -> dict[str, object]:
        coverage = values.get("field_coverage")
        if (
            values.get("status") == "complete"
            and isinstance(coverage, FieldCoverage)
            and coverage.missing
        ):
            raise ValueError("complete probe summaries cannot have missing fields")
        return values


class ProbeResult(StrictModel):
    """In-memory normalized action plus its sanitized report."""

    action: CanonicalAction
    summary: ProbeSummary


def build_probe_result(
    *,
    provider: SpikeProvider,
    action: CanonicalAction,
    adapter_id: str,
    api_call_count: int,
    required_fields: set[str],
    present_fields: set[str],
    limitations: list[str],
) -> ProbeResult:
    evidence = action.resolved_evidence
    if evidence is None:
        raise ValueError("probe action requires resolved evidence")
    audiences = evidence.audiences
    recipient_ids = {
        recipient for audience in audiences for recipient in audience.recipient_ids
    }
    external_ids = {
        recipient
        for audience in audiences
        for recipient in audience.external_recipient_ids
    }
    guest_ids = {
        recipient
        for audience in audiences
        for recipient in audience.guest_recipient_ids
    }
    missing = required_fields - present_fields
    complete = (
        evidence.resolution_complete
        and not missing
        and all(audience.resolution_complete for audience in audiences)
    )
    fingerprint_key = secrets.token_bytes(32)
    summary = ProbeSummary(
        provider=provider,
        status="complete" if complete else "incomplete",
        adapter_id=adapter_id,
        api_call_count=api_call_count,
        audience_count=len(audiences),
        recipient_count=len(recipient_ids),
        external_recipient_count=len(external_ids),
        guest_recipient_count=len(guest_ids),
        public_audience=any(audience.is_public for audience in audiences),
        resource_fingerprints=[
            hmac.new(
                fingerprint_key,
                audience.resource_id.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            for audience in audiences
        ],
        field_coverage=FieldCoverage(
            required=sorted(required_fields),
            present=sorted(present_fields),
            missing=sorted(missing),
        ),
        limitations=limitations,
    )
    return ProbeResult(action=action, summary=summary)
