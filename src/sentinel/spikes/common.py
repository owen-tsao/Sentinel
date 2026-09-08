"""Shared normalization helpers for read-only provider probes."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import BaseModel

from sentinel.actions import CanonicalAction, compute_action_evidence_binding
from sentinel.platforms import (
    AudienceSnapshot,
    EvidencePhase,
    FactProvenance,
    ProviderContext,
    ResolvedActionEvidence,
)


class LiveSpikeError(RuntimeError):
    """A live probe cannot produce complete, trustworthy metadata."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def canonical_sha256(value: Any) -> str:
    serialized = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def make_provenance(
    *,
    source_endpoint: str,
    source_fields: set[str],
    documentation_url: str,
    retrieved_at: datetime,
    ttl: timedelta = timedelta(minutes=5),
) -> FactProvenance:
    return FactProvenance(
        source_type="provider_api",
        source_endpoint=source_endpoint,
        source_fields=sorted(source_fields),
        documentation_url=documentation_url,
        retrieved_at=retrieved_at,
        valid_until=retrieved_at + ttl,
    )


def attach_evidence(
    action: CanonicalAction,
    *,
    provider_context: ProviderContext,
    audiences: list[AudienceSnapshot],
    provenance: FactProvenance,
    resolution_complete: bool,
    phase: EvidencePhase = "projected_effect",
) -> CanonicalAction:
    metadata_payload = {
        "provider_context": _json_payload(provider_context),
        "audiences": [_json_payload(audience) for audience in audiences],
        "provenance": _json_payload(provenance),
        "phase": phase,
        "resolution_complete": resolution_complete,
    }
    provisional_evidence = ResolvedActionEvidence(
        provider_context=provider_context,
        audiences=audiences,
        provenance=provenance,
        phase=phase,
        resolution_complete=resolution_complete,
        metadata_sha256=canonical_sha256(metadata_payload),
        action_binding_sha256="0" * 64,
    )
    provisional_action = CanonicalAction(
        **{
            **_python_payload(action),
            "resolved_evidence": provisional_evidence,
        }
    )
    bound_evidence = ResolvedActionEvidence(
        **{
            **_python_payload(provisional_evidence),
            "action_binding_sha256": compute_action_evidence_binding(
                provisional_action
            ),
        }
    )
    return CanonicalAction(
        **{
            **_python_payload(action),
            "resolved_evidence": bound_evidence,
        }
    )


def _python_payload(model: BaseModel) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="python", warnings=False)
    return model.dict()


def _json_payload(model: BaseModel) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="json", warnings=False)
    return json.loads(model.json())
