"""Deterministic matching between canonical actions and active contracts."""

from __future__ import annotations

import posixpath
from datetime import datetime, timedelta, timezone
from enum import Enum

from pydantic import BaseModel, Field

from sentinel.actions import (
    CanonicalAction,
    compute_action_evidence_binding,
    fingerprint_action,
)
from sentinel.contracts import ActionContract, ContractRecord
from sentinel.decision.contextual_evidence import (
    ContractEvaluationContext,
    ContractEvaluationFacts,
)


class ContractMismatchReason(str, Enum):
    TOOL = "contract:tool_mismatch"
    TARGET = "contract:target_mismatch"
    TARGET_INCOMPLETE = "contract:target_incomplete"
    ENVIRONMENT = "contract:environment_mismatch"
    ENVIRONMENT_CONTEXT = "contract:environment_context_mismatch"
    OPERATION = "contract:operation_mismatch"
    READ_ONLY_TO_WRITE = "contract:read_only_to_write"
    EFFECT = "contract:effect_mismatch"
    EFFECT_INCOMPLETE = "contract:effect_incomplete"
    FORBIDDEN_OPERATION = "contract:forbidden_operation"
    FORBIDDEN_EFFECT = "contract:forbidden_effect"
    DRY_RUN = "contract:dry_run_required"
    DRY_RUN_EVIDENCE = "contract:dry_run_evidence_conflict"
    ROLLBACK = "contract:rollback_required"
    TRANSACTION = "contract:transaction_required"
    BACKUP = "contract:backup_required"
    BACKUP_EVIDENCE = "contract:backup_evidence_unverified"
    OBLIGATION_EVIDENCE = "contract:obligation_evidence_required"
    CONTEXT_BINDING = "contract:context_evidence_binding_mismatch"
    CONTEXT_STALE = "contract:context_evidence_stale"
    CUMULATIVE_LIMIT = "contract:cumulative_limit_exceeded"
    CUMULATIVE_EVIDENCE = "contract:cumulative_limit_evidence_incomplete"
    CUMULATIVE_SCOPE = "contract:cumulative_limit_scope_mismatch"
    CUMULATIVE_UNIT = "contract:cumulative_limit_unit_mismatch"
    INACTIVE = "contract:inactive"
    PREFLIGHT = "contract:preflight_incomplete"
    EXPIRED = "contract:expired"
    STALE_VERSION = "contract:stale_version"
    STALE_CONTRACT = "contract:stale_contract"
    SESSION = "contract:session_mismatch"
    TASK = "contract:inactive_task"
    PROVIDER_POLICY = "contract:provider_policy_required"
    PROVIDER_EVIDENCE = "contract:provider_evidence_required"
    EVIDENCE_SOURCE = "contract:evidence_source_untrusted"
    EVIDENCE_BINDING = "contract:evidence_action_binding_mismatch"
    EVIDENCE_TARGET = "contract:evidence_action_target_mismatch"
    EVIDENCE_PHASE = "contract:evidence_phase_invalid"
    PROVIDER = "contract:provider_mismatch"
    TENANT = "contract:provider_tenant_mismatch"
    ACCOUNT = "contract:provider_account_mismatch"
    CREDENTIAL_PRINCIPAL = "contract:credential_principal_mismatch"
    ACTOR = "contract:provider_actor_mismatch"
    ADAPTER = "contract:provider_adapter_mismatch"
    ADAPTER_UNSUPPORTED = "contract:provider_adapter_unsupported"
    PAYLOAD = "contract:payload_mismatch"
    EVIDENCE_INCOMPLETE = "contract:evidence_incomplete"
    EVIDENCE_STALE = "contract:evidence_stale"
    EXTERNAL_AUDIENCE = "contract:external_audience_forbidden"
    GUEST_AUDIENCE = "contract:guest_audience_forbidden"
    PUBLIC_AUDIENCE = "contract:public_audience_forbidden"
    BROADCAST = "contract:broadcast_forbidden"
    RECIPIENT_EXPANSION = "contract:recipient_expansion_forbidden"
    AUDIENCE_RESOURCE = "contract:audience_resource_mismatch"
    RECIPIENT = "contract:recipient_mismatch"
    RECIPIENT_SCOPE = "contract:recipient_scope_exceeded"


class ContractMatchResult(BaseModel):
    """Explainable result from contract boundary matching."""

    if hasattr(BaseModel, "model_validate"):
        model_config = {"extra": "forbid"}
    else:
        class Config:
            extra = "forbid"

    matches: bool
    reason_codes: list[str] = Field(default_factory=list)
    contract_id: str
    contract_version: int
    action_fingerprint: str

    @property
    def authorized(self) -> bool:
        return self.matches


def match_action_to_contract(
    record: ContractRecord,
    action: CanonicalAction,
    *,
    expected_contract_id: str,
    expected_version: int,
    session_id: str,
    active_task_id: str,
    now: datetime | None = None,
    trusted_context: ContractEvaluationContext | None = None,
    trusted_context_producers: set[tuple[str, str]] | None = None,
) -> ContractMatchResult:
    """Return every deterministic mismatch in stable policy order."""

    current = _as_utc(now or datetime.now(timezone.utc))
    reasons: list[str] = []
    contract = record.contract
    context_is_trusted = _append_context_integrity_reasons(
        reasons,
        record,
        action,
        trusted_context,
        trusted_context_producers,
        current,
    )
    facts = trusted_context.facts if context_is_trusted and trusted_context else None
    effective_targets = list(action.targets)
    effective_effects = set(action.effects)
    if facts is not None:
        effective_targets = sorted(set(effective_targets + facts.resolved_targets))
        effective_effects.update(facts.resolved_effects)

    if expected_contract_id != record.contract_id:
        reasons.append(ContractMismatchReason.STALE_CONTRACT.value)
    if expected_version != record.version:
        reasons.append(ContractMismatchReason.STALE_VERSION.value)
    if session_id != record.session_id:
        reasons.append(ContractMismatchReason.SESSION.value)
    if active_task_id != record.task_id:
        reasons.append(ContractMismatchReason.TASK.value)
    if record.status != "active":
        reasons.append(ContractMismatchReason.INACTIVE.value)
    if record.preflight_status != "complete":
        reasons.append(ContractMismatchReason.PREFLIGHT.value)
    if record.expires_at <= current:
        reasons.append(ContractMismatchReason.EXPIRED.value)

    action_tool = _normalize_tool(action.tool or action.family)
    allowed_tools = {_normalize_tool(tool) for tool in contract.allowed_tools}
    if action_tool not in allowed_tools:
        reasons.append(ContractMismatchReason.TOOL.value)

    if action.environment != contract.environment:
        reasons.append(ContractMismatchReason.ENVIRONMENT.value)
    if action.environment_context != contract.environment_context:
        reasons.append(ContractMismatchReason.ENVIRONMENT_CONTEXT.value)

    evidence = action.resolved_evidence
    if _requires_provider_profile(contract, action) and not _provider_profile_complete(
        contract
    ):
        reasons.append(ContractMismatchReason.PROVIDER_POLICY.value)
    if (contract.provider_scope or contract.audience_policy) and evidence is None:
        reasons.append(ContractMismatchReason.PROVIDER_EVIDENCE.value)
    if evidence is not None:
        if evidence.provenance.source_type != "provider_api":
            reasons.append(ContractMismatchReason.EVIDENCE_SOURCE.value)
        if evidence.action_binding_sha256 != compute_action_evidence_binding(action):
            reasons.append(ContractMismatchReason.EVIDENCE_BINDING.value)
        evidence_audience_targets = {
            audience.canonical_target for audience in evidence.audiences
        }
        if (
            set(action.audience_targets) != evidence_audience_targets
            or not set(action.audience_targets).issubset(action.targets)
        ):
            reasons.append(ContractMismatchReason.EVIDENCE_TARGET.value)
        if evidence.phase != "projected_effect":
            reasons.append(ContractMismatchReason.EVIDENCE_PHASE.value)
        provider = evidence.provider_context
        _append_provider_adapter_reasons(reasons, action)
        scope = contract.provider_scope
        if scope is not None:
            if provider.provider != scope.provider:
                if ContractMismatchReason.PROVIDER.value not in reasons:
                    reasons.append(ContractMismatchReason.PROVIDER.value)
            if provider.tenant_id != scope.tenant_id:
                reasons.append(ContractMismatchReason.TENANT.value)
            if (
                scope.resource_account_id is not None
                and provider.resource_account_id != scope.resource_account_id
            ):
                reasons.append(ContractMismatchReason.ACCOUNT.value)
            if (
                provider.credential_principal_id
                != scope.credential_principal_id
            ):
                reasons.append(
                    ContractMismatchReason.CREDENTIAL_PRINCIPAL.value
                )
            if scope.actor_id is not None and provider.actor_id != scope.actor_id:
                reasons.append(ContractMismatchReason.ACTOR.value)
            if provider.adapter_id != scope.adapter_id:
                if ContractMismatchReason.ADAPTER.value not in reasons:
                    reasons.append(ContractMismatchReason.ADAPTER.value)
        if any(
            audience.tenant_id != provider.tenant_id
            for audience in evidence.audiences
        ) and ContractMismatchReason.TENANT.value not in reasons:
            reasons.append(ContractMismatchReason.TENANT.value)
        if _evidence_is_stale(action, current):
            reasons.append(ContractMismatchReason.EVIDENCE_STALE.value)
        _append_audience_reasons(reasons, contract, action)

    operation_allowed = action.operation in contract.allowed_operations
    if not operation_allowed:
        if _is_read_to_write(contract, action):
            reasons.append(ContractMismatchReason.READ_ONLY_TO_WRITE.value)
        else:
            reasons.append(ContractMismatchReason.OPERATION.value)
    if action.operation in contract.forbidden_operations:
        reasons.append(ContractMismatchReason.FORBIDDEN_OPERATION.value)

    if not action.targets:
        reasons.append(ContractMismatchReason.TARGET_INCOMPLETE.value)
    if not action.effects:
        reasons.append(ContractMismatchReason.EFFECT_INCOMPLETE.value)
    allowed_effects = contract.allowed_effects or {
        operation for operation in contract.allowed_operations
    }
    if not effective_effects.issubset(allowed_effects):
        reasons.append(ContractMismatchReason.EFFECT.value)
    if effective_effects.intersection(contract.forbidden_effect_codes):
        reasons.append(ContractMismatchReason.FORBIDDEN_EFFECT.value)

    if not _targets_match(contract, effective_targets):
        reasons.append(ContractMismatchReason.TARGET.value)

    if (
        contract.approved_payload_sha256 is not None
        and action.payload_sha256 != contract.approved_payload_sha256
    ):
        reasons.append(ContractMismatchReason.PAYLOAD.value)

    _append_obligation_reasons(
        reasons,
        contract,
        action,
        facts,
    )
    if context_is_trusted and trusted_context is not None:
        _append_cumulative_limit_reasons(reasons, trusted_context, action)

    return ContractMatchResult(
        matches=not reasons,
        reason_codes=reasons,
        contract_id=record.contract_id,
        contract_version=record.version,
        action_fingerprint=fingerprint_action(action),
    )


match_contract = match_action_to_contract


def _is_read_to_write(contract: ActionContract, action: CanonicalAction) -> bool:
    mutating = {"write", "delete", "execute", "external_communication"}
    return contract.allowed_operations.issubset({"read"}) and (
        action.operation in mutating or bool(action.effects.intersection(mutating))
    )


def _normalize_tool(tool: str) -> str:
    normalized = tool.strip().lower()
    if normalized in {"bash", "exec", "process", "run"}:
        return "shell"
    return normalized


def _targets_match(contract: ActionContract, targets: list[str]) -> bool:
    return all(
        any(_target_allowed(target, allowed, contract.maximum_scope) for allowed in contract.exact_targets)
        for target in targets
    )


def _append_obligation_reasons(
    reasons: list[str],
    contract: ActionContract,
    action: CanonicalAction,
    facts: ContractEvaluationFacts | None,
) -> None:
    obligations = contract.effective_obligations()
    requirements = [
        (
            obligations.dry_run_required,
            action.dry_run,
            facts.dry_run_verified if facts is not None else None,
            ContractMismatchReason.DRY_RUN.value,
            ContractMismatchReason.DRY_RUN_EVIDENCE.value,
        ),
        (
            obligations.rollback_required,
            action.rollback_available,
            facts.rollback_verified if facts is not None else None,
            ContractMismatchReason.ROLLBACK.value,
            ContractMismatchReason.ROLLBACK.value,
        ),
        (
            obligations.transaction_required,
            action.transaction,
            facts.transaction_verified if facts is not None else None,
            ContractMismatchReason.TRANSACTION.value,
            ContractMismatchReason.TRANSACTION.value,
        ),
        (
            obligations.backup_required,
            action.backup_available,
            facts.backup_verified if facts is not None else None,
            ContractMismatchReason.BACKUP.value,
            ContractMismatchReason.BACKUP_EVIDENCE.value,
        ),
    ]
    missing_claims = [
        missing_reason
        for required, claimed, _, missing_reason, _ in requirements
        if required and not claimed
    ]
    if missing_claims:
        reasons.extend(missing_claims)
        return
    required_checks = [
        (verified, conflict_reason)
        for required, _, verified, _, conflict_reason in requirements
        if required
    ]
    if not required_checks:
        return
    if any(verified is None for verified, _ in required_checks):
        reasons.append(ContractMismatchReason.OBLIGATION_EVIDENCE.value)
        return
    for verified, conflict_reason in required_checks:
        if verified is False:
            _append_once(reasons, conflict_reason)


def _append_context_integrity_reasons(
    reasons: list[str],
    record: ContractRecord,
    action: CanonicalAction,
    context: ContractEvaluationContext | None,
    trusted_producers: set[tuple[str, str]] | None,
    now: datetime,
) -> bool:
    if context is None:
        return False
    binding_matches = (
        trusted_producers is not None
        and (context.source, context.producer_id) in trusted_producers
        and context.action_fingerprint == fingerprint_action(action)
        and context.contract_id == record.contract_id
        and context.contract_version == record.version
        and context.authority_epoch == record.authority_epoch
        and context.session_id == record.session_id
        and context.task_id == record.task_id
        and context.environment == action.environment
        and context.valid_until <= record.expires_at
    )
    if not binding_matches:
        reasons.append(ContractMismatchReason.CONTEXT_BINDING.value)
    maximum_age = {
        "reviewed_fixture": timedelta(minutes=5),
        "trusted_adapter": timedelta(minutes=5),
        "trusted_filesystem": timedelta(minutes=1),
        "server_ledger": timedelta(minutes=1),
    }[context.source]
    fresh = (
        context.observed_at <= now < context.valid_until
        and now - context.observed_at <= maximum_age
    )
    if not fresh:
        reasons.append(ContractMismatchReason.CONTEXT_STALE.value)
    return binding_matches and fresh


def _append_cumulative_limit_reasons(
    reasons: list[str],
    context: ContractEvaluationContext,
    action: CanonicalAction,
) -> None:
    measurements = context.facts.measurements
    for measurement in measurements:
        metric_limits = [
            limit
            for limit in context.authorized_limits
            if limit.metric == measurement.metric
        ]
        if not metric_limits:
            continue
        scoped_limits = [
            limit
            for limit in metric_limits
            if limit.target is None or limit.target == measurement.target
        ]
        if not scoped_limits or (
            measurement.target is not None
            and measurement.target not in action.targets
        ):
            _append_once(reasons, ContractMismatchReason.CUMULATIVE_SCOPE.value)
            continue
        if all(limit.unit != measurement.unit for limit in scoped_limits):
            _append_once(reasons, ContractMismatchReason.CUMULATIVE_UNIT.value)
    for usage in context.recent_usage:
        if not usage.successful or usage.task_id != context.task_id:
            continue
        scoped_limits = [
            limit
            for limit in context.authorized_limits
            if limit.metric == usage.metric
            and (limit.target is None or limit.target == usage.target)
        ]
        if scoped_limits and all(limit.unit != usage.unit for limit in scoped_limits):
            _append_once(reasons, ContractMismatchReason.CUMULATIVE_UNIT.value)
    for limit in context.authorized_limits:
        proposed_for_metric = [
            measurement
            for measurement in measurements
            if measurement.metric == limit.metric
        ]
        if not proposed_for_metric:
            _append_once(reasons, ContractMismatchReason.CUMULATIVE_EVIDENCE.value)
            continue
        proposed_for_scope = [
            measurement
            for measurement in proposed_for_metric
            if limit.target is None or measurement.target == limit.target
        ]
        if not proposed_for_scope:
            _append_once(reasons, ContractMismatchReason.CUMULATIVE_SCOPE.value)
            continue
        proposed_for_key = [
            measurement
            for measurement in proposed_for_scope
            if measurement.unit == limit.unit
        ]
        if not proposed_for_key:
            _append_once(reasons, ContractMismatchReason.CUMULATIVE_UNIT.value)
            continue
        if limit.target is None and any(
            measurement.target is not None
            and measurement.target not in action.targets
            for measurement in proposed_for_key
        ):
            _append_once(reasons, ContractMismatchReason.CUMULATIVE_SCOPE.value)
            continue
        usage_for_key = [
            usage
            for usage in context.recent_usage
            if usage.successful
            and usage.task_id == context.task_id
            and usage.metric == limit.metric
            and usage.unit == limit.unit
            and (limit.target is None or usage.target == limit.target)
        ]
        used = sum(
            usage.amount
            for usage in usage_for_key
        )
        requested = sum(measurement.amount for measurement in proposed_for_key)
        if used + requested > limit.maximum:
            _append_once(reasons, ContractMismatchReason.CUMULATIVE_LIMIT.value)


def _append_once(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


def _target_allowed(target: str, allowed: str, maximum_scope: str) -> bool:
    if "://" in target or "://" in allowed:
        return target == allowed
    if not allowed.startswith("/"):
        return target == allowed
    normalized_target = posixpath.normpath(target)
    normalized_allowed = posixpath.normpath(allowed)
    if maximum_scope == "exact":
        return normalized_target == normalized_allowed
    return normalized_target == normalized_allowed or normalized_target.startswith(
        normalized_allowed.rstrip("/") + "/"
    )


def _evidence_is_stale(action: CanonicalAction, now: datetime) -> bool:
    evidence = action.resolved_evidence
    if evidence is None:
        return False
    if evidence.provenance.retrieved_at > now:
        return True
    requested_execution = action.requested_execution_at or now
    required_until = max(now, requested_execution)
    return (
        evidence.provenance.valid_until <= required_until
        or now - evidence.provenance.retrieved_at > timedelta(minutes=5)
    )


def _append_audience_reasons(
    reasons: list[str],
    contract: ActionContract,
    action: CanonicalAction,
) -> None:
    policy = contract.audience_policy
    evidence = action.resolved_evidence
    if policy is None or evidence is None:
        return
    audiences = evidence.audiences
    incomplete = (
        not evidence.resolution_complete
        or not audiences
        or any(not audience.resolution_complete for audience in audiences)
    )
    if incomplete:
        reasons.append(ContractMismatchReason.EVIDENCE_INCOMPLETE.value)
    if not policy.allow_external and any(
        audience.is_external_shared or audience.external_recipient_ids
        for audience in audiences
    ):
        reasons.append(ContractMismatchReason.EXTERNAL_AUDIENCE.value)
    if not policy.allow_guests and any(
        audience.guest_recipient_ids for audience in audiences
    ):
        reasons.append(ContractMismatchReason.GUEST_AUDIENCE.value)
    if not policy.allow_public and any(
        audience.is_public for audience in audiences
    ):
        reasons.append(ContractMismatchReason.PUBLIC_AUDIENCE.value)
    if not policy.allow_broadcast and any(
        audience.is_broadcast for audience in audiences
    ):
        reasons.append(ContractMismatchReason.BROADCAST.value)
    if not policy.allow_recipient_expansion and any(
        audience.allows_recipient_expansion for audience in audiences
    ):
        reasons.append(ContractMismatchReason.RECIPIENT_EXPANSION.value)
    if policy.allowed_audience_resource_ids is not None and any(
        audience.resource_id not in policy.allowed_audience_resource_ids
        for audience in audiences
    ):
        reasons.append(ContractMismatchReason.AUDIENCE_RESOURCE.value)
    resolved_recipients = {
        recipient
        for audience in audiences
        for recipient in audience.recipient_ids
    }
    if policy.allowed_recipient_ids is not None and not resolved_recipients.issubset(
        policy.allowed_recipient_ids
    ):
        reasons.append(ContractMismatchReason.RECIPIENT.value)
    if (
        policy.maximum_recipient_count is not None
        and (
            (
                not incomplete
                and len(resolved_recipients) > policy.maximum_recipient_count
            )
            or any(
                audience.recipient_count > policy.maximum_recipient_count
                for audience in audiences
            )
        )
    ):
        reasons.append(ContractMismatchReason.RECIPIENT_SCOPE.value)


def _requires_provider_profile(
    contract: ActionContract,
    action: CanonicalAction,
) -> bool:
    provider_tools = {"slack", "gmail", "google_calendar", "google_drive"}
    communication_effects = {
        "external_send",
        "calendar_invite",
        "share_read",
        "share_write",
        "public_share",
        "portal_publish",
        "court_file",
        "audience_change",
        "recipient_expansion",
    }
    action_tool = _normalize_tool(action.tool or action.family)
    allowed_tools = {_normalize_tool(tool) for tool in contract.allowed_tools}
    return (
        action.operation == "external_communication"
        or bool(action.effects.intersection(communication_effects))
        or bool(contract.allowed_effects.intersection(communication_effects))
        or action_tool in provider_tools
        or bool(allowed_tools.intersection(provider_tools))
    )


def _provider_profile_complete(contract: ActionContract) -> bool:
    policy = contract.audience_policy
    return bool(
        contract.provider_scope is not None
        and policy is not None
        and contract.approved_payload_sha256 is not None
        and (
            policy.allowed_recipient_ids is not None
            or policy.allowed_audience_resource_ids is not None
        )
    )


def _append_provider_adapter_reasons(
    reasons: list[str],
    action: CanonicalAction,
) -> None:
    evidence = action.resolved_evidence
    if evidence is None:
        return
    profiles = {
        "slack": (
            "slack",
            "sentinel:slack:v1",
            {"channel", "direct_message", "group_message", "file"},
            "slack:",
        ),
        "gmail": (
            "gmail",
            "sentinel:gmail:v1",
            {"email"},
            "gmail:",
        ),
        "google_calendar": (
            "google_calendar",
            "sentinel:google_calendar:v1",
            {"calendar_event"},
            "calendar:",
        ),
        "google_drive": (
            "google_drive",
            "sentinel:google_drive:v1",
            {"file"},
            "drive:",
        ),
    }
    action_tool = _normalize_tool(action.tool or action.family)
    profile = profiles.get(action_tool)
    if profile is None:
        if (
            action.operation == "external_communication"
            or action.effects.intersection(
                {
                    "external_send",
                    "calendar_invite",
                    "share_read",
                    "share_write",
                    "public_share",
                    "portal_publish",
                    "court_file",
                    "audience_change",
                    "recipient_expansion",
                }
            )
        ):
            reasons.append(ContractMismatchReason.ADAPTER_UNSUPPORTED.value)
        return
    expected_provider, expected_adapter, allowed_kinds, target_prefix = profile
    provider = evidence.provider_context
    if (
        provider.provider != expected_provider
        and ContractMismatchReason.PROVIDER.value not in reasons
    ):
        reasons.append(ContractMismatchReason.PROVIDER.value)
    if (
        provider.adapter_id != expected_adapter
        and ContractMismatchReason.ADAPTER.value not in reasons
    ):
        reasons.append(ContractMismatchReason.ADAPTER.value)
    if any(audience.kind not in allowed_kinds for audience in evidence.audiences):
        if ContractMismatchReason.EVIDENCE_TARGET.value not in reasons:
            reasons.append(ContractMismatchReason.EVIDENCE_TARGET.value)
    if any(not target.startswith(target_prefix) for target in action.targets):
        if ContractMismatchReason.EVIDENCE_TARGET.value not in reasons:
            reasons.append(ContractMismatchReason.EVIDENCE_TARGET.value)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
