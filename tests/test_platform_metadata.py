from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pydantic import ValidationError


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.actions import (  # noqa: E402
    CanonicalAction,
    compute_action_evidence_binding,
    fingerprint_action,
)
from sentinel.api.schemas import ShellActionRequest  # noqa: E402
from sentinel.contracts import ActionContract, ContractRecord  # noqa: E402
from sentinel.decision.contract_policy import match_action_to_contract  # noqa: E402
from sentinel.platforms import AudienceSnapshot, ResolvedActionEvidence  # noqa: E402


NOW = datetime(2026, 9, 4, 20, 0, tzinfo=timezone.utc)
PAYLOAD_HASH = "a" * 64
METADATA_HASH = "b" * 64


class AuthorityModelStrictnessTests(unittest.TestCase):
    def test_canonical_action_rejects_unknown_fields(self) -> None:
        with self.assertRaises(ValidationError):
            CanonicalAction(
                family="shell",
                operation="read",
                environment="sandbox",
                effect={"read"},
            )


def make_contract(**overrides: object) -> ActionContract:
    payload: dict[str, object] = {
        "objective": "Post the reviewed update to the internal engineering channel.",
        "allowed_operations": {"external_communication"},
        "allowed_tools": {"slack"},
        "exact_targets": ["slack:channel:C-ENGINEERING"],
        "environment": "production",
        "maximum_scope": "exact",
        "expected_side_effects": ["Send one internal Slack message."],
        "allowed_effects": {"external_send"},
        "forbidden_operations": {"credential_access"},
        "forbidden_effects": ["Do not contact external or guest users."],
        "forbidden_effect_codes": {"credential_access"},
        "rollback_plan": "Delete the message if delivery fails.",
        "dry_run_required": False,
        "provider_scope": {
            "provider": "slack",
            "tenant_id": "T-INTERNAL",
            "resource_account_id": "A-SENTINEL",
            "credential_principal_id": "BOT-SENTINEL",
            "actor_id": "U-OPERATOR",
            "adapter_id": "sentinel:slack:v1",
        },
        "audience_policy": {
            "allow_external": False,
            "allow_guests": False,
            "allow_public": False,
            "allow_broadcast": False,
            "allow_recipient_expansion": False,
            "maximum_recipient_count": 20,
            "allowed_audience_resource_ids": {"C-ENGINEERING"},
        },
        "approved_payload_sha256": PAYLOAD_HASH,
        "authorization_reference": "trusted-event-platform-1",
        "version": 1,
        "expires_at": NOW + timedelta(hours=1),
    }
    payload.update(overrides)
    return ActionContract(**payload)


def make_record(**contract_overrides: object) -> ContractRecord:
    contract = make_contract(**contract_overrides)
    return ContractRecord(
        contract_id="contract-platform-1",
        task_id="task-platform-1",
        session_id="session-platform-1",
        version=1,
        authority_epoch=1,
        authority_event_id="trusted-event-platform-1",
        status="active",
        contract=contract,
        authorization_source="trusted_user",
        authorization_reference="trusted-event-platform-1",
        preflight_status="complete",
        created_at=NOW - timedelta(minutes=5),
        updated_at=NOW - timedelta(minutes=5),
        expires_at=contract.expires_at,
    )


def make_evidence(**overrides: object) -> ResolvedActionEvidence:
    payload: dict[str, object] = {
        "provider_context": {
            "provider": "slack",
            "tenant_id": "T-INTERNAL",
            "resource_account_id": "A-SENTINEL",
            "credential_principal_id": "BOT-SENTINEL",
            "actor_id": "U-OPERATOR",
            "adapter_id": "sentinel:slack:v1",
        },
        "audiences": [
            {
                "resource_id": "C-ENGINEERING",
                "canonical_target": "slack:channel:C-ENGINEERING",
                "kind": "channel",
                "tenant_id": "T-INTERNAL",
                "recipient_ids": ["U-1", "U-2"],
                "recipient_count": 2,
                "state_version": "membership-v1",
            }
        ],
        "provenance": {
            "source_type": "provider_api",
            "source_endpoint": "conversations.info + conversations.members",
            "source_fields": ["id", "is_ext_shared", "members"],
            "documentation_url": "https://docs.slack.dev/reference/methods/conversations.info",
            "retrieved_at": NOW - timedelta(seconds=5),
            "valid_until": NOW + timedelta(seconds=30),
        },
        "phase": "projected_effect",
        "resolution_complete": True,
        "metadata_sha256": METADATA_HASH,
        "action_binding_sha256": "0" * 64,
    }
    payload.update(overrides)
    for audience in payload["audiences"]:
        if isinstance(audience, dict) and "canonical_target" not in audience:
            audience["canonical_target"] = (
                f"slack:channel:{audience['resource_id']}"
            )
    return ResolvedActionEvidence(**payload)


def make_action(**overrides: object) -> CanonicalAction:
    payload: dict[str, object] = {
        "family": "mcp",
        "tool": "slack",
        "operation": "external_communication",
        "targets": ["slack:channel:C-ENGINEERING"],
        "effects": {"external_send"},
        "environment": "production",
        "payload_sha256": PAYLOAD_HASH,
        "resolved_evidence": make_evidence(),
    }
    payload.update(overrides)
    evidence = payload.get("resolved_evidence")
    if "audience_targets" not in overrides and evidence is not None:
        audiences = (
            evidence.audiences
            if isinstance(evidence, ResolvedActionEvidence)
            else evidence["audiences"]
        )
        payload["audience_targets"] = [
            (
                audience.canonical_target
                if hasattr(audience, "canonical_target")
                else audience["canonical_target"]
            )
            for audience in audiences
        ]
    provisional = CanonicalAction(**payload)
    if provisional.resolved_evidence is None:
        return provisional
    action_payload = (
        provisional.model_dump()
        if hasattr(provisional, "model_dump")
        else provisional.dict()
    )
    action_payload["resolved_evidence"][
        "action_binding_sha256"
    ] = compute_action_evidence_binding(provisional)
    return CanonicalAction(**action_payload)


def match(record: ContractRecord, action: CanonicalAction):
    return match_action_to_contract(
        record,
        action,
        expected_contract_id=record.contract_id,
        expected_version=record.version,
        session_id=record.session_id,
        active_task_id=record.task_id,
        now=NOW,
    )


class PlatformMetadataModelTests(unittest.TestCase):
    def test_public_shell_request_cannot_supply_trusted_evidence(self) -> None:
        with self.assertRaises(ValidationError):
            ShellActionRequest(
                family="shell",
                raw_command="ls /workspace",
                resolved_evidence={"resolution_complete": True},
            )

    def test_external_and_guest_ids_must_be_resolved_recipients(self) -> None:
        with self.assertRaises(ValidationError):
            AudienceSnapshot(
                resource_id="C-1",
                canonical_target="slack:channel:C-1",
                kind="channel",
                tenant_id="T-1",
                recipient_ids=["U-1"],
                external_recipient_ids=["U-2"],
                recipient_count=2,
            )

    def test_complete_evidence_must_enumerate_every_recipient(self) -> None:
        with self.assertRaises(ValidationError):
            AudienceSnapshot(
                resource_id="C-1",
                canonical_target="slack:channel:C-1",
                kind="channel",
                tenant_id="T-1",
                recipient_ids=["U-1"],
                recipient_count=2,
                resolution_complete=True,
            )

    def test_collection_bounds_are_enforced_independently_of_pydantic_version(self) -> None:
        with self.assertRaises(ValidationError):
            AudienceSnapshot(
                resource_id="C-1",
                canonical_target="slack:channel:C-1",
                kind="channel",
                tenant_id="T-1",
                recipient_ids=[f"U-{index}" for index in range(10_001)],
                recipient_count=10_001,
            )

    def test_fingerprint_binds_payload_and_resolved_metadata(self) -> None:
        baseline = make_action()
        changed_payload = make_action(payload_sha256="c" * 64)
        changed_evidence = make_action(
            resolved_evidence=make_evidence(metadata_sha256="d" * 64)
        )

        self.assertNotEqual(
            fingerprint_action(baseline),
            fingerprint_action(changed_payload),
        )
        self.assertNotEqual(
            fingerprint_action(baseline),
            fingerprint_action(changed_evidence),
        )


class PlatformContractPolicyTests(unittest.TestCase):
    def test_complete_internal_audience_matches(self) -> None:
        result = match(make_record(), make_action())

        self.assertTrue(result.matches)
        self.assertEqual(result.reason_codes, [])

    def test_provider_and_tenant_mismatch_have_stable_order(self) -> None:
        evidence = make_evidence(
            provider_context={
                "provider": "gmail",
                "tenant_id": "C-OTHER",
                "resource_account_id": "A-SENTINEL",
                "credential_principal_id": "BOT-SENTINEL",
                "actor_id": "U-OPERATOR",
                "adapter_id": "sentinel:slack:v1",
            }
        )
        result = match(make_record(), make_action(resolved_evidence=evidence))

        self.assertEqual(
            result.reason_codes,
            [
                "contract:provider_mismatch",
                "contract:provider_tenant_mismatch",
            ],
        )

    def test_adapter_registry_binds_provider_identity_to_tool(self) -> None:
        gmail_scope = {
            "provider": "gmail",
            "tenant_id": "T-INTERNAL",
            "resource_account_id": "MAILBOX-1",
            "credential_principal_id": "GOOGLE-OAUTH-SUB:U-1",
            "actor_id": "U-OPERATOR",
            "adapter_id": "sentinel:gmail:v1",
        }
        evidence = make_evidence(
            provider_context=gmail_scope,
        )

        result = match(
            make_record(provider_scope=gmail_scope),
            make_action(resolved_evidence=evidence),
        )

        self.assertEqual(
            result.reason_codes,
            [
                "contract:provider_mismatch",
                "contract:provider_adapter_mismatch",
            ],
        )

    def test_exact_audience_resource_and_recipient_are_enforced(self) -> None:
        recipient_policy = {
            "allow_external": False,
            "allow_guests": False,
            "allow_public": False,
            "allow_broadcast": False,
            "allow_recipient_expansion": False,
            "maximum_recipient_count": 20,
            "allowed_recipient_ids": {"U-APPROVED"},
            "allowed_audience_resource_ids": {"C-ENGINEERING"},
        }
        evidence = make_evidence(
            audiences=[
                {
                    "resource_id": "C-UNRELATED",
                    "kind": "channel",
                    "tenant_id": "T-INTERNAL",
                    "recipient_ids": ["U-UNAPPROVED"],
                    "recipient_count": 1,
                }
            ]
        )

        result = match(
            make_record(audience_policy=recipient_policy),
            make_action(resolved_evidence=evidence),
        )

        self.assertEqual(
            result.reason_codes,
            [
                "contract:evidence_action_target_mismatch",
                "contract:audience_resource_mismatch",
                "contract:recipient_mismatch",
            ],
        )

    def test_unapproved_internal_recipient_is_not_treated_as_safe(self) -> None:
        recipient_policy = {
            "allow_external": False,
            "allow_guests": False,
            "allow_public": False,
            "allow_broadcast": False,
            "allow_recipient_expansion": False,
            "maximum_recipient_count": 20,
            "allowed_recipient_ids": {"U-APPROVED"},
            "allowed_audience_resource_ids": {"C-ENGINEERING"},
        }
        evidence = make_evidence(
            audiences=[
                {
                    "resource_id": "C-ENGINEERING",
                    "kind": "channel",
                    "tenant_id": "T-INTERNAL",
                    "recipient_ids": ["U-UNAPPROVED"],
                    "recipient_count": 1,
                }
            ]
        )

        result = match(
            make_record(audience_policy=recipient_policy),
            make_action(resolved_evidence=evidence),
        )

        self.assertEqual(
            result.reason_codes,
            ["contract:recipient_mismatch"],
        )

        deny_all_policy = dict(recipient_policy)
        deny_all_policy["allowed_recipient_ids"] = set()
        deny_all = match(
            make_record(audience_policy=deny_all_policy),
            make_action(resolved_evidence=evidence),
        )
        self.assertEqual(
            deny_all.reason_codes,
            ["contract:recipient_mismatch"],
        )

    def test_recipient_limit_counts_unique_principals_across_audiences(self) -> None:
        policy = {
            "allow_external": False,
            "allow_guests": False,
            "allow_public": False,
            "allow_broadcast": False,
            "allow_recipient_expansion": False,
            "maximum_recipient_count": 2,
            "allowed_recipient_ids": {"U-1", "U-2"},
            "allowed_audience_resource_ids": {"C-1", "C-2"},
        }
        evidence = make_evidence(
            audiences=[
                {
                    "resource_id": channel,
                    "kind": "channel",
                    "tenant_id": "T-INTERNAL",
                    "recipient_ids": ["U-1", "U-2"],
                    "recipient_count": 2,
                }
                for channel in ("C-1", "C-2")
            ]
        )
        targets = ["slack:channel:C-1", "slack:channel:C-2"]

        result = match(
            make_record(
                exact_targets=targets,
                audience_policy=policy,
            ),
            make_action(
                targets=targets,
                resolved_evidence=evidence,
            ),
        )

        self.assertTrue(result.matches)

    def test_audience_tenant_must_match_credential_tenant(self) -> None:
        evidence = make_evidence(
            audiences=[
                {
                    "resource_id": "C-ENGINEERING",
                    "kind": "channel",
                    "tenant_id": "T-OTHER",
                    "recipient_ids": ["U-1"],
                    "recipient_count": 1,
                }
            ]
        )

        result = match(make_record(), make_action(resolved_evidence=evidence))

        self.assertEqual(
            result.reason_codes,
            ["contract:provider_tenant_mismatch"],
        )

    def test_provider_tool_requires_complete_policy_profile(self) -> None:
        record = make_record(
            provider_scope=None,
            audience_policy=None,
            approved_payload_sha256=None,
        )

        result = match(record, make_action(resolved_evidence=None))

        self.assertEqual(
            result.reason_codes,
            ["contract:provider_policy_required"],
        )

    def test_effect_only_external_send_requires_provider_profile(self) -> None:
        record = make_record(
            allowed_operations={"write"},
            allowed_tools={"email"},
            allowed_effects={"external_send"},
            exact_targets=["email:message:M-1"],
            provider_scope=None,
            audience_policy=None,
            approved_payload_sha256=None,
        )
        action = make_action(
            tool="email",
            operation="write",
            targets=["email:message:M-1"],
            effects={"external_send"},
            payload_sha256=None,
            resolved_evidence=None,
        )

        result = match(record, action)

        self.assertEqual(
            result.reason_codes,
            ["contract:provider_policy_required"],
        )

    def test_external_guest_public_broadcast_and_scope_are_separate(self) -> None:
        recipients = [f"U-{index}" for index in range(25)]
        recipients[1] = "U-EXTERNAL"
        recipients[2] = "U-GUEST"
        audience = {
            "resource_id": "C-ENGINEERING",
            "kind": "channel",
            "tenant_id": "T-INTERNAL",
            "recipient_ids": recipients,
            "external_recipient_ids": ["U-EXTERNAL"],
            "guest_recipient_ids": ["U-GUEST"],
            "recipient_count": 25,
            "is_public": True,
            "is_external_shared": True,
            "is_broadcast": True,
            "state_version": "membership-v2",
        }
        evidence = make_evidence(audiences=[audience])

        result = match(make_record(), make_action(resolved_evidence=evidence))

        self.assertEqual(
            result.reason_codes,
            [
                "contract:external_audience_forbidden",
                "contract:guest_audience_forbidden",
                "contract:public_audience_forbidden",
                "contract:broadcast_forbidden",
                "contract:recipient_scope_exceeded",
            ],
        )

    def test_missing_incomplete_and_stale_evidence_fail_closed(self) -> None:
        missing = match(make_record(), make_action(resolved_evidence=None))
        incomplete_evidence = make_evidence(
            audiences=[],
            resolution_complete=False,
        )
        incomplete = match(
            make_record(),
            make_action(resolved_evidence=incomplete_evidence),
        )
        stale_evidence = make_evidence(
            provenance={
                "source_type": "provider_api",
                "source_endpoint": "conversations.info",
                "source_fields": ["id"],
                "documentation_url": "https://docs.slack.dev/reference/methods/conversations.info",
                "retrieved_at": NOW - timedelta(minutes=2),
                "valid_until": NOW - timedelta(minutes=1),
            }
        )
        stale = match(make_record(), make_action(resolved_evidence=stale_evidence))

        self.assertEqual(
            missing.reason_codes,
            ["contract:provider_evidence_required"],
        )
        self.assertEqual(
            incomplete.reason_codes,
            ["contract:evidence_incomplete"],
        )
        self.assertEqual(stale.reason_codes, ["contract:evidence_stale"])

    def test_official_schema_fixture_is_not_live_enforcement_evidence(self) -> None:
        fixture = make_evidence(
            provenance={
                "source_type": "official_schema_fixture",
                "source_endpoint": "conversations.info",
                "source_fields": ["id", "members"],
                "documentation_url": "https://docs.slack.dev/reference/methods/conversations.info",
                "retrieved_at": NOW - timedelta(seconds=5),
                "valid_until": NOW + timedelta(seconds=30),
            }
        )
        result = match(make_record(), make_action(resolved_evidence=fixture))

        self.assertEqual(
            result.reason_codes,
            ["contract:evidence_source_untrusted"],
        )

    def test_evidence_binding_detects_post_resolution_action_change(self) -> None:
        action = make_action()
        action.targets = ["slack:channel:C-UNRELATED"]

        result = match(make_record(), action)

        self.assertIn(
            "contract:evidence_action_binding_mismatch",
            result.reason_codes,
        )
        self.assertIn("contract:target_mismatch", result.reason_codes)

    def test_every_declared_audience_target_requires_evidence(self) -> None:
        targets = ["slack:channel:C-1", "slack:channel:C-2"]
        evidence = make_evidence(
            audiences=[
                {
                    "resource_id": "C-1",
                    "kind": "channel",
                    "tenant_id": "T-INTERNAL",
                    "recipient_ids": ["U-1"],
                    "recipient_count": 1,
                }
            ]
        )
        action = make_action(
            targets=targets,
            audience_targets=targets,
            resolved_evidence=evidence,
        )

        result = match(
            make_record(
                exact_targets=targets,
                audience_policy={
                    "maximum_recipient_count": 10,
                    "allowed_audience_resource_ids": {"C-1", "C-2"},
                },
            ),
            action,
        )

        self.assertEqual(
            result.reason_codes,
            ["contract:evidence_action_target_mismatch"],
        )

    def test_future_evidence_and_past_execution_timestamp_cannot_bypass_freshness(
        self,
    ) -> None:
        future = make_evidence(
            provenance={
                "source_type": "provider_api",
                "source_endpoint": "conversations.info",
                "source_fields": ["id"],
                "documentation_url": "https://docs.slack.dev/reference/methods/conversations.info",
                "retrieved_at": NOW + timedelta(seconds=1),
                "valid_until": NOW + timedelta(minutes=1),
            }
        )
        future_result = match(
            make_record(),
            make_action(resolved_evidence=future),
        )
        expired = make_evidence(
            provenance={
                "source_type": "provider_api",
                "source_endpoint": "conversations.info",
                "source_fields": ["id"],
                "documentation_url": "https://docs.slack.dev/reference/methods/conversations.info",
                "retrieved_at": NOW - timedelta(minutes=2),
                "valid_until": NOW - timedelta(minutes=1),
            }
        )
        past_execution_result = match(
            make_record(),
            make_action(
                resolved_evidence=expired,
                requested_execution_at=NOW - timedelta(minutes=2),
            ),
        )

        self.assertEqual(
            future_result.reason_codes,
            ["contract:evidence_stale"],
        )
        self.assertEqual(
            past_execution_result.reason_codes,
            ["contract:evidence_stale"],
        )

    def test_scheduled_action_must_have_evidence_valid_at_delivery(self) -> None:
        action = make_action(
            requested_execution_at=NOW + timedelta(minutes=5),
        )

        result = match(make_record(), action)

        self.assertEqual(result.reason_codes, ["contract:evidence_stale"])

    def test_payload_must_match_reviewed_content(self) -> None:
        result = match(make_record(), make_action(payload_sha256="c" * 64))

        self.assertEqual(result.reason_codes, ["contract:payload_mismatch"])


if __name__ == "__main__":
    unittest.main()
