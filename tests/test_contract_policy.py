from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.actions import (  # noqa: E402
    CanonicalAction,
    ShellCanonicalizationError,
    canonicalize_shell_action,
    fingerprint_action,
)
from sentinel.contracts import (  # noqa: E402
    ActionContract,
    InMemoryContractStore,
    InMemoryTrustedEventConsumer,
    TrustedPromptEnvelope,
)
from sentinel.decision.contextual_evidence import (  # noqa: E402
    ActionMeasurement,
    AuthorizedCumulativeLimit,
    ContractEvaluationContext,
    ContractEvaluationFacts,
    UsageRecord,
)
from sentinel.decision.contract_policy import match_action_to_contract as _match_action  # noqa: E402


NOW = datetime(2026, 8, 31, 20, 0, tzinfo=timezone.utc)


def make_contract(**overrides: object) -> ActionContract:
    payload: dict[str, object] = {
        "objective": "Write exactly two reviewed build outputs.",
        "allowed_operations": {"write"},
        "allowed_tools": {"shell"},
        "exact_targets": ["/workspace/build/a.txt", "/workspace/build/b.txt"],
        "environment": "sandbox",
        "maximum_scope": "exact",
        "expected_side_effects": ["Write the reviewed output files."],
        "allowed_effects": {"write"},
        "forbidden_operations": {"network", "credential_access"},
        "forbidden_effects": ["Do not use the network or credentials."],
        "forbidden_effect_codes": {"network", "credential_access"},
        "rollback_plan": "Delete the output files.",
        "dry_run_required": False,
        "authorization_reference": "trusted-event-1",
        "expires_at": NOW + timedelta(hours=1),
    }
    payload.update(overrides)
    return ActionContract(**payload)


def active_record(**contract_overrides: object):
    consumer = InMemoryTrustedEventConsumer(
        host_id="test-host",
        session_id="session-1",
        channel="test-direct-user",
    )
    store = InMemoryContractStore(trusted_event_consumer=consumer)
    contract_id = str(uuid4())
    receipt = consumer.consume(
        TrustedPromptEnvelope(
            event_id=f"event-{uuid4()}",
            nonce=f"nonce-{uuid4().hex}",
            host_id="test-host",
            session_id="session-1",
            channel="test-direct-user",
            prompt="Activate reviewed contract.",
            purpose="task_transition",
            contract_id=contract_id,
            contract_version=1,
            decision="approve",
            issued_at=NOW - timedelta(seconds=1),
            expires_at=NOW + timedelta(minutes=5),
            authenticated=True,
        ),
        now=NOW,
    )
    record = store.create_active(
        make_contract(**contract_overrides),
        session_id="session-1",
        authorization_source="trusted_user",
        created_at=NOW,
        contract_id=contract_id,
        expected_active_task_id=None,
        trusted_event=receipt,
    )
    return store, record


def match(record, action, **overrides):
    arguments = {
        "expected_contract_id": record.contract_id,
        "expected_version": record.version,
        "session_id": record.session_id,
        "active_task_id": record.task_id,
        "now": NOW,
    }
    arguments.update(overrides)
    context = arguments.get("trusted_context")
    if context is not None and "trusted_context_producers" not in arguments:
        arguments["trusted_context_producers"] = {
            (context.source, context.producer_id)
        }
    return _match_action(record, action, **arguments)


def trusted_context(record, action, **overrides):
    payload = {
        "source": "reviewed_fixture",
        "producer_id": "sentinel-test-fixture-adapter",
        "snapshot_revision": "fixture-v1",
        "action_fingerprint": fingerprint_action(action),
        "contract_id": record.contract_id,
        "contract_version": record.version,
        "authority_epoch": record.authority_epoch,
        "session_id": record.session_id,
        "task_id": record.task_id,
        "environment": action.environment,
        "observed_at": NOW - timedelta(seconds=1),
        "valid_until": NOW + timedelta(minutes=1),
        "facts": ContractEvaluationFacts(),
    }
    payload.update(overrides)
    return ContractEvaluationContext(**payload)


class CanonicalActionTests(unittest.TestCase):
    def test_shell_canonicalizer_keeps_every_target(self) -> None:
        action = canonicalize_shell_action(
            "touch /workspace/build/a.txt /workspace/build/b.txt /workspace/escaped.txt",
            environment="sandbox",
        )

        self.assertEqual(
            action.targets,
            [
                "/workspace/build/a.txt",
                "/workspace/build/b.txt",
                "/workspace/escaped.txt",
            ],
        )
        self.assertEqual(action.operation, "write")
        self.assertEqual(action.effects, {"write"})

    def test_compound_shell_command_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            ShellCanonicalizationError,
            "action:compound_shell_unsupported",
        ):
            canonicalize_shell_action(
                "touch /workspace/build/a.txt && touch /workspace/escaped.txt",
                environment="sandbox",
            )

    def test_dynamic_option_target_and_unknown_command_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            ShellCanonicalizationError,
            "action:dynamic_shell_target",
        ):
            canonicalize_shell_action(
                "tee --output=$DEST /workspace/build/a.txt",
                environment="sandbox",
            )
        with self.assertRaisesRegex(
            ShellCanonicalizationError,
            "action:dynamic_shell_target",
        ):
            canonicalize_shell_action(
                "tee --output=/workspace/* /workspace/build/a.txt",
                environment="sandbox",
            )
        with self.assertRaisesRegex(
            ShellCanonicalizationError,
            "action:unsupported_shell_command",
        ):
            canonicalize_shell_action(
                "python deploy.py",
                environment="sandbox",
            )
        with self.assertRaisesRegex(
            ShellCanonicalizationError,
            "action:unsupported_shell_command",
        ):
            canonicalize_shell_action(
                "find /workspace -fprint /workspace/escaped.txt",
                environment="sandbox",
            )

    def test_state_dependent_copy_and_move_fail_closed(self) -> None:
        for command in (
            "cp /workspace/build/a.txt /workspace/build",
            "mv /workspace/build/a.txt /workspace/build",
        ):
            with self.assertRaisesRegex(
                ShellCanonicalizationError,
                "action:unsupported_shell_command",
            ):
                canonicalize_shell_action(command, environment="sandbox")

    def test_indirect_option_targets_fail_closed(self) -> None:
        for command in (
            "touch --reference=/workspace/secret /workspace/build/a.txt",
            "tail --follow /workspace/build/a.txt",
        ):
            with self.assertRaisesRegex(
                ShellCanonicalizationError,
                "action:indirect_shell_target",
            ):
                canonicalize_shell_action(command, environment="sandbox")

    def test_du_is_not_supported_because_ordinary_du_is_recursive(self) -> None:
        for command in (
            "du",
            "du /workspace/build",
            "du --summarize /workspace/build",
        ):
            with self.subTest(command=command), self.assertRaisesRegex(
                ShellCanonicalizationError,
                "action:unsupported_shell_command",
            ):
                canonicalize_shell_action(command, environment="sandbox")

    def test_recursive_and_parent_scope_options_fail_closed(self) -> None:
        for command in (
            "rm -rf /workspace/build",
            "rm --recursive /workspace/build",
            "ls -R /workspace/build",
            "ls -lR /workspace/build",
            "ls --recursive /workspace/build",
            "mkdir -p /workspace/build/nested",
            "rmdir --parents /workspace/build/nested",
        ):
            with self.assertRaisesRegex(
                ShellCanonicalizationError,
                "action:recursive_scope_unsupported",
            ):
                canonicalize_shell_action(command, environment="sandbox")

    def test_implicit_ls_target_is_the_trusted_working_directory(self) -> None:
        action = canonicalize_shell_action(
            "ls -la",
            environment="sandbox",
            cwd="/workspace/build",
        )

        self.assertEqual(action.targets, ["/workspace/build"])

    def test_command_specific_short_flags_are_not_globally_rejected(self) -> None:
        cases = {
            "rm -f /workspace/build/a.txt": ["/workspace/build/a.txt"],
            "ls -r": ["/workspace"],
            "ls -F": ["/workspace"],
            "ls --color /workspace/private.txt": ["/workspace/private.txt"],
            "ls --color=always /workspace/private.txt": ["/workspace/private.txt"],
            "stat -f /workspace/build/a.txt": ["/workspace/build/a.txt"],
        }
        for command, expected_targets in cases.items():
            with self.subTest(command=command):
                action = canonicalize_shell_action(
                    command,
                    environment="sandbox",
                )
                self.assertEqual(action.targets, expected_targets)

    def test_recursive_rm_short_flags_still_fail_closed(self) -> None:
        for command in (
            "rm -r /workspace/build",
            "rm -R /workspace/build",
            "rm -fr /workspace/build",
        ):
            with self.subTest(command=command), self.assertRaisesRegex(
                ShellCanonicalizationError,
                "action:recursive_scope_unsupported",
            ):
                canonicalize_shell_action(command, environment="sandbox")

    def test_pwd_targets_the_trusted_working_directory(self) -> None:
        action = canonicalize_shell_action(
            "pwd -P",
            environment="sandbox",
            cwd="/workspace/build",
        )

        self.assertEqual(action.targets, ["/workspace/build"])

    def test_df_target_is_not_discarded(self) -> None:
        action = canonicalize_shell_action(
            "df /workspace/build/a.txt",
            environment="sandbox",
        )

        self.assertEqual(action.targets, ["/workspace/build/a.txt"])

    def test_bare_df_and_other_targetless_reads_fail_closed(self) -> None:
        for command in ("df", "df -h", "cat", "head -n 5"):
            with self.subTest(command=command), self.assertRaisesRegex(
                ShellCanonicalizationError,
                "action:uninspectable_shell_target",
            ):
                canonicalize_shell_action(command, environment="sandbox")

    def test_which_is_not_supported_as_workspace_path_enforcement(self) -> None:
        with self.assertRaisesRegex(
            ShellCanonicalizationError,
            "action:unsupported_shell_command",
        ):
            canonicalize_shell_action("which python", environment="sandbox")

    def test_fingerprint_is_order_stable_and_covers_all_targets(self) -> None:
        first = CanonicalAction(
            family="shell",
            operation="write",
            targets=["/workspace/b", "/workspace/a"],
            effects={"write"},
            environment="sandbox",
        )
        reordered = CanonicalAction(
            family="shell",
            operation="write",
            targets=["/workspace/a", "/workspace/b"],
            effects={"write"},
            environment="sandbox",
        )
        overstep = CanonicalAction(
            family="shell",
            operation="write",
            targets=["/workspace/a", "/workspace/b", "/workspace/c"],
            effects={"write"},
            environment="sandbox",
        )

        self.assertEqual(fingerprint_action(first), fingerprint_action(reordered))
        self.assertNotEqual(fingerprint_action(first), fingerprint_action(overstep))


class ContractPolicyTests(unittest.TestCase):
    def test_matching_authority_is_persistent_for_multiple_actions(self) -> None:
        store, record = active_record()
        first_action = canonicalize_shell_action(
            "touch /workspace/build/a.txt",
            environment="sandbox",
        )
        second_action = canonicalize_shell_action(
            "touch /workspace/build/b.txt",
            environment="sandbox",
        )

        first = match(
            store.get_active("session-1", now=NOW),
            first_action,
            expected_contract_id=record.contract_id,
            expected_version=1,
            session_id="session-1",
            active_task_id=record.task_id,
            now=NOW,
        )
        second = match(
            store.get_active("session-1", now=NOW),
            second_action,
            expected_contract_id=record.contract_id,
            expected_version=1,
            session_id="session-1",
            active_task_id=record.task_id,
            now=NOW,
        )

        self.assertTrue(first.matches)
        self.assertTrue(second.matches)
        self.assertEqual(store.get_active("session-1", now=NOW).version, 1)

    def test_second_unapproved_target_causes_target_mismatch(self) -> None:
        _, record = active_record()
        action = canonicalize_shell_action(
            "touch /workspace/build/a.txt /workspace/escaped.txt",
            environment="sandbox",
        )

        result = match(record, action, now=NOW)

        self.assertFalse(result.matches)
        self.assertIn("contract:target_mismatch", result.reason_codes)

    def test_environment_mismatch_is_deterministic(self) -> None:
        _, record = active_record()
        action = canonicalize_shell_action(
            "touch /workspace/build/a.txt",
            environment="production",
        )

        result = match(record, action, now=NOW)

        self.assertIn("contract:environment_mismatch", result.reason_codes)

    def test_environment_context_and_preflight_are_enforced(self) -> None:
        _, record = active_record(
            environment_context={"account": "sandbox-a"},
        )
        action = canonicalize_shell_action(
            "touch /workspace/build/a.txt",
            environment="sandbox",
            environment_context={"account": "sandbox-b"},
        )

        result = match(record, action, now=NOW)
        self.assertIn("contract:environment_context_mismatch", result.reason_codes)

        payload = (
            record.model_dump()
            if hasattr(record, "model_dump")
            else record.dict()
        )
        incomplete = type(record)(**{**payload, "preflight_status": "needs_clarification"})
        incomplete_result = match(incomplete, action, now=NOW)
        self.assertIn("contract:preflight_incomplete", incomplete_result.reason_codes)

    def test_action_tool_must_match_contract_tool(self) -> None:
        _, record = active_record(allowed_tools={"mcp"})
        action = canonicalize_shell_action(
            "touch /workspace/build/a.txt",
            environment="sandbox",
        )

        result = match(record, action, now=NOW)

        self.assertIn("contract:tool_mismatch", result.reason_codes)

    def test_read_only_contract_reports_read_to_write(self) -> None:
        _, record = active_record(
            allowed_operations={"read"},
            allowed_effects={"read"},
        )
        action = canonicalize_shell_action(
            "touch /workspace/build/a.txt",
            environment="sandbox",
        )

        result = match(record, action, now=NOW)

        self.assertIn("contract:read_only_to_write", result.reason_codes)

    def test_operation_and_effect_mismatches_are_separate(self) -> None:
        _, record = active_record(
            allowed_operations={"execute"},
            allowed_effects={"execute"},
        )
        action = canonicalize_shell_action(
            "touch /workspace/build/a.txt",
            environment="sandbox",
        )

        result = match(record, action, now=NOW)

        self.assertIn("contract:operation_mismatch", result.reason_codes)
        self.assertIn("contract:effect_mismatch", result.reason_codes)

    def test_forbidden_effect_is_reported(self) -> None:
        _, record = active_record(
            allowed_effects={"write", "network"},
            forbidden_effect_codes={"network"},
        )
        action = CanonicalAction(
            family="shell",
            operation="write",
            targets=["/workspace/build/a.txt"],
            effects={"write", "network"},
            environment="sandbox",
        )

        result = match(record, action, now=NOW)

        self.assertIn("contract:forbidden_effect", result.reason_codes)

    def test_consequential_actions_require_targets_and_effects(self) -> None:
        _, record = active_record(
            allowed_operations={"delete"},
            allowed_effects={"delete"},
        )
        missing_target = CanonicalAction(
            family="file",
            tool="shell",
            operation="delete",
            targets=[],
            effects={"delete"},
            environment="sandbox",
        )
        missing_effect = CanonicalAction(
            family="file",
            tool="shell",
            operation="delete",
            targets=["/workspace/build/a.txt"],
            effects=set(),
            environment="sandbox",
        )

        target_result = match(record, missing_target)
        effect_result = match(record, missing_effect)

        self.assertIn("contract:target_incomplete", target_result.reason_codes)
        self.assertIn("contract:effect_incomplete", effect_result.reason_codes)

    def test_complete_mutation_does_not_trigger_completeness_reasons(self) -> None:
        _, record = active_record()
        action = canonicalize_shell_action(
            "touch /workspace/build/a.txt",
            environment="sandbox",
        )

        result = match(record, action)

        self.assertTrue(result.matches)
        self.assertNotIn("contract:target_incomplete", result.reason_codes)
        self.assertNotIn("contract:effect_incomplete", result.reason_codes)

    def test_targetless_read_fails_closed(self) -> None:
        _, record = active_record(
            allowed_operations={"read"},
            allowed_effects={"read"},
        )
        action = CanonicalAction(
            family="file",
            tool="shell",
            operation="read",
            targets=[],
            effects={"read"},
            environment="sandbox",
        )

        result = match(record, action)

        self.assertIn("contract:target_incomplete", result.reason_codes)

    def test_resolved_targets_and_effects_expand_policy_checks(self) -> None:
        _, record = active_record(
            allowed_operations={"execute"},
            allowed_effects={"execute"},
            exact_targets=["/workspace/report.py"],
            forbidden_effect_codes={"network", "external_send"},
        )
        action = CanonicalAction(
            family="shell",
            tool="shell",
            operation="execute",
            targets=["/workspace/report.py"],
            effects={"execute"},
            environment="sandbox",
        )
        context = trusted_context(
            record,
            action,
            facts=ContractEvaluationFacts(
                resolved_targets=["/home/user/.ssh/id_ed25519"],
                resolved_effects={"network", "external_send"},
            ),
        )

        result = match(record, action, trusted_context=context)

        self.assertIn("contract:target_mismatch", result.reason_codes)
        self.assertIn("contract:effect_mismatch", result.reason_codes)
        self.assertIn("contract:forbidden_effect", result.reason_codes)

    def test_context_binding_failure_rejects_without_trusting_resolved_facts(self) -> None:
        _, record = active_record()
        action = canonicalize_shell_action(
            "touch /workspace/build/a.txt",
            environment="sandbox",
        )
        context = trusted_context(
            record,
            action,
            action_fingerprint="0" * 64,
            facts=ContractEvaluationFacts(
                resolved_targets=["/workspace/escaped.txt"],
            ),
        )

        result = match(record, action, trusted_context=context)

        self.assertEqual(
            result.reason_codes,
            ["contract:context_evidence_binding_mismatch"],
        )

    def test_context_requires_registered_source_and_producer(self) -> None:
        _, record = active_record()
        action = canonicalize_shell_action(
            "touch /workspace/build/a.txt",
            environment="sandbox",
        )
        context = trusted_context(record, action)

        result = match(
            record,
            action,
            trusted_context=context,
            trusted_context_producers={
                ("reviewed_fixture", "different-producer")
            },
        )

        self.assertEqual(
            result.reason_codes,
            ["contract:context_evidence_binding_mismatch"],
        )

    def test_stale_context_is_rejected_without_trusting_resolved_facts(self) -> None:
        _, record = active_record()
        action = canonicalize_shell_action(
            "touch /workspace/build/a.txt",
            environment="sandbox",
        )
        context = trusted_context(
            record,
            action,
            observed_at=NOW - timedelta(minutes=6),
            valid_until=NOW + timedelta(minutes=1),
            facts=ContractEvaluationFacts(
                resolved_targets=["/workspace/escaped.txt"],
            ),
        )

        result = match(record, action, trusted_context=context)

        self.assertEqual(result.reason_codes, ["contract:context_evidence_stale"])

    def test_trusted_obligation_facts_override_agent_claims(self) -> None:
        _, backup_record = active_record(
            allowed_operations={"delete"},
            allowed_effects={"delete"},
            exact_targets=["db:test"],
            backup_required=True,
        )
        backup_action = CanonicalAction(
            family="database",
            tool="shell",
            operation="delete",
            targets=["db:test"],
            effects={"delete"},
            environment="sandbox",
            backup_available=True,
        )
        backup_context = trusted_context(
            backup_record,
            backup_action,
            facts=ContractEvaluationFacts(backup_verified=False),
        )
        _, dry_run_record = active_record(
            allowed_operations={"execute"},
            allowed_effects={"execute"},
            exact_targets=["service:prod-api"],
            dry_run_required=True,
        )
        dry_run_action = CanonicalAction(
            family="deployment",
            tool="shell",
            operation="execute",
            targets=["service:prod-api"],
            effects={"execute"},
            environment="sandbox",
            dry_run=True,
        )
        dry_run_context = trusted_context(
            dry_run_record,
            dry_run_action,
            facts=ContractEvaluationFacts(dry_run_verified=False),
        )

        backup_result = match(
            backup_record,
            backup_action,
            trusted_context=backup_context,
        )
        dry_run_result = match(
            dry_run_record,
            dry_run_action,
            trusted_context=dry_run_context,
        )

        self.assertIn(
            "contract:backup_evidence_unverified",
            backup_result.reason_codes,
        )
        self.assertIn(
            "contract:dry_run_evidence_conflict",
            dry_run_result.reason_codes,
        )

    def test_cumulative_limits_use_successful_same_task_usage(self) -> None:
        _, record = active_record(
            allowed_operations={"write"},
            allowed_effects={"fund_transfer"},
            allowed_tools={"bank"},
            exact_targets=["account:vendor-001"],
        )
        action = CanonicalAction(
            family="mcp",
            tool="bank",
            operation="write",
            targets=["account:vendor-001"],
            effects={"fund_transfer"},
            environment="sandbox",
        )
        limit = AuthorizedCumulativeLimit(
            metric="fund_transfer",
            maximum="10000",
            unit="usd",
            target="account:vendor-001",
        )
        proposed = ActionMeasurement(
            metric="fund_transfer",
            amount="1000",
            unit="usd",
            target="account:vendor-001",
        )
        usage = [
            UsageRecord(
                metric="fund_transfer",
                amount="6000",
                unit="usd",
                target="account:vendor-001",
                task_id=record.task_id,
            ),
            UsageRecord(
                metric="fund_transfer",
                amount="4000",
                unit="usd",
                target="account:vendor-001",
                task_id=record.task_id,
            ),
            UsageRecord(
                metric="fund_transfer",
                amount="9000",
                unit="usd",
                target="account:vendor-001",
                task_id="different-task",
            ),
            UsageRecord(
                metric="fund_transfer",
                amount="9000",
                unit="usd",
                target="account:vendor-001",
                task_id=record.task_id,
                successful=False,
            ),
        ]
        over_limit = trusted_context(
            record,
            action,
            facts=ContractEvaluationFacts(measurements=[proposed]),
            authorized_limits=[limit],
            recent_usage=usage,
        )
        at_limit = trusted_context(
            record,
            action,
            facts=ContractEvaluationFacts(
                measurements=[
                    ActionMeasurement(
                        metric="fund_transfer",
                        amount="0",
                        unit="usd",
                        target="account:vendor-001",
                    )
                ]
            ),
            authorized_limits=[limit],
            recent_usage=usage,
        )

        over_result = match(record, action, trusted_context=over_limit)
        at_limit_result = match(record, action, trusted_context=at_limit)

        self.assertIn(
            "contract:cumulative_limit_exceeded",
            over_result.reason_codes,
        )
        self.assertTrue(at_limit_result.matches)

    def test_cumulative_limit_rejects_unit_mismatch(self) -> None:
        _, record = active_record(
            allowed_effects={"write"},
        )
        action = canonicalize_shell_action(
            "touch /workspace/build/a.txt",
            environment="sandbox",
        )
        context = trusted_context(
            record,
            action,
            facts=ContractEvaluationFacts(
                measurements=[
                    ActionMeasurement(
                        metric="write_count",
                        amount="1",
                        unit="items",
                    )
                ]
            ),
            authorized_limits=[
                AuthorizedCumulativeLimit(
                    metric="write_count",
                    maximum="5",
                    unit="files",
                )
            ],
        )

        result = match(record, action, trusted_context=context)

        self.assertIn(
            "contract:cumulative_limit_unit_mismatch",
            result.reason_codes,
        )

    def test_cumulative_limit_requires_matching_measurement_and_scope(self) -> None:
        _, record = active_record()
        action = canonicalize_shell_action(
            "touch /workspace/build/a.txt",
            environment="sandbox",
        )
        limit = AuthorizedCumulativeLimit(
            metric="write_count",
            maximum="5",
            unit="files",
            target="/workspace/build/a.txt",
        )
        missing = trusted_context(
            record,
            action,
            authorized_limits=[limit],
        )
        wrong_scope = trusted_context(
            record,
            action,
            facts=ContractEvaluationFacts(
                measurements=[
                    ActionMeasurement(
                        metric="write_count",
                        amount="1",
                        unit="files",
                        target="/workspace/build/b.txt",
                    )
                ]
            ),
            authorized_limits=[limit],
        )

        missing_result = match(record, action, trusted_context=missing)
        wrong_scope_result = match(record, action, trusted_context=wrong_scope)

        self.assertIn(
            "contract:cumulative_limit_evidence_incomplete",
            missing_result.reason_codes,
        )
        self.assertIn(
            "contract:cumulative_limit_scope_mismatch",
            wrong_scope_result.reason_codes,
        )

    def test_cumulative_limits_account_by_exact_metric_unit_and_target(self) -> None:
        _, record = active_record(
            allowed_effects={"write"},
            exact_targets=["account:a", "account:b"],
        )
        action = CanonicalAction(
            family="mcp",
            tool="shell",
            operation="write",
            targets=["account:a", "account:b"],
            effects={"write"},
            environment="sandbox",
        )
        context = trusted_context(
            record,
            action,
            facts=ContractEvaluationFacts(
                measurements=[
                    ActionMeasurement(
                        metric="write_count",
                        amount="1",
                        unit="items",
                        target="account:a",
                    ),
                    ActionMeasurement(
                        metric="write_count",
                        amount="2",
                        unit="items",
                        target="account:b",
                    ),
                ]
            ),
            authorized_limits=[
                AuthorizedCumulativeLimit(
                    metric="write_count",
                    maximum="5",
                    unit="items",
                    target="account:a",
                ),
                AuthorizedCumulativeLimit(
                    metric="write_count",
                    maximum="5",
                    unit="items",
                    target="account:b",
                ),
            ],
        )

        result = match(record, action, trusted_context=context)

        self.assertTrue(result.matches)

    def test_cumulative_limits_allow_distinct_units_for_same_metric_target(self) -> None:
        _, record = active_record()
        action = canonicalize_shell_action(
            "touch /workspace/build/a.txt",
            environment="sandbox",
        )
        context = trusted_context(
            record,
            action,
            facts=ContractEvaluationFacts(
                measurements=[
                    ActionMeasurement(
                        metric="write_size",
                        amount="1",
                        unit="items",
                        target="/workspace/build/a.txt",
                    ),
                    ActionMeasurement(
                        metric="write_size",
                        amount="100",
                        unit="bytes",
                        target="/workspace/build/a.txt",
                    ),
                ]
            ),
            authorized_limits=[
                AuthorizedCumulativeLimit(
                    metric="write_size",
                    maximum="5",
                    unit="items",
                    target="/workspace/build/a.txt",
                ),
                AuthorizedCumulativeLimit(
                    metric="write_size",
                    maximum="1000",
                    unit="bytes",
                    target="/workspace/build/a.txt",
                ),
            ],
        )

        result = match(record, action, trusted_context=context)

        self.assertTrue(result.matches)

    def test_measurement_identifiers_reject_whitespace(self) -> None:
        with self.assertRaisesRegex(ValueError, "must not be blank"):
            ActionMeasurement(
                metric=" ",
                amount="1",
                unit="usd",
            )

    def test_dry_run_and_rollback_obligations_are_enforced(self) -> None:
        _, record = active_record(
            dry_run_required=True,
            rollback_required=True,
        )
        action = canonicalize_shell_action(
            "touch /workspace/build/a.txt",
            environment="sandbox",
        )

        result = match(record, action, now=NOW)

        self.assertIn("contract:dry_run_required", result.reason_codes)
        self.assertIn("contract:rollback_required", result.reason_codes)

    def test_obligations_pass_with_canonical_evidence(self) -> None:
        _, record = active_record(
            dry_run_required=True,
            rollback_required=True,
        )
        action = CanonicalAction(
            family="shell",
            tool="shell",
            operation="write",
            targets=["/workspace/build/a.txt"],
            effects={"write"},
            environment="sandbox",
            dry_run=True,
            rollback_available=True,
        )
        context = trusted_context(
            record,
            action,
            facts=ContractEvaluationFacts(
                dry_run_verified=True,
                rollback_verified=True,
            ),
        )

        result = match(record, action, now=NOW, trusted_context=context)

        self.assertTrue(result.matches)

    def test_obligation_claims_without_trusted_evidence_fail_closed(self) -> None:
        _, record = active_record(
            backup_required=True,
        )
        action = CanonicalAction(
            family="shell",
            tool="shell",
            operation="write",
            targets=["/workspace/build/a.txt"],
            effects={"write"},
            environment="sandbox",
            backup_available=True,
        )

        result = match(record, action)

        self.assertEqual(
            result.reason_codes,
            ["contract:obligation_evidence_required"],
        )

    def test_suspended_and_stale_contract_are_rejected(self) -> None:
        store, record = active_record()
        suspended = store.suspend(
            record.contract_id,
            expected_version=1,
            suspended_at=NOW + timedelta(minutes=1),
        )
        action = canonicalize_shell_action(
            "touch /workspace/build/a.txt",
            environment="sandbox",
        )

        result = match(
            suspended,
            action,
            expected_version=2,
            now=NOW + timedelta(minutes=1),
        )

        self.assertIn("contract:inactive", result.reason_codes)
        self.assertIn("contract:stale_version", result.reason_codes)

    def test_expired_record_is_rejected_even_before_store_cleanup(self) -> None:
        _, record = active_record(expires_at=NOW + timedelta(seconds=1))
        action = canonicalize_shell_action(
            "touch /workspace/build/a.txt",
            environment="sandbox",
        )

        result = match(
            record,
            action,
            now=NOW + timedelta(seconds=2),
        )

        self.assertIn("contract:expired", result.reason_codes)


if __name__ == "__main__":
    unittest.main()
