from __future__ import annotations

import sqlite3
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from pydantic import ValidationError


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.contracts import (  # noqa: E402
    ActionContract,
    ContractObligations,
    ContractConflictError,
    InMemoryAcceptedContractStore,
    InMemoryContractStore,
    InMemoryTrustedEventConsumer,
    InvalidContractTransition,
    SQLiteContractStore,
    TaskTemplate,
    TrustedEventError,
    TrustedPromptEnvelope,
)


NOW = datetime(2026, 8, 31, 20, 0, tzinfo=timezone.utc)


def make_contract(**overrides: object) -> ActionContract:
    payload: dict[str, object] = {
        "objective": "Create reviewed build outputs.",
        "allowed_operations": {"write"},
        "allowed_tools": {"shell"},
        "exact_targets": ["/workspace/build/a.txt", "/workspace/build/b.txt"],
        "environment": "sandbox",
        "maximum_scope": "exact",
        "expected_side_effects": ["Write the two reviewed build outputs."],
        "allowed_effects": {"write"},
        "forbidden_operations": {"network", "credential_access"},
        "forbidden_effects": ["Do not send data or read credentials."],
        "forbidden_effect_codes": {"network", "credential_access"},
        "rollback_plan": "Delete the generated output files.",
        "dry_run_required": False,
        "authorization_reference": "trusted-event-1",
        "version": 1,
        "expires_at": NOW + timedelta(hours=2),
    }
    payload.update(overrides)
    return ActionContract(**payload)


def make_envelope(**overrides: object) -> TrustedPromptEnvelope:
    payload: dict[str, object] = {
        "event_id": "event-1",
        "nonce": "nonce-1234567890abcdef",
        "host_id": "cursor-local",
        "session_id": "session-1",
        "channel": "cursor-direct-user",
        "prompt": "Create the two reviewed build outputs.",
        "purpose": "task_transition",
        "issued_at": NOW - timedelta(seconds=5),
        "expires_at": NOW + timedelta(minutes=5),
        "authenticated": True,
    }
    payload.update(overrides)
    return TrustedPromptEnvelope(**payload)


def consume_event(
    *,
    consumer: InMemoryTrustedEventConsumer | None = None,
    channel: str = "cursor-direct-user",
    purpose: str = "task_transition",
    contract_id: str | None = None,
    contract_version: int | None = None,
    decision: str | None = None,
):
    selected = consumer or InMemoryTrustedEventConsumer(
        host_id="cursor-local",
        session_id="session-1",
        channel=channel,
    )
    envelope = make_envelope(
        channel=channel,
        purpose=purpose,
        contract_id=contract_id,
        contract_version=contract_version,
        decision=decision,
    )
    receipt = selected.consume(
        envelope,
        expected_channel=channel,
        now=NOW,
    )
    return selected, receipt


def create_authorized(
    store: InMemoryContractStore | SQLiteContractStore,
    contract: ActionContract,
    **kwargs: object,
):
    """Create active authority through the same exact receipt boundary as production."""

    session_id = str(kwargs["session_id"])
    created_at = kwargs["created_at"]
    assert isinstance(created_at, datetime)
    contract_id = str(kwargs.pop("contract_id", uuid4()))
    consumer = store._trusted_event_consumer
    if consumer is None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="cursor-local",
            session_id=session_id,
        )
        store._trusted_event_consumer = consumer
    envelope = make_envelope(
        event_id=f"event-{uuid4()}",
        nonce=f"nonce-{uuid4().hex}",
        session_id=session_id,
        purpose="task_transition",
        contract_id=contract_id,
        contract_version=1,
        decision="approve",
        issued_at=created_at - timedelta(seconds=1),
        expires_at=created_at + timedelta(minutes=5),
    )
    receipt = consumer.consume(
        envelope,
        expected_host_id="cursor-local",
        expected_session_id=session_id,
        expected_channel="cursor-direct-user",
        now=created_at,
    )
    return store.create_active(
        contract,
        contract_id=contract_id,
        trusted_event=receipt,
        **kwargs,
    )


def consume_amendment_approval(
    store: InMemoryContractStore | SQLiteContractStore,
    *,
    contract_id: str,
    contract_version: int,
    session_id: str = "session-1",
    now: datetime = NOW,
    event_id: str | None = None,
):
    consumer = store._trusted_event_consumer
    if consumer is None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="cursor-local",
            session_id=session_id,
        )
        store._trusted_event_consumer = consumer
    envelope = make_envelope(
        event_id=event_id or f"event-{uuid4()}",
        nonce=f"nonce-{uuid4().hex}",
        session_id=session_id,
        purpose="amendment_decision",
        contract_id=contract_id,
        contract_version=contract_version,
        decision="approve",
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
    )
    return consumer.consume(
        envelope,
        expected_host_id="cursor-local",
        expected_session_id=session_id,
        expected_channel="cursor-direct-user",
        now=now,
    )


class ContractSchemaTests(unittest.TestCase):
    def test_contract_rejects_unknown_effect_code_typo(self) -> None:
        with self.assertRaises(ValidationError):
            make_contract(
                forbidden_effect_code={"network"},
                forbidden_effect_codes=set(),
            )

        with self.assertRaises(ValidationError):
            ContractObligations(dry_run_requred=True)

        with self.assertRaises(ValidationError):
            make_envelope(event_typo="ignored")

    def test_legacy_action_contract_and_single_use_store_are_preserved(self) -> None:
        contract = make_contract(allowed_effects=set(), forbidden_effect_codes=set())
        store = InMemoryAcceptedContractStore()
        accepted = store.accept(contract, approver_id="reviewer", accepted_at=NOW)

        self.assertIsNotNone(store.resolve(accepted.contract_id))
        self.assertIsNotNone(store.consume(accepted.contract_id))
        self.assertIsNone(store.consume(accepted.contract_id))

    def test_contract_record_is_immutable_and_server_copies_input(self) -> None:
        contract = make_contract()
        store = InMemoryContractStore()
        record = create_authorized(
            store,
            contract,
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )
        contract.exact_targets.append("/workspace/escaped.txt")

        self.assertNotIn("/workspace/escaped.txt", store.get(record.contract_id, 1).contract.exact_targets)
        with self.assertRaises((ValidationError, TypeError)):
            record.status = "revoked"  # type: ignore[misc]

    def test_trusted_event_is_bound_and_replay_safe(self) -> None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="cursor-local",
            session_id="session-1",
            channel="cursor-direct-user",
        )
        envelope = make_envelope()

        receipt = consumer.consume(envelope, now=NOW)
        self.assertEqual(receipt.event_id, envelope.event_id)
        receipt_payload = (
            receipt.model_dump()
            if hasattr(receipt, "model_dump")
            else receipt.dict()
        )
        with self.assertRaises(ValidationError):
            type(receipt)(**{**receipt_payload, "event_iid": "typo"})
        with self.assertRaisesRegex(TrustedEventError, "trusted_event:replayed"):
            consumer.consume(envelope, now=NOW)

        wrong_host = make_envelope(event_id="event-2", nonce="nonce-2222222222222222")
        with self.assertRaisesRegex(TrustedEventError, "trusted_event:binding_conflict"):
            consumer.consume(wrong_host, expected_host_id="different-host", now=NOW)

    def test_expired_trusted_event_is_rejected_without_burning_nonce(self) -> None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="cursor-local",
            session_id="session-1",
            channel="cursor-direct-user",
        )
        expired = make_envelope(expires_at=NOW - timedelta(seconds=1))

        with self.assertRaisesRegex(TrustedEventError, "trusted_event:expired"):
            consumer.consume(expired, now=NOW)

    def test_trusted_receipt_can_be_claimed_only_once(self) -> None:
        consumer, receipt = consume_event(
            purpose="task_reactivation",
            contract_id="contract-1",
            contract_version=1,
            decision="reactivate",
        )

        consumer.claim(
            receipt,
            expected_session_id="session-1",
            expected_purpose="task_reactivation",
            expected_contract_id="contract-1",
            expected_contract_version=1,
            expected_decision="reactivate",
            now=NOW,
        )
        with self.assertRaisesRegex(
            TrustedEventError,
            "trusted_event:invalid_or_used_receipt",
        ):
            consumer.claim(
                receipt,
                expected_session_id="session-1",
                expected_purpose="task_reactivation",
                expected_contract_id="contract-1",
                expected_contract_version=1,
                expected_decision="reactivate",
                now=NOW,
            )

    def test_template_is_explicitly_non_authorizing(self) -> None:
        template = TaskTemplate(
            template_id="template-1",
            version=1,
            name="Build two outputs",
            normalized_task_pattern="Create reviewed build outputs.",
            contract_defaults={
                "objective": "Create reviewed build outputs.",
                "allowed_operations": {"write"},
                "allowed_tools": {"shell"},
                "maximum_scope": "exact",
                "allowed_effects": {"write"},
            },
            provenance="trusted_user",
            last_reviewed_at=NOW,
        )

        self.assertFalse(template.authorizes_actions)
        self.assertFalse(hasattr(template, "status"))
        self.assertFalse(hasattr(template.contract_defaults, "authorization_reference"))
        with self.assertRaises(ValidationError):
            payload = (
                template.model_dump()
                if hasattr(template, "model_dump")
                else template.dict()
            )
            TaskTemplate(
                **{
                    **payload,
                    "authorizes_actions": True,
                }
            )


class ContractStoreTests(unittest.TestCase):
    def test_active_creation_requires_exact_trusted_receipt(self) -> None:
        store = InMemoryContractStore()

        with self.assertRaisesRegex(
            TrustedEventError,
            "trusted_event:consumer_not_configured",
        ):
            store.create_active(
                make_contract(),
                session_id="session-1",
                authorization_source="trusted_user",
                created_at=NOW,
                contract_id="contract-1",
            )

    def test_initial_pending_review_is_rejected_as_stranded(self) -> None:
        store = InMemoryContractStore()

        with self.assertRaisesRegex(
            InvalidContractTransition,
            "contract:initial_pending_review",
        ):
            store.create(
                make_contract(),
                session_id="session-1",
                authorization_source="trusted_user",
                created_at=NOW,
                status="pending_review",
            )

    def test_initial_proposal_has_valid_receipt_backed_activation(self) -> None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="cursor-local",
            session_id="session-1",
        )
        store = InMemoryContractStore(trusted_event_consumer=consumer)
        proposed = store.create(
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_host",
            created_at=NOW,
            contract_id="contract-proposed",
        )
        envelope = make_envelope(
            event_id="event-proposed-approval",
            nonce="nonce-proposed-approval-1234",
            purpose="task_transition",
            contract_id=proposed.contract_id,
            contract_version=1,
            decision="approve",
        )
        receipt = consumer.consume(
            envelope,
            expected_channel="cursor-direct-user",
            now=NOW,
        )

        activated = store.activate_proposed(
            proposed.contract_id,
            expected_version=1,
            expected_active_task_id=None,
            trusted_event=receipt,
            activated_at=NOW,
        )

        self.assertEqual(proposed.status, "proposed")
        self.assertEqual(proposed.authority_epoch, 0)
        self.assertEqual(activated.status, "active")
        self.assertEqual(activated.authority_epoch, 1)
        self.assertEqual(activated.authority_event_id, envelope.event_id)

    def test_contract_authority_persists_across_multiple_reads(self) -> None:
        store = InMemoryContractStore()
        record = create_authorized(
            store,
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )

        first = store.get_active("session-1", now=NOW)
        second = store.get_active("session-1", now=NOW + timedelta(seconds=1))

        self.assertEqual(first, record)
        self.assertEqual(second, record)

    def test_execution_guard_holds_lifecycle_state_until_release(self) -> None:
        store = InMemoryContractStore()
        record = create_authorized(
            store,
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )
        started = threading.Event()

        def suspend():
            started.set()
            return store.suspend(
                record.contract_id,
                expected_version=record.version,
                suspended_at=NOW + timedelta(seconds=1),
            )

        with ThreadPoolExecutor(max_workers=1) as pool:
            with store.execution_guard(
                record.contract_id,
                expected_version=record.version,
                expected_authority_epoch=record.authority_epoch,
                session_id=record.session_id,
                now=NOW,
            ):
                future = pool.submit(suspend)
                self.assertTrue(started.wait(timeout=1))
                self.assertFalse(future.done())
            suspended = future.result(timeout=1)

        self.assertEqual(suspended.status, "suspended")

    def test_stale_version_cannot_amend_contract(self) -> None:
        store = InMemoryContractStore()
        record = create_authorized(
            store,
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )
        store.amend(
            record.contract_id,
            make_contract(exact_targets=["/workspace/build/a.txt"]),
            expected_version=1,
            authorization_source="trusted_user",
            created_at=NOW + timedelta(minutes=1),
            sensitive=False,
            trusted_event=consume_amendment_approval(
                store,
                contract_id=record.contract_id,
                contract_version=2,
                now=NOW + timedelta(minutes=1),
            ),
        )

        with self.assertRaisesRegex(ContractConflictError, "contract:stale_version"):
            store.amend(
                record.contract_id,
                make_contract(exact_targets=["/workspace/build/b.txt"]),
                expected_version=1,
                authorization_source="trusted_user",
                created_at=NOW + timedelta(minutes=2),
                sensitive=False,
                trusted_event=consume_amendment_approval(
                    store,
                    contract_id=record.contract_id,
                    contract_version=2,
                    now=NOW + timedelta(minutes=2),
                ),
            )

    def test_active_amendment_requires_exact_fresh_receipt(self) -> None:
        store = InMemoryContractStore()
        active = create_authorized(
            store,
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )

        with self.assertRaisesRegex(TrustedEventError, "trusted_event:receipt_required"):
            store.amend(
                active.contract_id,
                make_contract(exact_targets=["/workspace/build/a.txt"]),
                expected_version=1,
                authorization_source="trusted_user",
                created_at=NOW + timedelta(minutes=1),
                sensitive=False,
            )

        wrong = consume_amendment_approval(
            store,
            contract_id=active.contract_id,
            contract_version=3,
            now=NOW + timedelta(minutes=1),
        )
        with self.assertRaisesRegex(
            TrustedEventError,
            "trusted_event:authority_binding_mismatch",
        ):
            store.amend(
                active.contract_id,
                make_contract(exact_targets=["/workspace/build/a.txt"]),
                expected_version=1,
                authorization_source="trusted_user",
                created_at=NOW + timedelta(minutes=1),
                sensitive=False,
                trusted_event=wrong,
            )
        self.assertEqual(len(store.list_versions(active.contract_id)), 1)

    def test_active_amendment_uses_new_event_as_authority(self) -> None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="cursor-local",
            session_id="session-1",
        )
        store = InMemoryContractStore(trusted_event_consumer=consumer)
        active = create_authorized(
            store,
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )
        envelope = make_envelope(
            event_id="event-amendment-2",
            nonce="nonce-amendment-22222222",
            channel="protected_local_ui",
            purpose="amendment_decision",
            contract_id=active.contract_id,
            contract_version=2,
            decision="approve",
        )
        receipt = consumer.consume(
            envelope,
            expected_channel="protected_local_ui",
            now=NOW,
        )

        amended = store.amend(
            active.contract_id,
            make_contract(exact_targets=["/workspace/build/a.txt"]),
            expected_version=1,
            authorization_source="trusted_host",
            created_at=NOW + timedelta(minutes=1),
            sensitive=False,
            trusted_event=receipt,
        )

        self.assertEqual(amended.authority_event_id, "event-amendment-2")
        self.assertEqual(amended.authorization_reference, "event-amendment-2")
        self.assertEqual(amended.contract.authorization_reference, "event-amendment-2")
        self.assertEqual(amended.authorization_source, "protected_local_ui")

    def test_sensitive_pending_version_leaves_previous_active(self) -> None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="cursor-local",
            session_id="session-1",
        )
        store = InMemoryContractStore(trusted_event_consumer=consumer)
        active = create_authorized(
            store,
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )
        pending = store.amend(
            active.contract_id,
            make_contract(
                allowed_operations={"write", "network"},
                allowed_effects={"write", "network"},
            ),
            expected_version=1,
            authorization_source="trusted_user",
            created_at=NOW + timedelta(minutes=1),
            sensitive=False,
        )

        self.assertEqual(pending.status, "pending_review")
        self.assertEqual(store.get_active("session-1", now=NOW).version, 1)
        _, receipt = consume_event(
            consumer=consumer,
            channel="protected_local_ui",
            purpose="amendment_decision",
            contract_id=active.contract_id,
            contract_version=pending.version,
            decision="reject",
        )
        rejected = store.decide_pending(
            active.contract_id,
            pending.version,
            approve=False,
            expected_active_version=1,
            decided_at=NOW + timedelta(minutes=2),
            trusted_event=receipt,
        )
        self.assertEqual(rejected.status, "rejected")

    def test_provider_audience_or_payload_change_requires_review(self) -> None:
        base_overrides = {
            "provider_scope": {
                "provider": "slack",
                "tenant_id": "T-INTERNAL",
                "resource_account_id": "APP-SENTINEL",
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
                "allowed_recipient_ids": {"U-APPROVED"},
                "allowed_audience_resource_ids": {"C-ENGINEERING"},
            },
            "approved_payload_sha256": "a" * 64,
        }
        changes = {
            "provider": {
                "provider_scope": {
                    "provider": "slack",
                    "tenant_id": "T-OTHER",
                    "resource_account_id": "APP-SENTINEL",
                    "credential_principal_id": "BOT-SENTINEL",
                    "actor_id": "U-OPERATOR",
                    "adapter_id": "sentinel:slack:v1",
                }
            },
            "audience": {
                "audience_policy": {
                    "allow_external": True,
                    "allow_guests": False,
                    "allow_public": False,
                    "allow_broadcast": False,
                    "allow_recipient_expansion": False,
                    "maximum_recipient_count": 20,
                    "allowed_recipient_ids": {"U-APPROVED"},
                    "allowed_audience_resource_ids": {"C-ENGINEERING"},
                }
            },
            "recipient_allowlist_removal": {
                "audience_policy": {
                    "allow_external": False,
                    "allow_guests": False,
                    "allow_public": False,
                    "allow_broadcast": False,
                    "allow_recipient_expansion": False,
                    "maximum_recipient_count": 20,
                    "allowed_recipient_ids": None,
                    "allowed_audience_resource_ids": {"C-ENGINEERING"},
                }
            },
            "payload": {"approved_payload_sha256": "b" * 64},
        }

        for name, change in changes.items():
            with self.subTest(name=name):
                store = InMemoryContractStore()
                active = create_authorized(
                    store,
                    make_contract(**base_overrides),
                    session_id="session-1",
                    authorization_source="trusted_user",
                    created_at=NOW,
                )
                pending = store.amend(
                    active.contract_id,
                    make_contract(**{**base_overrides, **change}),
                    expected_version=1,
                    authorization_source="trusted_user",
                    created_at=NOW + timedelta(minutes=1),
                    sensitive=False,
                )

                self.assertEqual(pending.status, "pending_review")
                self.assertEqual(store.get_active("session-1", now=NOW).version, 1)
        self.assertEqual(store.get_active("session-1", now=NOW).version, 1)

    def test_adding_provider_restrictions_is_a_non_sensitive_narrowing(self) -> None:
        store = InMemoryContractStore()
        active = create_authorized(
            store,
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )
        narrowed = store.amend(
            active.contract_id,
            make_contract(
                provider_scope={
                    "provider": "slack",
                    "tenant_id": "T-INTERNAL",
                    "resource_account_id": "APP-SENTINEL",
                    "credential_principal_id": "BOT-SENTINEL",
                    "actor_id": "U-OPERATOR",
                    "adapter_id": "sentinel:slack:v1",
                },
                audience_policy={
                    "allow_external": False,
                    "allow_guests": False,
                    "allow_public": False,
                    "allow_broadcast": False,
                    "allow_recipient_expansion": False,
                    "maximum_recipient_count": 20,
                    "allowed_audience_resource_ids": {"C-ENGINEERING"},
                },
                approved_payload_sha256="a" * 64,
            ),
            expected_version=1,
            authorization_source="trusted_user",
            created_at=NOW + timedelta(minutes=1),
            sensitive=False,
            trusted_event=consume_amendment_approval(
                store,
                contract_id=active.contract_id,
                contract_version=2,
                now=NOW + timedelta(minutes=1),
            ),
        )

        self.assertEqual(narrowed.status, "active")
        self.assertEqual(narrowed.version, 2)

    def test_completing_required_provider_profile_needs_review(self) -> None:
        store = InMemoryContractStore()
        active = create_authorized(
            store,
            make_contract(
                allowed_operations={"external_communication"},
                allowed_tools={"gmail"},
                allowed_effects={"external_send"},
                exact_targets=["gmail:message:reviewed"],
            ),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )
        pending = store.amend(
            active.contract_id,
            make_contract(
                allowed_operations={"external_communication"},
                allowed_tools={"gmail"},
                allowed_effects={"external_send"},
                exact_targets=["gmail:message:reviewed"],
                provider_scope={
                    "provider": "gmail",
                    "tenant_id": "T-INTERNAL",
                    "resource_account_id": "MAILBOX-1",
                    "credential_principal_id": "GOOGLE-OAUTH-SUB:U-1",
                    "actor_id": "U-1",
                    "adapter_id": "sentinel:gmail:v1",
                },
                audience_policy={
                    "maximum_recipient_count": 1,
                    "allowed_recipient_ids": {"U-APPROVED"},
                },
                approved_payload_sha256="a" * 64,
            ),
            expected_version=1,
            authorization_source="trusted_user",
            created_at=NOW + timedelta(minutes=1),
            sensitive=False,
        )

        self.assertEqual(pending.status, "pending_review")
        self.assertEqual(store.get_active("session-1", now=NOW).version, 1)

    def test_clearing_effect_allowlist_requires_review(self) -> None:
        store = InMemoryContractStore()
        active = create_authorized(
            store,
            make_contract(
                allowed_operations={"write", "delete"},
                allowed_effects={"write"},
            ),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )

        pending = store.amend(
            active.contract_id,
            make_contract(
                allowed_operations={"write", "delete"},
                allowed_effects=set(),
            ),
            expected_version=1,
            authorization_source="trusted_user",
            created_at=NOW,
            sensitive=False,
        )

        self.assertEqual(pending.status, "pending_review")
        self.assertEqual(store.get_active("session-1", now=NOW).version, 1)

    def test_expired_pending_version_cannot_be_approved(self) -> None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="cursor-local",
            session_id="session-1",
        )
        store = InMemoryContractStore(trusted_event_consumer=consumer)
        active = create_authorized(
            store,
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )
        pending = store.amend(
            active.contract_id,
            make_contract(
                allowed_operations={"write", "network"},
                allowed_effects={"write", "network"},
                expires_at=NOW + timedelta(seconds=1),
            ),
            expected_version=1,
            authorization_source="trusted_user",
            created_at=NOW,
            sensitive=False,
        )
        _, receipt = consume_event(
            consumer=consumer,
            channel="protected_local_ui",
            purpose="amendment_decision",
            contract_id=active.contract_id,
            contract_version=pending.version,
            decision="approve",
        )

        with self.assertRaisesRegex(InvalidContractTransition, "contract:expired"):
            store.decide_pending(
                active.contract_id,
                pending.version,
                approve=True,
                expected_active_version=1,
                decided_at=NOW + timedelta(seconds=2),
                trusted_event=receipt,
            )

        self.assertEqual(store.get(active.contract_id, pending.version).status, "expired")
        self.assertEqual(store.get_active("session-1", now=NOW).version, 1)

    def test_unbound_or_foreign_receipt_cannot_approve_amendment(self) -> None:
        owner = InMemoryTrustedEventConsumer(
            host_id="cursor-local",
            session_id="session-1",
        )
        store = InMemoryContractStore(trusted_event_consumer=owner)
        active = create_authorized(
            store,
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )
        pending = store.amend(
            active.contract_id,
            make_contract(allowed_tools={"shell", "mcp"}),
            expected_version=1,
            authorization_source="trusted_user",
            created_at=NOW,
            sensitive=False,
        )
        attacker, forged_receipt = consume_event(
            channel="protected_local_ui",
            purpose="amendment_decision",
            contract_id=active.contract_id,
            contract_version=pending.version,
            decision="approve",
        )

        with self.assertRaisesRegex(TrustedEventError, "trusted_event:invalid_receipt"):
            store.decide_pending(
                active.contract_id,
                pending.version,
                approve=True,
                expected_active_version=1,
                decided_at=NOW,
                trusted_event=forged_receipt,
            )

        self.assertIsNot(attacker, owner)
        self.assertEqual(store.get_active("session-1", now=NOW).version, 1)

    def test_approving_sensitive_version_supersedes_previous(self) -> None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="cursor-local",
            session_id="session-1",
        )
        store = InMemoryContractStore(trusted_event_consumer=consumer)
        active = create_authorized(
            store,
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )
        pending = store.amend(
            active.contract_id,
            make_contract(
                allowed_operations={"write", "network"},
                allowed_effects={"write", "network"},
            ),
            expected_version=1,
            authorization_source="trusted_user",
            created_at=NOW + timedelta(minutes=1),
            sensitive=True,
        )

        _, receipt = consume_event(
            consumer=consumer,
            channel="protected_local_ui",
            purpose="amendment_decision",
            contract_id=active.contract_id,
            contract_version=pending.version,
            decision="approve",
        )
        approved = store.decide_pending(
            active.contract_id,
            pending.version,
            approve=True,
            expected_active_version=1,
            decided_at=NOW + timedelta(minutes=2),
            trusted_event=receipt,
        )

        self.assertEqual(approved.status, "active")
        self.assertEqual(store.get(active.contract_id, 1).status, "superseded")
        self.assertEqual(store.get_active("session-1", now=NOW).version, 2)

    def test_new_active_task_suspends_previous_task(self) -> None:
        store = InMemoryContractStore()
        first = create_authorized(
            store,
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )
        second = create_authorized(
            store,
            make_contract(objective="Create a different reviewed output."),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW + timedelta(minutes=1),
            expected_active_task_id=first.task_id,
        )

        self.assertEqual(store.get(first.contract_id, 1).status, "suspended")
        self.assertEqual(store.get_active("session-1", now=NOW).task_id, second.task_id)

    def test_reactivation_requires_receipt_and_suspends_current_task(self) -> None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="cursor-local",
            session_id="session-1",
        )
        store = InMemoryContractStore(trusted_event_consumer=consumer)
        first = create_authorized(
            store,
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )
        second = create_authorized(
            store,
            make_contract(objective="Different task"),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW + timedelta(minutes=1),
            expected_active_task_id=first.task_id,
        )
        _, receipt = consume_event(
            consumer=consumer,
            purpose="task_reactivation",
            contract_id=first.contract_id,
            contract_version=1,
            decision="reactivate",
        )

        reactivated = store.reactivate(
            first.contract_id,
            expected_version=1,
            expected_active_task_id=second.task_id,
            trusted_event=receipt,
            reactivated_at=NOW + timedelta(minutes=2),
        )

        self.assertEqual(reactivated.status, "active")
        self.assertEqual(first.authority_epoch, 1)
        self.assertEqual(reactivated.authority_epoch, 3)
        self.assertEqual(store.get(second.contract_id, 1).status, "suspended")
        self.assertEqual(store.get(second.contract_id, 1).authority_epoch, 2)
        self.assertEqual(store.get_active("session-1", now=NOW).task_id, first.task_id)

    def test_revoked_contract_cannot_reactivate(self) -> None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="cursor-local",
            session_id="session-1",
        )
        store = InMemoryContractStore(trusted_event_consumer=consumer)
        active = create_authorized(
            store,
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )
        suspended = store.suspend(
            active.contract_id,
            expected_version=1,
            suspended_at=NOW + timedelta(minutes=1),
        )
        store.revoke(
            suspended.contract_id,
            expected_version=1,
            revoked_at=NOW + timedelta(minutes=2),
        )
        _, receipt = consume_event(
            consumer=consumer,
            purpose="task_reactivation",
            contract_id=active.contract_id,
            contract_version=1,
            decision="reactivate",
        )

        with self.assertRaisesRegex(InvalidContractTransition, "contract:cannot_reactivate"):
            store.reactivate(
                active.contract_id,
                expected_version=1,
                expected_active_task_id=None,
                trusted_event=receipt,
                reactivated_at=NOW + timedelta(minutes=3),
            )

    def test_expired_contract_is_removed_from_active_session(self) -> None:
        store = InMemoryContractStore()
        active = create_authorized(
            store,
            make_contract(expires_at=NOW + timedelta(seconds=1)),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )

        self.assertIsNone(store.get_active("session-1", now=NOW + timedelta(seconds=2)))
        self.assertEqual(store.get(active.contract_id, 1).status, "expired")


class SQLiteContractStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.database = Path(self._temporary_directory.name) / "contracts.sqlite3"

    def tearDown(self) -> None:
        self._temporary_directory.cleanup()

    def test_execution_guard_blocks_lifecycle_write_from_second_store(self) -> None:
        first = SQLiteContractStore(self.database)
        record = create_authorized(
            first,
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )
        second = SQLiteContractStore(self.database)
        started = threading.Event()

        def suspend():
            started.set()
            return second.suspend(
                record.contract_id,
                expected_version=record.version,
                suspended_at=NOW + timedelta(seconds=1),
            )

        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                with first.execution_guard(
                    record.contract_id,
                    expected_version=record.version,
                    expected_authority_epoch=record.authority_epoch,
                    session_id=record.session_id,
                    now=NOW,
                ):
                    self.assertEqual(
                        first.get_active("session-1", now=NOW),
                        record,
                    )
                    future = pool.submit(suspend)
                    self.assertTrue(started.wait(timeout=1))
                    self.assertFalse(future.done())
                suspended = future.result(timeout=1)
            self.assertEqual(suspended.status, "suspended")
        finally:
            first.close()
            second.close()

    def test_legacy_receiptless_active_row_is_suspended_on_migration(self) -> None:
        contract = make_contract()
        contract_json = (
            contract.model_dump_json()
            if hasattr(contract, "model_dump_json")
            else contract.json()
        )
        connection = sqlite3.connect(self.database)
        connection.executescript(
            """
            CREATE TABLE contract_lineages (
                contract_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL UNIQUE,
                session_id TEXT NOT NULL,
                UNIQUE (contract_id, task_id, session_id)
            );
            CREATE TABLE contract_records (
                contract_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                status TEXT NOT NULL,
                contract_json TEXT NOT NULL,
                authorization_source TEXT NOT NULL,
                authorization_reference TEXT NOT NULL,
                parent_contract_id TEXT,
                parent_version INTEGER,
                supersedes_version INTEGER,
                superseded_by_version INTEGER,
                preflight_status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY (contract_id, version),
                FOREIGN KEY (contract_id, task_id, session_id)
                    REFERENCES contract_lineages(contract_id, task_id, session_id)
            );
            """
        )
        connection.execute(
            """
            INSERT INTO contract_lineages (contract_id, task_id, session_id)
            VALUES ('legacy-contract', 'legacy-task', 'session-1')
            """
        )
        connection.execute(
            """
            INSERT INTO contract_records (
                contract_id, task_id, session_id, version, status,
                contract_json, authorization_source, authorization_reference,
                parent_contract_id, parent_version, supersedes_version,
                superseded_by_version, preflight_status, created_at,
                updated_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy-contract",
                "legacy-task",
                "session-1",
                1,
                "active",
                contract_json,
                "trusted_user",
                "self-asserted-reference",
                None,
                None,
                None,
                None,
                "complete",
                NOW.isoformat(),
                NOW.isoformat(),
                contract.expires_at.isoformat(),
            ),
        )
        connection.commit()
        connection.close()

        store = SQLiteContractStore(self.database)
        try:
            migrated = store.get("legacy-contract", 1)
            assert migrated is not None
            self.assertEqual(migrated.status, "suspended")
            self.assertEqual(migrated.authority_epoch, 2)
            self.assertIsNone(migrated.authority_event_id)
            self.assertIsNone(store.get_active("session-1", now=NOW))
        finally:
            store.close()

    def test_records_and_active_authority_persist_after_reopen(self) -> None:
        store = SQLiteContractStore(self.database)
        first = create_authorized(
            store,
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )
        amended = store.amend(
            first.contract_id,
            make_contract(exact_targets=["/workspace/build/a.txt"]),
            expected_version=1,
            authorization_source="trusted_user",
            created_at=NOW + timedelta(minutes=1),
            sensitive=False,
            trusted_event=consume_amendment_approval(
                store,
                contract_id=first.contract_id,
                contract_version=2,
                now=NOW + timedelta(minutes=1),
            ),
        )
        store.close()

        reopened = SQLiteContractStore(self.database)
        try:
            self.assertEqual(reopened.get(first.contract_id, 1).status, "superseded")
            self.assertEqual(reopened.get_active("session-1", now=NOW), amended)
            self.assertEqual(
                [record.version for record in reopened.list_versions(first.contract_id)],
                [1, 2],
            )
            self.assertEqual(
                reopened._connection.execute("PRAGMA journal_mode").fetchone()[0],
                "wal",
            )
            self.assertEqual(
                reopened._connection.execute("PRAGMA synchronous").fetchone()[0],
                2,
            )
        finally:
            reopened.close()

    def test_active_and_pending_invariants_survive_task_switch(self) -> None:
        store = SQLiteContractStore(self.database)
        try:
            first = create_authorized(
                store,
                make_contract(),
                session_id="session-1",
                authorization_source="trusted_user",
                created_at=NOW,
            )
            pending = store.amend(
                first.contract_id,
                make_contract(allowed_tools={"shell", "mcp"}),
                expected_version=1,
                authorization_source="trusted_user",
                created_at=NOW + timedelta(minutes=1),
            )

            with self.assertRaisesRegex(
                ContractConflictError,
                "contract:pending_version_exists",
            ):
                store.amend(
                    first.contract_id,
                    make_contract(allowed_operations={"write", "network"}),
                    expected_version=1,
                    authorization_source="trusted_user",
                    created_at=NOW + timedelta(minutes=2),
                )
            with self.assertRaisesRegex(
                ContractConflictError,
                "contract:stale_active_task",
            ):
                store.create_active(
                    make_contract(objective="Second task"),
                    session_id="session-1",
                    authorization_source="trusted_user",
                    created_at=NOW + timedelta(minutes=2),
                )

            second = create_authorized(
                store,
                make_contract(objective="Second task"),
                session_id="session-1",
                authorization_source="trusted_user",
                created_at=NOW + timedelta(minutes=2),
                expected_active_task_id=first.task_id,
            )
            self.assertEqual(store.get(first.contract_id, 1).status, "suspended")
            self.assertEqual(store.get(first.contract_id, pending.version).status, "pending_review")
            self.assertEqual(store.get_active("session-1", now=NOW).task_id, second.task_id)
        finally:
            store.close()

    def test_stale_cas_is_rejected_across_open_store_instances(self) -> None:
        first_store = SQLiteContractStore(self.database)
        second_store = SQLiteContractStore(self.database)
        try:
            created = create_authorized(
                first_store,
                make_contract(),
                session_id="session-1",
                authorization_source="trusted_user",
                created_at=NOW,
            )
            first_store.amend(
                created.contract_id,
                make_contract(exact_targets=["/workspace/build/a.txt"]),
                expected_version=1,
                authorization_source="trusted_user",
                created_at=NOW + timedelta(minutes=1),
                sensitive=False,
                trusted_event=consume_amendment_approval(
                    first_store,
                    contract_id=created.contract_id,
                    contract_version=2,
                    now=NOW + timedelta(minutes=1),
                ),
            )

            with self.assertRaisesRegex(ContractConflictError, "contract:stale_version"):
                second_store.amend(
                    created.contract_id,
                    make_contract(exact_targets=["/workspace/build/b.txt"]),
                    expected_version=1,
                    authorization_source="trusted_user",
                    created_at=NOW + timedelta(minutes=1),
                    sensitive=False,
                    trusted_event=consume_amendment_approval(
                        second_store,
                        contract_id=created.contract_id,
                        contract_version=2,
                        now=NOW + timedelta(minutes=1),
                    ),
                )
        finally:
            first_store.close()
            second_store.close()

    def test_concurrent_amendments_allow_exactly_one_cas_winner(self) -> None:
        creator = SQLiteContractStore(self.database)
        created = create_authorized(
            creator,
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )
        creator.close()

        stores = [SQLiteContractStore(self.database), SQLiteContractStore(self.database)]
        barrier = threading.Barrier(2)

        def amend(store: SQLiteContractStore, target: str) -> str:
            barrier.wait()
            try:
                store.amend(
                    created.contract_id,
                    make_contract(exact_targets=[target]),
                    expected_version=1,
                    authorization_source="trusted_user",
                    created_at=NOW + timedelta(minutes=1),
                    sensitive=False,
                    trusted_event=consume_amendment_approval(
                        store,
                        contract_id=created.contract_id,
                        contract_version=2,
                        now=NOW + timedelta(minutes=1),
                    ),
                )
                return "committed"
            except ContractConflictError as exc:
                return exc.reason_code

        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(
                    executor.map(
                        amend,
                        stores,
                        ["/workspace/build/a.txt", "/workspace/build/b.txt"],
                    )
                )
            self.assertCountEqual(results, ["committed", "contract:stale_version"])
            self.assertEqual(len(stores[0].list_versions(created.contract_id)), 2)
        finally:
            for store in stores:
                store.close()

    def test_failed_protected_transaction_restores_database_and_receipt(self) -> None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="cursor-local",
            session_id="session-1",
        )
        store = SQLiteContractStore(
            self.database,
            trusted_event_consumer=consumer,
        )
        try:
            active = create_authorized(
                store,
                make_contract(),
                session_id="session-1",
                authorization_source="trusted_user",
                created_at=NOW,
            )
            pending = store.amend(
                active.contract_id,
                make_contract(allowed_tools={"shell", "mcp"}),
                expected_version=1,
                authorization_source="trusted_user",
                created_at=NOW + timedelta(minutes=1),
            )
            _, receipt = consume_event(
                consumer=consumer,
                channel="protected_local_ui",
                purpose="amendment_decision",
                contract_id=active.contract_id,
                contract_version=pending.version,
                decision="approve",
            )
            store._connection.execute(
                """
                CREATE TRIGGER fail_test_approval
                BEFORE UPDATE ON contract_records
                WHEN NEW.status = 'superseded'
                BEGIN
                    SELECT RAISE(ABORT, 'injected write failure');
                END
                """
            )

            with self.assertRaisesRegex(sqlite3.IntegrityError, "injected write failure"):
                store.decide_pending(
                    active.contract_id,
                    pending.version,
                    approve=True,
                    expected_active_version=1,
                    decided_at=NOW + timedelta(minutes=2),
                    trusted_event=receipt,
                )

            self.assertEqual(store.get(active.contract_id, 1).status, "active")
            self.assertEqual(store.get(active.contract_id, pending.version).status, "pending_review")
            store._connection.execute("DROP TRIGGER fail_test_approval")
            approved = store.decide_pending(
                active.contract_id,
                pending.version,
                approve=True,
                expected_active_version=1,
                decided_at=NOW + timedelta(minutes=2),
                trusted_event=receipt,
            )
            self.assertEqual(approved.status, "active")
        finally:
            store.close()

    def test_failed_active_amendment_restores_receipt_across_reopen(self) -> None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="cursor-local",
            session_id="session-1",
        )
        store = SQLiteContractStore(
            self.database,
            trusted_event_consumer=consumer,
        )
        active = create_authorized(
            store,
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )
        receipt = consume_amendment_approval(
            store,
            contract_id=active.contract_id,
            contract_version=2,
            now=NOW + timedelta(minutes=1),
            event_id="event-active-amendment",
        )
        store._connection.execute(
            """
            CREATE TRIGGER fail_test_active_amendment
            BEFORE INSERT ON contract_records
            WHEN NEW.version = 2
            BEGIN
                SELECT RAISE(ABORT, 'injected amendment failure');
            END
            """
        )

        with self.assertRaisesRegex(
            sqlite3.IntegrityError,
            "injected amendment failure",
        ):
            store.amend(
                active.contract_id,
                make_contract(exact_targets=["/workspace/build/a.txt"]),
                expected_version=1,
                authorization_source="trusted_user",
                created_at=NOW + timedelta(minutes=1),
                sensitive=False,
                trusted_event=receipt,
            )
        self.assertEqual(store.get(active.contract_id, 1).status, "active")
        self.assertIsNone(store.get(active.contract_id, 2))
        store._connection.execute("DROP TRIGGER fail_test_active_amendment")
        store._connection.commit()
        store.close()

        reopened = SQLiteContractStore(
            self.database,
            trusted_event_consumer=consumer,
        )
        amended = reopened.amend(
            active.contract_id,
            make_contract(exact_targets=["/workspace/build/a.txt"]),
            expected_version=1,
            authorization_source="trusted_user",
            created_at=NOW + timedelta(minutes=1),
            sensitive=False,
            trusted_event=receipt,
        )
        reopened.close()

        final = SQLiteContractStore(self.database)
        try:
            self.assertEqual(amended.authority_event_id, "event-active-amendment")
            self.assertEqual(final.get(active.contract_id, 1).status, "superseded")
            self.assertEqual(
                final.get_active("session-1", now=NOW).authority_event_id,
                "event-active-amendment",
            )
        finally:
            final.close()

    def test_active_amendment_event_replay_is_blocked_after_reopen(self) -> None:
        first_consumer = InMemoryTrustedEventConsumer(
            host_id="cursor-local",
            session_id="session-1",
        )
        store = SQLiteContractStore(
            self.database,
            trusted_event_consumer=first_consumer,
        )
        active = create_authorized(
            store,
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )
        envelope = make_envelope(
            event_id="event-replayed-amendment",
            nonce="nonce-replayed-amendment-1",
            purpose="amendment_decision",
            contract_id=active.contract_id,
            contract_version=2,
            decision="approve",
        )
        receipt = first_consumer.consume(
            envelope,
            expected_channel="cursor-direct-user",
            now=NOW,
        )
        store.amend(
            active.contract_id,
            make_contract(exact_targets=["/workspace/build/a.txt"]),
            expected_version=1,
            authorization_source="trusted_user",
            created_at=NOW + timedelta(minutes=1),
            sensitive=False,
            trusted_event=receipt,
        )
        store.close()

        second_consumer = InMemoryTrustedEventConsumer(
            host_id="cursor-local",
            session_id="session-1",
        )
        replayed = second_consumer.consume(
            envelope,
            expected_channel="cursor-direct-user",
            now=NOW,
        )
        reopened = SQLiteContractStore(
            self.database,
            trusted_event_consumer=second_consumer,
        )
        try:
            with self.assertRaisesRegex(TrustedEventError, "trusted_event:replayed"):
                reopened.amend(
                    active.contract_id,
                    make_contract(exact_targets=["/workspace/build/a.txt"]),
                    expected_version=2,
                    authorization_source="trusted_user",
                    created_at=NOW + timedelta(minutes=2),
                    sensitive=False,
                    trusted_event=replayed,
                )
            self.assertEqual(len(reopened.list_versions(active.contract_id)), 2)
        finally:
            reopened.close()

    def test_replay_ids_survive_reopen_and_block_reused_lifecycle_event(self) -> None:
        first_consumer = InMemoryTrustedEventConsumer(
            host_id="cursor-local",
            session_id="session-1",
        )
        store = SQLiteContractStore(
            self.database,
            trusted_event_consumer=first_consumer,
        )
        active = create_authorized(
            store,
            make_contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
        )
        store.suspend(
            active.contract_id,
            expected_version=1,
            suspended_at=NOW + timedelta(minutes=1),
        )
        envelope = make_envelope(
            purpose="task_reactivation",
            contract_id=active.contract_id,
            contract_version=1,
            decision="reactivate",
        )
        receipt = first_consumer.consume(
            envelope,
            expected_channel="cursor-direct-user",
            now=NOW,
        )
        store.reactivate(
            active.contract_id,
            expected_version=1,
            expected_active_task_id=None,
            trusted_event=receipt,
            reactivated_at=NOW + timedelta(minutes=2),
        )
        store.suspend(
            active.contract_id,
            expected_version=1,
            suspended_at=NOW + timedelta(minutes=3),
        )
        store.close()

        second_consumer = InMemoryTrustedEventConsumer(
            host_id="cursor-local",
            session_id="session-1",
        )
        reopened = SQLiteContractStore(
            self.database,
            trusted_event_consumer=second_consumer,
        )
        replayed_receipt = second_consumer.consume(
            envelope,
            expected_channel="cursor-direct-user",
            now=NOW,
        )
        try:
            with self.assertRaisesRegex(TrustedEventError, "trusted_event:replayed"):
                reopened.reactivate(
                    active.contract_id,
                    expected_version=1,
                    expected_active_task_id=None,
                    trusted_event=replayed_receipt,
                    reactivated_at=NOW + timedelta(minutes=4),
                )
            self.assertEqual(reopened.get(active.contract_id, 1).status, "suspended")
        finally:
            reopened.close()

    def test_reactivation_discovery_persists_expired_state(self) -> None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="cursor-local",
            session_id="session-1",
        )
        store = SQLiteContractStore(
            self.database,
            trusted_event_consumer=consumer,
        )
        try:
            active = create_authorized(
                store,
                make_contract(expires_at=NOW + timedelta(minutes=1)),
                session_id="session-1",
                authorization_source="trusted_user",
                created_at=NOW,
            )
            store.suspend(
                active.contract_id,
                expected_version=1,
                suspended_at=NOW + timedelta(seconds=30),
            )
            _, receipt = consume_event(
                consumer=consumer,
                purpose="task_reactivation",
                contract_id=active.contract_id,
                contract_version=1,
                decision="reactivate",
            )

            with self.assertRaisesRegex(InvalidContractTransition, "contract:expired"):
                store.reactivate(
                    active.contract_id,
                    expected_version=1,
                    expected_active_task_id=None,
                    trusted_event=receipt,
                    reactivated_at=NOW + timedelta(minutes=2),
                )

            self.assertEqual(store.get(active.contract_id, 1).status, "expired")
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
