from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.audit import AuditEvent, AuditHealth, AuditQuery  # noqa: E402
from sentinel.authority import ContractAuthorityService  # noqa: E402
from sentinel.contracts import (  # noqa: E402
    ActionContract,
    AuthorityQuarantine,
    InMemoryContractStore,
    InMemoryTrustedEventConsumer,
    SQLiteContractStore,
    TrustedPromptEnvelope,
)

NOW = datetime(2026, 8, 31, 20, 0, tzinfo=timezone.utc)


def contract(*, expires_at: datetime | None = None) -> ActionContract:
    return ActionContract(
        objective="Write one reviewed output.",
        allowed_operations={"write"},
        allowed_tools={"shell"},
        exact_targets=["/workspace/output.txt"],
        environment="sandbox",
        maximum_scope="exact",
        expected_side_effects=["Write the reviewed output."],
        allowed_effects={"write"},
        forbidden_operations={"network", "credential_access"},
        forbidden_effects=["No network or credential access."],
        forbidden_effect_codes={"network", "credential_access"},
        rollback_plan="Delete the output.",
        dry_run_required=False,
        authorization_reference="proposal",
        version=1,
        expires_at=expires_at or NOW + timedelta(hours=1),
    )


class RecordingAuditStore:
    def __init__(self, *, fail: bool = False, fail_after: int | None = None) -> None:
        self.events: list[AuditEvent] = []
        self.fail = fail
        self.fail_after = fail_after

    def health(self) -> AuditHealth:
        return AuditHealth(status="healthy")

    def write(self, event: AuditEvent) -> None:
        if self.fail or (
            self.fail_after is not None and len(self.events) >= self.fail_after
        ):
            raise RuntimeError("audit unavailable")
        self.events.append(event)

    def write_required(self, event: AuditEvent) -> None:
        self.write(event)

    def query(self, query: AuditQuery) -> list[AuditEvent]:
        del query
        return list(self.events)

    def export_jsonl(self, destination: Path, query: AuditQuery | None = None) -> int:
        del destination, query
        return 0


class ContractAuthorityServiceTests(unittest.TestCase):
    def test_observer_failure_does_not_misreport_committed_transition(self) -> None:
        contracts = InMemoryContractStore()
        audit = RecordingAuditStore()
        service = ContractAuthorityService(contracts, audit)

        def fail_observer(record):
            del record
            raise RuntimeError("observer unavailable")

        service.set_authority_change_observer(fail_observer)
        proposed = service.create_proposed(
            contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
            contract_id="contract-1",
        )

        self.assertEqual(proposed.status, "proposed")
        self.assertEqual(
            audit.events[-1].event_type,
            "authority_change_observer_failed",
        )

    def test_active_amendment_claims_receipt_through_service(self) -> None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="test-host",
            session_id="session-1",
            channel="protected_local_ui",
        )
        contracts = InMemoryContractStore(trusted_event_consumer=consumer)
        audit = RecordingAuditStore()
        service = ContractAuthorityService(contracts, audit)
        proposed = service.create_proposed(
            contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
            contract_id="contract-1",
        )
        activation = consumer.consume(
            TrustedPromptEnvelope(
                event_id="event-activation",
                nonce="nonce-activation-123456",
                host_id="test-host",
                session_id="session-1",
                channel="protected_local_ui",
                prompt="Activate this reviewed task.",
                purpose="task_transition",
                contract_id=proposed.contract_id,
                contract_version=1,
                decision="approve",
                issued_at=NOW,
                expires_at=NOW + timedelta(minutes=5),
                authenticated=True,
            ),
            now=NOW,
        )
        service.activate_proposed(
            proposed.contract_id,
            expected_version=1,
            expected_active_task_id=None,
            trusted_event=activation,
            activated_at=NOW,
        )
        amendment = consumer.consume(
            TrustedPromptEnvelope(
                event_id="event-amendment",
                nonce="nonce-amendment-1234567",
                host_id="test-host",
                session_id="session-1",
                channel="protected_local_ui",
                prompt="Narrow the reviewed task.",
                purpose="amendment_decision",
                contract_id=proposed.contract_id,
                contract_version=2,
                decision="approve",
                issued_at=NOW,
                expires_at=NOW + timedelta(minutes=5),
                authenticated=True,
            ),
            now=NOW,
        )

        base_contract = contract()
        amended_contract = ActionContract(
            **{
                **(
                    base_contract.model_dump()
                    if hasattr(base_contract, "model_dump")
                    else base_contract.dict()
                ),
                "backup_required": True,
            }
        )
        amended = service.amend(
            proposed.contract_id,
            amended_contract,
            expected_version=1,
            authorization_source="trusted_host",
            created_at=NOW + timedelta(minutes=1),
            sensitive=False,
            trusted_event=amendment,
        )

        self.assertEqual(amended.status, "active")
        self.assertEqual(amended.authority_event_id, "event-amendment")
        self.assertEqual(audit.events[-1].contract_version, 2)
        self.assertEqual(
            audit.events[-1].details["trusted_event"]["event_id"],
            "event-amendment",
        )

    def test_activation_and_revocation_have_ordered_lifecycle_evidence(self) -> None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="test-host",
            session_id="session-1",
            channel="protected_local_ui",
        )
        contracts = InMemoryContractStore(trusted_event_consumer=consumer)
        audit = RecordingAuditStore()
        service = ContractAuthorityService(contracts, audit)
        proposed = service.create_proposed(
            contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
            contract_id="contract-1",
        )
        receipt = consumer.consume(
            TrustedPromptEnvelope(
                event_id="event-1",
                nonce="nonce-1234567890abcdef",
                host_id="test-host",
                session_id="session-1",
                channel="protected_local_ui",
                prompt="Activate this reviewed task.",
                purpose="task_transition",
                contract_id=proposed.contract_id,
                contract_version=1,
                decision="approve",
                issued_at=NOW,
                expires_at=NOW + timedelta(minutes=5),
                authenticated=True,
            ),
            now=NOW,
        )
        active = service.activate_proposed(
            proposed.contract_id,
            expected_version=1,
            expected_active_task_id=None,
            trusted_event=receipt,
            activated_at=NOW,
        )
        revoked = service.revoke(
            active.contract_id,
            expected_version=active.version,
            revoked_at=NOW + timedelta(minutes=1),
        )

        self.assertEqual(revoked.status, "revoked")
        self.assertEqual(
            [event.event_type for event in audit.events],
            [
                "authority_transition_prepared",
                "authority_transition_completed",
                "authority_transition_prepared",
                "authority_transition_completed",
                "authority_transition_prepared",
                "authority_transition_completed",
            ],
        )
        self.assertEqual(audit.events[-1].details["status"], "revoked")
        self.assertEqual(audit.events[-1].details["authority_epoch"], 2)

    def test_failed_pre_transition_audit_prevents_mutation(self) -> None:
        contracts = InMemoryContractStore()
        service = ContractAuthorityService(
            contracts,
            RecordingAuditStore(fail=True),
        )

        with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
            service.create_proposed(
                contract(),
                session_id="session-1",
                authorization_source="trusted_user",
                created_at=NOW,
                contract_id="contract-1",
            )

        self.assertIsNone(contracts.get("contract-1"))

    def test_failed_completion_audit_suspends_new_active_authority(self) -> None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="test-host",
            session_id="session-1",
            channel="protected_local_ui",
        )
        contracts = InMemoryContractStore(trusted_event_consumer=consumer)
        audit = RecordingAuditStore()
        service = ContractAuthorityService(contracts, audit)
        proposed = service.create_proposed(
            contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
            contract_id="contract-1",
        )
        receipt = consumer.consume(
            TrustedPromptEnvelope(
                event_id="event-1",
                nonce="nonce-1234567890abcdef",
                host_id="test-host",
                session_id="session-1",
                channel="protected_local_ui",
                prompt="Activate reviewed task.",
                purpose="task_transition",
                contract_id=proposed.contract_id,
                contract_version=1,
                decision="approve",
                issued_at=NOW,
                expires_at=NOW + timedelta(minutes=5),
                authenticated=True,
            ),
            now=NOW,
        )
        audit.fail_after = len(audit.events) + 1

        with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
            service.activate_proposed(
                proposed.contract_id,
                expected_version=1,
                expected_active_task_id=None,
                trusted_event=receipt,
                activated_at=NOW,
            )

        self.assertIsNone(contracts.get_active("session-1", now=NOW))
        self.assertEqual(contracts.get("contract-1", 1).status, "suspended")
        self.assertFalse(service.authority_available)
        self.assertEqual(
            audit.events[-1].details["completion_failure_compensation"],
            "suspend_new_active_authority",
        )

    def test_failed_completion_and_compensation_close_authority_gate(self) -> None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="test-host",
            session_id="session-1",
            channel="protected_local_ui",
        )
        contracts = InMemoryContractStore(trusted_event_consumer=consumer)
        audit = RecordingAuditStore()
        service = ContractAuthorityService(contracts, audit)
        proposed = service.create_proposed(
            contract(),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
            contract_id="contract-1",
        )
        receipt = consumer.consume(
            TrustedPromptEnvelope(
                event_id="event-1",
                nonce="nonce-1234567890abcdef",
                host_id="test-host",
                session_id="session-1",
                channel="protected_local_ui",
                prompt="Activate reviewed task.",
                purpose="task_transition",
                contract_id=proposed.contract_id,
                contract_version=1,
                decision="approve",
                issued_at=NOW,
                expires_at=NOW + timedelta(minutes=5),
                authenticated=True,
            ),
            now=NOW,
        )
        audit.fail_after = len(audit.events) + 1
        original_suspend = contracts.suspend

        def fail_suspend(*args, **kwargs):
            del args, kwargs
            raise RuntimeError("contract store unavailable")

        contracts.suspend = fail_suspend  # type: ignore[method-assign]
        try:
            with self.assertRaisesRegex(
                RuntimeError,
                "execution remains disabled",
            ):
                service.activate_proposed(
                    proposed.contract_id,
                    expected_version=1,
                    expected_active_task_id=None,
                    trusted_event=receipt,
                    activated_at=NOW,
                )
        finally:
            contracts.suspend = original_suspend  # type: ignore[method-assign]

        self.assertFalse(service.authority_available)
        self.assertIsNotNone(contracts.get_active("session-1", now=NOW))
        with self.assertRaisesRegex(
            RuntimeError,
            "authority is unavailable pending recovery",
        ):
            service.create_proposed(
                contract(),
                session_id="session-1",
                authorization_source="trusted_user",
                created_at=NOW,
                contract_id="contract-2",
            )

    def test_unverified_active_authority_is_suspended_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite3"
            consumer = InMemoryTrustedEventConsumer(
                host_id="test-host",
                session_id="session-1",
                channel="protected_local_ui",
            )
            contracts = SQLiteContractStore(
                database,
                trusted_event_consumer=consumer,
            )
            audit = RecordingAuditStore()
            service = ContractAuthorityService(contracts, audit)
            proposed = service.create_proposed(
                contract(expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc)),
                session_id="session-1",
                authorization_source="trusted_user",
                created_at=NOW,
                contract_id="contract-1",
            )
            receipt = consumer.consume(
                TrustedPromptEnvelope(
                    event_id="event-1",
                    nonce="nonce-1234567890abcdef",
                    host_id="test-host",
                    session_id="session-1",
                    channel="protected_local_ui",
                    prompt="Activate reviewed task.",
                    purpose="task_transition",
                    contract_id=proposed.contract_id,
                    contract_version=1,
                    decision="approve",
                    issued_at=NOW,
                    expires_at=NOW + timedelta(minutes=5),
                    authenticated=True,
                ),
                now=NOW,
            )
            audit.fail_after = len(audit.events) + 1
            original_suspend = contracts.suspend

            def fail_suspend(*args, **kwargs):
                del args, kwargs
                raise RuntimeError("contract store unavailable")

            contracts.suspend = fail_suspend  # type: ignore[method-assign]
            try:
                with self.assertRaisesRegex(
                    RuntimeError,
                    "execution remains disabled",
                ):
                    service.activate_proposed(
                        proposed.contract_id,
                        expected_version=1,
                        expected_active_task_id=None,
                        trusted_event=receipt,
                        activated_at=NOW,
                    )
            finally:
                contracts.suspend = original_suspend  # type: ignore[method-assign]
                contracts.close()

            blocked_store = SQLiteContractStore(database)
            blocked = ContractAuthorityService(
                blocked_store,
                RecordingAuditStore(fail=True),
            )
            try:
                self.assertFalse(blocked.authority_available)
                recovered = blocked_store.get("contract-1", 1)
                assert recovered is not None
                self.assertEqual(recovered.status, "suspended")
            finally:
                blocked_store.close()

            reopened = SQLiteContractStore(database)
            recovery_audit = RecordingAuditStore()
            restarted = ContractAuthorityService(reopened, recovery_audit)
            try:
                self.assertTrue(restarted.authority_available)
                self.assertIsNone(reopened.get_active("session-1", now=NOW))
                self.assertEqual(
                    recovery_audit.events[-1].event_type,
                    "authority_quarantine_reconciled",
                )
            finally:
                reopened.close()

    def test_expired_quarantined_authority_stays_expired_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite3"
            consumer = InMemoryTrustedEventConsumer(
                host_id="test-host",
                session_id="session-1",
                channel="protected_local_ui",
            )
            contracts = SQLiteContractStore(
                database,
                trusted_event_consumer=consumer,
            )
            service = ContractAuthorityService(
                contracts,
                RecordingAuditStore(),
            )
            proposed = service.create_proposed(
                contract(),
                session_id="session-1",
                authorization_source="trusted_user",
                created_at=NOW,
                contract_id="contract-1",
            )
            receipt = consumer.consume(
                TrustedPromptEnvelope(
                    event_id="event-expiring",
                    nonce="nonce-expiring-123456",
                    host_id="test-host",
                    session_id="session-1",
                    channel="protected_local_ui",
                    prompt="Activate reviewed task.",
                    purpose="task_transition",
                    contract_id=proposed.contract_id,
                    contract_version=1,
                    decision="approve",
                    issued_at=NOW,
                    expires_at=NOW + timedelta(minutes=5),
                    authenticated=True,
                ),
                now=NOW,
            )
            active = service.activate_proposed(
                proposed.contract_id,
                expected_version=1,
                expected_active_task_id=None,
                trusted_event=receipt,
                activated_at=NOW,
            )
            quarantine = AuthorityQuarantine(
                quarantine_id="quarantine-expired",
                reason="authority_transition_completion_unverified",
                transition="active",
                session_id=active.session_id,
                task_id=active.task_id,
                contract_id=active.contract_id,
                contract_version=active.version,
                previous_contract_id=None,
                previous_contract_version=None,
                previous_authority_epoch=None,
                created_at=NOW,
            )
            with contracts.authority_quarantine_guard(quarantine):
                pass
            contracts.close()

            reopened = SQLiteContractStore(database)
            recovery_audit = RecordingAuditStore()
            restarted = ContractAuthorityService(reopened, recovery_audit)
            try:
                self.assertTrue(restarted.authority_available)
                recovered = reopened.get(active.contract_id, active.version)
                assert recovered is not None
                self.assertEqual(recovered.status, "expired")
                self.assertEqual(
                    recovery_audit.events[-1].details["target_status"],
                    "expired",
                )
            finally:
                reopened.close()

    def test_expiry_side_effect_is_audited_when_reactivation_fails(self) -> None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="test-host",
            session_id="session-1",
            channel="protected_local_ui",
        )
        contracts = InMemoryContractStore(trusted_event_consumer=consumer)
        audit = RecordingAuditStore()
        service = ContractAuthorityService(contracts, audit)
        proposed = service.create_proposed(
            contract(expires_at=NOW + timedelta(minutes=1)),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
            contract_id="contract-1",
        )
        activation = consumer.consume(
            TrustedPromptEnvelope(
                event_id="event-activation",
                nonce="nonce-activation-expiry",
                host_id="test-host",
                session_id="session-1",
                channel="protected_local_ui",
                prompt="Activate reviewed task.",
                purpose="task_transition",
                contract_id=proposed.contract_id,
                contract_version=1,
                decision="approve",
                issued_at=NOW,
                expires_at=NOW + timedelta(minutes=5),
                authenticated=True,
            ),
            now=NOW,
        )
        active = service.activate_proposed(
            proposed.contract_id,
            expected_version=1,
            expected_active_task_id=None,
            trusted_event=activation,
            activated_at=NOW,
        )
        service.suspend(
            active.contract_id,
            expected_version=active.version,
            suspended_at=NOW + timedelta(seconds=30),
        )
        reactivation_time = NOW + timedelta(minutes=2)
        reactivation = consumer.consume(
            TrustedPromptEnvelope(
                event_id="event-reactivation",
                nonce="nonce-reactivation-expiry",
                host_id="test-host",
                session_id="session-1",
                channel="protected_local_ui",
                prompt="Reactivate reviewed task.",
                purpose="task_transition",
                contract_id=active.contract_id,
                contract_version=active.version,
                decision="reactivate",
                issued_at=reactivation_time,
                expires_at=reactivation_time + timedelta(minutes=5),
                authenticated=True,
            ),
            now=reactivation_time,
        )

        with self.assertRaisesRegex(
            ValueError,
            "contract:expired",
        ):
            service.reactivate(
                active.contract_id,
                expected_version=active.version,
                expected_active_task_id=None,
                trusted_event=reactivation,
                reactivated_at=reactivation_time,
            )

        expired = contracts.get(active.contract_id, active.version)
        assert expired is not None
        self.assertEqual(expired.status, "expired")
        self.assertTrue(service.authority_available)
        self.assertEqual(
            audit.events[-1].details["transition"],
            "expired_during_reactivated",
        )

    def test_task_switch_audits_displaced_contract_suspension(self) -> None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="test-host",
            session_id="session-1",
            channel="protected_local_ui",
        )
        contracts = InMemoryContractStore(trusted_event_consumer=consumer)
        audit = RecordingAuditStore()
        service = ContractAuthorityService(contracts, audit)

        def create_and_activate(
            contract_id: str,
            event_id: str,
            nonce: str,
            expected_active_task_id: str | None,
        ):
            proposed = service.create_proposed(
                contract(),
                session_id="session-1",
                authorization_source="trusted_user",
                created_at=NOW,
                contract_id=contract_id,
            )
            receipt = consumer.consume(
                TrustedPromptEnvelope(
                    event_id=event_id,
                    nonce=nonce,
                    host_id="test-host",
                    session_id="session-1",
                    channel="protected_local_ui",
                    prompt="Activate reviewed task.",
                    purpose="task_transition",
                    contract_id=contract_id,
                    contract_version=1,
                    decision="approve",
                    issued_at=NOW,
                    expires_at=NOW + timedelta(minutes=5),
                    authenticated=True,
                ),
                now=NOW,
            )
            return service.activate_proposed(
                proposed.contract_id,
                expected_version=1,
                expected_active_task_id=expected_active_task_id,
                trusted_event=receipt,
                activated_at=NOW,
            )

        first = create_and_activate(
            "contract-1",
            "event-1",
            "nonce-1234567890abcdef",
            None,
        )
        create_and_activate(
            "contract-2",
            "event-2",
            "nonce-abcdef1234567890",
            first.task_id,
        )

        displaced_events = [
            event
            for event in audit.events
            if event.details.get("transition") == "suspended_for_task_switch"
        ]
        self.assertEqual(len(displaced_events), 1)
        self.assertEqual(displaced_events[0].contract_id, first.contract_id)
        self.assertEqual(displaced_events[0].details["status"], "suspended")

    def test_task_switch_audits_expired_displaced_authority(self) -> None:
        consumer = InMemoryTrustedEventConsumer(
            host_id="test-host",
            session_id="session-1",
            channel="protected_local_ui",
        )
        contracts = InMemoryContractStore(trusted_event_consumer=consumer)
        audit = RecordingAuditStore()
        service = ContractAuthorityService(contracts, audit)
        first = service.create_proposed(
            contract(expires_at=NOW + timedelta(minutes=1)),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW,
            contract_id="contract-1",
        )
        first_receipt = consumer.consume(
            TrustedPromptEnvelope(
                event_id="event-first",
                nonce="nonce-first-expiring",
                host_id="test-host",
                session_id="session-1",
                channel="protected_local_ui",
                prompt="Activate first task.",
                purpose="task_transition",
                contract_id=first.contract_id,
                contract_version=1,
                decision="approve",
                issued_at=NOW,
                expires_at=NOW + timedelta(minutes=5),
                authenticated=True,
            ),
            now=NOW,
        )
        active = service.activate_proposed(
            first.contract_id,
            expected_version=1,
            expected_active_task_id=None,
            trusted_event=first_receipt,
            activated_at=NOW,
        )
        second = service.create_proposed(
            contract(expires_at=NOW + timedelta(hours=2)),
            session_id="session-1",
            authorization_source="trusted_user",
            created_at=NOW + timedelta(seconds=30),
            contract_id="contract-2",
        )
        switch_time = NOW + timedelta(minutes=2)
        second_receipt = consumer.consume(
            TrustedPromptEnvelope(
                event_id="event-second",
                nonce="nonce-second-expiring",
                host_id="test-host",
                session_id="session-1",
                channel="protected_local_ui",
                prompt="Activate second task.",
                purpose="task_transition",
                contract_id=second.contract_id,
                contract_version=1,
                decision="approve",
                issued_at=switch_time,
                expires_at=switch_time + timedelta(minutes=5),
                authenticated=True,
            ),
            now=switch_time,
        )

        replacement = service.activate_proposed(
            second.contract_id,
            expected_version=1,
            expected_active_task_id=active.task_id,
            trusted_event=second_receipt,
            activated_at=switch_time,
        )

        expired = contracts.get(active.contract_id, active.version)
        assert expired is not None
        self.assertEqual(expired.status, "expired")
        self.assertEqual(replacement.status, "active")
        expiry_events = [
            event
            for event in audit.events
            if event.details.get("transition") == "expired_before_task_switch"
        ]
        self.assertEqual(len(expiry_events), 1)
        self.assertEqual(expiry_events[0].contract_id, active.contract_id)


if __name__ == "__main__":
    unittest.main()
