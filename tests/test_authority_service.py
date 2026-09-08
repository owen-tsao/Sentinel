from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.audit import AuditEvent, AuditHealth, AuditQuery  # noqa: E402
from sentinel.authority import ContractAuthorityService  # noqa: E402
from sentinel.contracts import (  # noqa: E402
    ActionContract,
    InMemoryContractStore,
    InMemoryTrustedEventConsumer,
    TrustedPromptEnvelope,
)

NOW = datetime(2026, 8, 31, 20, 0, tzinfo=timezone.utc)


def contract() -> ActionContract:
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
        expires_at=NOW + timedelta(hours=1),
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


if __name__ == "__main__":
    unittest.main()
