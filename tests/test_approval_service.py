from __future__ import annotations

import sys
import unittest
from pathlib import Path

from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.approval import ApprovalBinding, InMemoryApprovalService  # noqa: E402


def binding(**overrides: object) -> ApprovalBinding:
    values: dict[str, object] = {
        "contract_id": "contract-1",
        "contract_version": 1,
        "authority_epoch": 1,
        "action_fingerprint": "fingerprint-1",
        "environment": "sandbox",
        "session_id": "session-1",
        "task_id": "task-1",
        "attempt_id": "attempt-1",
    }
    values.update(overrides)
    return ApprovalBinding(**values)  # type: ignore[arg-type]


class ApprovalServiceTests(unittest.TestCase):
    def test_approval_models_reject_unknown_fields(self) -> None:
        with self.assertRaises(ValidationError):
            binding(action_fingerprnt="typo")

    def test_token_is_exact_bound_and_one_use(self) -> None:
        service = InMemoryApprovalService(
            approval_id_factory=lambda: "approval-1",
            token_factory=lambda: "token-1",
        )
        pending = service.request(binding())
        issued = service.issue(
            pending.approval_id,
            approver_id="reviewer-1",
            approver_channel="isolated-test-harness",
        )
        assert issued is not None

        self.assertEqual(issued.approver_id, "reviewer-1")
        self.assertEqual(issued.approver_channel, "isolated-test-harness")
        self.assertFalse(
            service.consume(
                issued.token,
                binding(action_fingerprint="different"),
            )
        )
        self.assertFalse(
            service.consume(
                issued.token,
                binding(attempt_id="different"),
            )
        )
        self.assertTrue(service.has_token(issued.token))
        self.assertTrue(service.consume(issued.token, binding()))
        self.assertFalse(service.consume(issued.token, binding()))

    def test_unknown_pending_request_cannot_issue_token(self) -> None:
        service = InMemoryApprovalService()
        self.assertIsNone(
            service.issue(
                "missing",
                approver_id="reviewer-1",
                approver_channel="isolated-test-harness",
            )
        )

    def test_token_from_previous_authority_epoch_cannot_be_consumed(self) -> None:
        service = InMemoryApprovalService(
            approval_id_factory=lambda: "approval-1",
            token_factory=lambda: "token-1",
        )
        pending = service.request(binding(authority_epoch=1))
        issued = service.issue(
            pending.approval_id,
            approver_id="reviewer-1",
            approver_channel="isolated-test-harness",
        )
        assert issued is not None

        self.assertFalse(
            service.consume(
                issued.token,
                binding(authority_epoch=2),
            )
        )
        self.assertTrue(service.has_token(issued.token))

    def test_failed_approval_audit_does_not_issue_or_lose_pending_request(self) -> None:
        def fail_audit(_token: object) -> None:
            raise RuntimeError("audit unavailable")

        service = InMemoryApprovalService(
            approval_id_factory=lambda: "approval-1",
            token_factory=lambda: "token-1",
            issue_observer=fail_audit,
        )
        pending = service.request(binding())

        with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
            service.issue(
                pending.approval_id,
                approver_id="reviewer-1",
                approver_channel="isolated-test-harness",
            )

        service.set_issue_observer(lambda _token: None)
        issued = service.issue(
            pending.approval_id,
            approver_id="reviewer-1",
            approver_channel="isolated-test-harness",
        )
        self.assertIsNotNone(issued)

    def test_failed_consume_observer_does_not_spend_token(self) -> None:
        def fail_audit(_token: object) -> None:
            raise RuntimeError("audit unavailable")

        service = InMemoryApprovalService(
            approval_id_factory=lambda: "approval-1",
            token_factory=lambda: "token-1",
        )
        pending = service.request(binding())
        issued = service.issue(
            pending.approval_id,
            approver_id="reviewer-1",
            approver_channel="isolated-test-harness",
        )
        assert issued is not None

        with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
            service.consume(
                issued.token,
                binding(),
                consume_observer=fail_audit,
            )

        self.assertTrue(service.has_token(issued.token))

    def test_duplicate_pending_request_reuses_existing_entry(self) -> None:
        service = InMemoryApprovalService(
            approval_id_factory=lambda: "approval-1",
            capacity=1,
        )

        first = service.request(binding())
        second = service.request(binding())

        self.assertEqual(second.approval_id, first.approval_id)

    def test_new_authority_epoch_removes_stale_pending_capacity(self) -> None:
        ids = iter(("approval-1", "approval-2", "approval-3"))
        service = InMemoryApprovalService(
            approval_id_factory=lambda: next(ids),
            capacity=2,
        )

        service.request(binding(authority_epoch=1))
        service.request(binding(authority_epoch=2))
        current = service.request(binding(authority_epoch=3))

        self.assertEqual(current.approval_id, "approval-3")

    def test_pending_requests_can_be_listed_and_denied_without_issuing(self) -> None:
        service = InMemoryApprovalService(
            approval_id_factory=lambda: "approval-1",
        )
        pending = service.request(binding())

        self.assertEqual(service.get_pending("approval-1"), pending)
        self.assertEqual(service.list_pending(), [pending])
        denied = service.deny("approval-1")

        self.assertEqual(denied, pending)
        self.assertEqual(service.list_pending(), [])
        self.assertIsNone(
            service.issue(
                "approval-1",
                approver_id="reviewer-1",
                approver_channel="isolated-test-harness",
            )
        )

    def test_pending_request_can_be_invalidated_without_granting_authority(self) -> None:
        service = InMemoryApprovalService(
            approval_id_factory=lambda: "approval-1",
        )
        pending = service.request(binding())

        self.assertTrue(service.invalidate(pending.approval_id))
        self.assertFalse(service.invalidate(pending.approval_id))
        self.assertEqual(service.list_pending(), [])
        self.assertIsNone(
            service.issue(
                pending.approval_id,
                approver_id="reviewer-1",
                approver_channel="protected-local-ui",
            )
        )

    def test_failed_denial_audit_retains_pending_request(self) -> None:
        service = InMemoryApprovalService(
            approval_id_factory=lambda: "approval-1",
        )
        pending = service.request(binding())

        with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
            service.deny(
                pending.approval_id,
                denial_observer=lambda _: (_ for _ in ()).throw(
                    RuntimeError("audit unavailable")
                ),
            )

        self.assertEqual(service.get_pending(pending.approval_id), pending)

    def test_unconsumed_internal_token_can_be_discarded(self) -> None:
        service = InMemoryApprovalService(
            approval_id_factory=lambda: "approval-1",
            token_factory=lambda: "token-1",
        )
        pending = service.request(binding())
        token = service.issue(
            pending.approval_id,
            approver_id="reviewer-1",
            approver_channel="protected-local-ui",
        )
        assert token is not None

        self.assertTrue(service.discard_token(token.token))
        self.assertFalse(service.has_token(token.token))
        self.assertFalse(service.discard_token(token.token))


if __name__ == "__main__":
    unittest.main()
