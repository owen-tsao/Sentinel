from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.decision.confirmation import (  # noqa: E402
    ConfirmationRequest,
    InMemoryConfirmationStore,
    fingerprint_confirmation_request,
)


def confirmation_request(**overrides: object) -> ConfirmationRequest:
    values: dict[str, object] = {
        "context": "Clean generated build artifacts.",
        "command": "rm -rf ./dist",
        "environment": "sandbox",
        "shell_type": "bash",
        "recent_actions": [
            {
                "type": "command",
                "summary": "Listed project files.",
                "sensitive_resources": [],
                "metadata": {"cwd": "/workspace"},
            }
        ],
        "session_id": "session-1",
        "agent_id": "agent-1",
        "user_id": "user-1",
    }
    values.update(overrides)
    return ConfirmationRequest(**values)  # type: ignore[arg-type]


class ConfirmationTests(unittest.TestCase):
    def test_fingerprint_is_stable_for_equivalent_request_dict_order(self) -> None:
        request_a = confirmation_request(
            recent_actions=[
                {
                    "type": "command",
                    "summary": "Listed project files.",
                    "sensitive_resources": [],
                    "metadata": {"cwd": "/workspace", "tool": "shell"},
                }
            ]
        )
        request_b = confirmation_request(
            recent_actions=[
                {
                    "metadata": {"tool": "shell", "cwd": "/workspace"},
                    "sensitive_resources": [],
                    "summary": "Listed project files.",
                    "type": "command",
                }
            ]
        )

        self.assertEqual(fingerprint_confirmation_request(request_a), fingerprint_confirmation_request(request_b))

    def test_fingerprint_changes_when_recent_action_history_order_changes(self) -> None:
        request_a = confirmation_request(
            recent_actions=[
                {"type": "command", "summary": "Listed files.", "sensitive_resources": []},
                {"type": "command", "summary": "Read config.", "sensitive_resources": ["config"]},
            ]
        )
        request_b = confirmation_request(
            recent_actions=[
                {"type": "command", "summary": "Read config.", "sensitive_resources": ["config"]},
                {"type": "command", "summary": "Listed files.", "sensitive_resources": []},
            ]
        )

        self.assertNotEqual(fingerprint_confirmation_request(request_a), fingerprint_confirmation_request(request_b))

    def test_store_issues_one_use_token_for_exact_request(self) -> None:
        store = InMemoryConfirmationStore(
            confirmation_id_factory=lambda: "confirmation-1",
            token_factory=lambda: "token-1",
        )
        request = confirmation_request()

        pending = store.create_pending(request, "confirm_required")
        token = store.approve(pending.confirmation_id)

        self.assertIsNotNone(token)
        self.assertEqual(pending.confirmation_id, "confirmation-1")
        self.assertTrue(store.consume_token("token-1", request))
        self.assertFalse(store.consume_token("token-1", request))
        self.assertIsNone(store.get_pending("confirmation-1"))

    def test_token_mismatch_fails_without_consuming_original_token(self) -> None:
        store = InMemoryConfirmationStore(
            confirmation_id_factory=lambda: "confirmation-1",
            token_factory=lambda: "token-1",
        )
        request = confirmation_request()
        altered_request = confirmation_request(command="rm -rf ./build")

        pending = store.create_pending(request, "confirm_required")
        store.approve(pending.confirmation_id)

        self.assertFalse(store.consume_token("token-1", altered_request))
        self.assertTrue(store.consume_token("token-1", request))

    def test_unknown_confirmation_id_does_not_issue_token(self) -> None:
        store = InMemoryConfirmationStore()

        self.assertIsNone(store.approve("missing-confirmation"))

    def test_pending_confirmation_can_only_be_approved_once(self) -> None:
        store = InMemoryConfirmationStore(
            confirmation_id_factory=lambda: "confirmation-1",
            token_factory=lambda: "token-1",
        )
        pending = store.create_pending(confirmation_request(), "confirm_required")

        first_token = store.approve(pending.confirmation_id)
        second_token = store.approve(pending.confirmation_id)

        self.assertIsNotNone(first_token)
        self.assertIsNone(second_token)
        self.assertIsNone(store.get_pending(pending.confirmation_id))

    def test_store_rejects_non_confirmable_block_verdict(self) -> None:
        store = InMemoryConfirmationStore()

        with self.assertRaisesRegex(ValueError, "not confirmable"):
            store.create_pending(confirmation_request(), "block")

    def test_concurrent_consume_spends_token_exactly_once(self) -> None:
        """A one-use token must never be double-spent by racing threads."""
        import threading

        store = InMemoryConfirmationStore(
            confirmation_id_factory=lambda: "confirmation-1",
            token_factory=lambda: "token-1",
        )
        request = confirmation_request()
        pending = store.create_pending(request, "confirm_required")
        store.approve(pending.confirmation_id)

        results: list[bool] = []
        barrier = threading.Barrier(8)

        def consume() -> None:
            barrier.wait()
            results.append(store.consume_token("token-1", request))

        threads = [threading.Thread(target=consume) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 7)

    def test_pending_and_token_ttls_use_injected_clock(self) -> None:
        now = datetime(2026, 8, 31, tzinfo=timezone.utc)

        def clock() -> datetime:
            return now

        store = InMemoryConfirmationStore(
            confirmation_id_factory=lambda: "confirmation-1",
            token_factory=lambda: "token-1",
            clock=clock,
            pending_ttl=timedelta(seconds=10),
            token_ttl=timedelta(seconds=5),
        )
        pending = store.create_pending(confirmation_request(), "confirm_required")

        now += timedelta(seconds=10)
        self.assertIsNone(store.get_pending(pending.confirmation_id))
        self.assertIsNone(store.approve(pending.confirmation_id))

        now += timedelta(seconds=1)
        pending = store.create_pending(confirmation_request(), "confirm_required")
        self.assertIsNotNone(store.approve(pending.confirmation_id))
        now += timedelta(seconds=5)
        self.assertFalse(store.consume_token("token-1", confirmation_request()))

    def test_store_evicts_oldest_items_at_capacity(self) -> None:
        confirmation_ids = iter(("confirmation-1", "confirmation-2", "confirmation-3"))
        tokens = iter(("token-1", "token-2"))
        store = InMemoryConfirmationStore(
            confirmation_id_factory=lambda: next(confirmation_ids),
            token_factory=lambda: next(tokens),
            max_pending_confirmations=2,
            max_tokens=1,
        )

        first = store.create_pending(confirmation_request(command="rm -rf ./one"), "confirm_required")
        second = store.create_pending(confirmation_request(command="rm -rf ./two"), "confirm_required")
        store.create_pending(confirmation_request(command="rm -rf ./three"), "confirm_required")

        self.assertIsNone(store.get_pending(first.confirmation_id))
        first_token = store.approve(second.confirmation_id)
        self.assertIsNotNone(first_token)
        third_token = store.approve("confirmation-3")
        self.assertIsNotNone(third_token)
        self.assertFalse(store.consume_token("token-1", confirmation_request(command="rm -rf ./two")))
        self.assertTrue(store.consume_token("token-2", confirmation_request(command="rm -rf ./three")))


if __name__ == "__main__":
    unittest.main()
