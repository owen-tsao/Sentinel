from __future__ import annotations

import sys
import unittest
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


if __name__ == "__main__":
    unittest.main()
