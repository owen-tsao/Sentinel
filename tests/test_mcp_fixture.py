from __future__ import annotations

import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.mcp import FixtureError, OperationBinding, SQLiteIssueFixture  # noqa: E402


def binding(**overrides: object) -> OperationBinding:
    values: dict[str, object] = {
        "attempt_id": "attempt-1",
        "adapter_session_id": "adapter-1",
        "supervision_session_id": "session-1",
        "task_id": "task-1",
        "contract_version": 1,
        "authority_epoch": "epoch-1",
        "policy_sha256": "p" * 64,
        "tool": "sentinel_issue_add_note",
        "operation": "issue_add_note",
        "issue_id": "SPIKE-1",
        "note_body": "note A",
    }
    values.update(overrides)
    return OperationBinding(**values)  # type: ignore[arg-type]


class Crash(RuntimeError):
    pass


class IssueFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.database = Path(self.tmp.name) / "fixture.sqlite3"
        self.fixture = SQLiteIssueFixture(self.database)
        self.fixture.seed({"SPIKE-1": "Login 500", "SPIKE-2": "Export drops rows"})

    def tearDown(self) -> None:
        self.fixture.close()
        self.tmp.cleanup()

    def reopen(self) -> SQLiteIssueFixture:
        self.fixture.close()
        self.fixture = SQLiteIssueFixture(self.database)
        return self.fixture

    def test_full_lifecycle_adds_exactly_one_note_and_suppresses_duplicates(self) -> None:
        b = binding()
        self.assertEqual(self.fixture.prepare(b).state, "prepared")
        self.assertEqual(self.fixture.admit(b.attempt_id).state, "admitted")
        applied = self.fixture.apply(b)
        again = self.fixture.apply(b)
        self.assertEqual(applied.state, "succeeded")
        self.assertTrue(applied.result["note_added"])
        self.assertTrue(again.result["duplicate_suppressed"])
        self.assertFalse(again.result["note_added"])
        self.assertEqual(self.fixture.note_count(), 1)
        self.assertEqual(self.fixture.issue("SPIKE-1").notes, ("note A",))

    def test_read_operation_never_adds_a_note(self) -> None:
        b = binding(tool="sentinel_issue_read", operation="issue_read", note_body=None)
        self.fixture.prepare(b)
        self.fixture.admit(b.attempt_id)
        result = self.fixture.apply(b).result
        self.assertEqual(result["title"], "Login 500")
        self.assertFalse(result["note_added"])
        self.assertEqual(self.fixture.note_count(), 0)

    def test_changed_payload_on_a_known_attempt_is_rejected_everywhere(self) -> None:
        b = binding()
        self.fixture.prepare(b)
        tampered = replace(b, note_body="note A tampered")
        redirected = replace(b, issue_id="SPIKE-2")
        for changed in (tampered, redirected):
            with self.subTest(changed=changed):
                with self.assertRaises(FixtureError) as raised:
                    self.fixture.prepare(changed)
                self.assertEqual(raised.exception.reason_code, "fixture:attempt_binding_mismatch")
        self.fixture.admit(b.attempt_id)
        with self.assertRaises(FixtureError):
            self.fixture.apply(tampered)
        self.assertEqual(self.fixture.note_count(), 0)

    def test_crash_before_admission_leaves_a_prepared_record_and_no_effect(self) -> None:
        b = binding()
        self.fixture.prepare(b)
        fixture = self.reopen()
        self.assertEqual(fixture.get(b.attempt_id).state, "prepared")
        with self.assertRaises(FixtureError) as raised:
            fixture.apply(b)
        self.assertEqual(raised.exception.reason_code, "fixture:cannot_apply_from_prepared")
        self.assertEqual(fixture.note_count(), 0)

    def test_crash_after_admission_before_effect_becomes_unknown_and_is_never_retried(self) -> None:
        b = binding()
        self.fixture.prepare(b)
        self.fixture.admit(b.attempt_id)

        def crash() -> None:
            raise Crash()

        with self.assertRaises(Crash):
            self.fixture.apply(b, fault_between_applying_and_effect=crash)
        self.assertEqual(self.fixture.get(b.attempt_id).state, "applying")
        fixture = self.reopen()
        self.assertEqual(fixture.get(b.attempt_id).state, "unknown")
        outcome = fixture.apply(b)
        self.assertEqual(outcome.state, "unknown")
        self.assertEqual(fixture.note_count(), 0)

    def test_crash_inside_effect_rolls_back_note_and_state_together(self) -> None:
        b = binding()
        self.fixture.prepare(b)
        self.fixture.admit(b.attempt_id)

        def crash() -> None:
            raise Crash()

        with self.assertRaises(Crash):
            self.fixture.apply(b, fault_inside_effect=crash)
        self.assertEqual(self.fixture.note_count(), 0, "note must not survive a failed result write")
        self.assertEqual(self.fixture.get(b.attempt_id).state, "applying")
        self.assertEqual(self.reopen().get(b.attempt_id).state, "unknown")

    def test_crash_after_terminal_storage_before_response_is_idempotent(self) -> None:
        b = binding()
        self.fixture.prepare(b)
        self.fixture.admit(b.attempt_id)
        self.fixture.apply(b)
        fixture = self.reopen()
        replayed = fixture.apply(b)
        self.assertEqual(replayed.state, "succeeded")
        self.assertTrue(replayed.result["duplicate_suppressed"])
        self.assertEqual(fixture.note_count(), 1)

    def test_failed_effect_is_terminal_and_reported(self) -> None:
        b = binding(note_body="")
        self.fixture.prepare(b)
        self.fixture.admit(b.attempt_id)
        with self.assertRaises(FixtureError) as raised:
            self.fixture.apply(b)
        self.assertEqual(raised.exception.reason_code, "fixture:note_body_required")
        self.assertEqual(self.fixture.get(b.attempt_id).state, "failed")
        self.assertEqual(self.fixture.note_count(), 0)

    def test_unknown_issue_and_unknown_attempt_fail_closed(self) -> None:
        with self.assertRaises(FixtureError) as unknown_issue:
            self.fixture.prepare(binding(issue_id="SPIKE-404"))
        with self.assertRaises(FixtureError) as unknown_attempt:
            self.fixture.admit("nope")
        self.assertEqual(unknown_issue.exception.reason_code, "fixture:unknown_issue")
        self.assertEqual(unknown_attempt.exception.reason_code, "fixture:unknown_attempt")


if __name__ == "__main__":
    unittest.main()
