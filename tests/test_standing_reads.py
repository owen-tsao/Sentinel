"""Week 14: standing reads under the ceiling.

With `standing_read` declared by the startup ceiling, in-pattern fixture reads
run with no active task and are audited as such. Writes still need a task,
out-of-pattern reads are still blocked, and none of the task rules change.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_mcp_mediation_api import UI_ORIGIN, call, mediated_client, pair  # noqa: E402
from test_task_proposal_api import active_authority, confirm, pending, propose  # noqa: E402

from sentinel.supervision import week12_fixture_policy  # noqa: E402

HEADERS = {"Origin": UI_ORIGIN}
STANDING = week12_fixture_policy(standing_read=True)


def read(ctx, issue_id: str):
    return call(ctx, "sentinel_issue_read", {"issue_id": issue_id}).json()


class StandingReadTests(unittest.TestCase):
    def test_in_pattern_reads_pass_with_no_task_and_are_audited_as_standing(self) -> None:
        with mediated_client(activate=False, policy=STANDING) as ctx:
            pair(ctx["client"])
            reads = [read(ctx, "SPIKE-1"), read(ctx, "SPIKE-2")]
            authority = active_authority(ctx)
            admitted = ctx["audit"].query(event_type="execution_admitted")
            decisions = ctx["audit"].query(event_type="decision")
            status = ctx["client"].get("/control/status", headers=HEADERS).json()
        for body in reads:
            self.assertEqual((body["verdict"], body["reason_code"]), ("allow", "supervision:standing_read"), body)
            self.assertEqual(body["operation_state"], "succeeded")
            self.assertIn("title", body["result"])
        self.assertIsNone(authority, "a standing read must not create or imply a task")
        self.assertEqual(len(admitted), 2)
        for event in admitted:
            self.assertIn("supervision:standing_read", event.reason_codes)
            self.assertIsNone(event.task_id)
            self.assertIsNone(event.contract_id)
        self.assertTrue(all(event.task_id is None for event in decisions))
        self.assertTrue(status["integration"]["ceiling"]["standing_read"])

    def test_writes_and_out_of_pattern_reads_are_still_blocked(self) -> None:
        with mediated_client(activate=False, policy=STANDING) as ctx:
            write = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "no"}).json()
            prod = read(ctx, "PROD-1")
            unknown = read(ctx, "SPIKE-9")
            notes = ctx["fixture"].note_count()
        self.assertEqual(write["verdict"], "block")
        self.assertEqual(write["reason_code"], "contract:not_found")
        self.assertIn("sentinel_task_propose", write["guidance"])
        self.assertEqual(prod["verdict"], "block")
        self.assertEqual(prod["reason_code"], "supervision:issue_out_of_scope")
        self.assertEqual(unknown["verdict"], "block", "a read of an unseeded issue fails at the fixture, not silently")
        self.assertEqual(notes, 0)

    def test_standing_read_is_off_unless_the_ceiling_declares_it(self) -> None:
        with mediated_client(activate=False) as ctx:
            blocked = read(ctx, "SPIKE-1")
        self.assertEqual(blocked["verdict"], "block")
        self.assertEqual(blocked["reason_code"], "contract:not_found")

    def test_quarantined_authority_blocks_standing_reads_too(self) -> None:
        # A quarantined authority also reports "no active record"; that state
        # must stay fully fail-closed rather than look like an idle ceiling.
        with mediated_client(activate=False, policy=STANDING) as ctx:
            before = read(ctx, "SPIKE-1")
            ctx["app"].state.authority_service._authority_available = False
            during = read(ctx, "SPIKE-1")
        self.assertEqual(before["reason_code"], "supervision:standing_read")
        self.assertEqual(during["verdict"], "block")
        self.assertNotEqual(during["reason_code"], "supervision:standing_read")

    def test_pending_proposal_does_not_stop_standing_reads_but_still_gates_writes(self) -> None:
        with mediated_client(activate=False, policy=STANDING) as ctx:
            pair(ctx["client"])
            propose(ctx, issue_ids=["SPIKE-1"])
            still_reads = read(ctx, "SPIKE-1")
            write = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "no"}).json()
        self.assertEqual(still_reads["reason_code"], "supervision:standing_read")
        self.assertEqual(write["verdict"], "block")
        self.assertEqual(write["reason_code"], "task:awaiting_confirmation")

    def test_task_rules_are_unchanged_once_a_task_exists(self) -> None:
        with mediated_client(activate=False, policy=STANDING) as ctx:
            pair(ctx["client"])
            draft_id = propose(ctx, issue_ids=["SPIKE-1"]).json()["result"]["draft_id"]
            confirmed = confirm(ctx, draft_id, {"expected_active_task_id": None})
            inside = read(ctx, "SPIKE-1")
            outside = read(ctx, "SPIKE-2")
            stale = confirm(ctx, propose(ctx, issue_ids=["SPIKE-2"]).json()["result"]["draft_id"],
                            {"expected_active_task_id": None})
        self.assertEqual(confirmed.status_code, 200, confirmed.text)
        self.assertEqual(inside["reason_code"], "mcp:matching_read")
        self.assertEqual((outside["verdict"], outside["reason_code"]), ("block", "contract:target_mismatch"),
                         "an active task narrows reads to its scope; standing reads do not apply beside a task")
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.json()["detail"]["reason_code"], "proposal:stale_view")

    def test_standing_reads_never_count_toward_or_spend_a_budget(self) -> None:
        with mediated_client(activate=False, policy=STANDING) as ctx:
            pair(ctx["client"])
            for _ in range(3):
                read(ctx, "SPIKE-1")
            spent = ctx["fixture"].count_spent_writes(
                supervision_session_id=ctx["app"].state.supervision_binding.session_id,
                task_id="standing-read", operations={"issue_add_note"},
            )
            listed = pending(ctx).json()
        self.assertEqual(spent, 0)
        self.assertIsNone(listed["proposal"])


if __name__ == "__main__":
    unittest.main()
