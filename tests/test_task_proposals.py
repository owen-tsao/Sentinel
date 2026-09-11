from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.audit import SQLiteAuditStore  # noqa: E402
from sentinel.audit.models import AuditQuery  # noqa: E402
from sentinel.control import InMemoryWorkspaceBindingStore, review_workspace  # noqa: E402
from sentinel.proposals import (  # noqa: E402
    InMemoryTaskProposalStore,
    ProposalFacts,
    ProposalStateError,
    ProposalValidationError,
    TaskProposalService,
    facts_from_arguments,
)
from sentinel.supervision import InMemorySupervisionPolicyStore, week12_fixture_policy  # noqa: E402


class Clock:
    def __init__(self) -> None:
        # Anchor to real time: the ceiling binding is stamped with the real clock
        # and a fixed date would make its remaining lifetime meaningless.
        self.now = datetime.now(timezone.utc).replace(microsecond=0)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: int) -> None:
        self.now += timedelta(**kwargs)


class TaskProposalServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        repository = root / "repo"
        repository.mkdir()
        (repository / ".git").mkdir()
        self.supervision = InMemoryWorkspaceBindingStore().bind(review_workspace(repository))
        self.policy_binding = InMemorySupervisionPolicyStore().bind(week12_fixture_policy(), self.supervision)
        self.audit = SQLiteAuditStore(root / "audit.sqlite3")
        self.clock = Clock()
        self.store = InMemoryTaskProposalStore(history_limit=3)
        self.service = TaskProposalService(
            store=self.store, policy_binding=self.policy_binding, supervision=self.supervision,
            audit_store=self.audit, environment="sandbox", clock=self.clock,
        )

    def tearDown(self) -> None:
        self.audit.close()
        self.tmp.cleanup()

    def propose(self, operation: str = "write", targets: list[str] | None = None, minutes: int = 30):
        facts = ProposalFacts(operation=operation, exact_targets=tuple(targets or ["SPIKE-1"]),  # type: ignore[arg-type]
                              task_duration_minutes=minutes)
        return self.service.propose(facts, request_id="req", adapter_session_id="adapter-1")

    def events(self, event_type: str | None = None):
        return self.audit.query(AuditQuery(event_type=event_type, limit=100))

    def test_proposal_is_stored_with_structured_facts_and_no_prose(self) -> None:
        proposal, superseded = self.propose(targets=["SPIKE-2", "SPIKE-1"])
        self.assertIsNone(superseded)
        self.assertEqual(proposal.state, "pending")
        self.assertEqual(proposal.exact_targets, ("SPIKE-2", "SPIKE-1"))
        self.assertEqual(proposal.allowed_effects, ("read", "write"))
        self.assertEqual(proposal.objective, "Add notes to fixture issues SPIKE-2, SPIKE-1 through the Sentinel MCP tools.")
        self.assertEqual(proposal.proposal_expires_at, self.clock.now + timedelta(minutes=15))
        self.assertEqual(self.service.pending(), proposal)
        proposed = self.events("task_proposed")
        self.assertEqual(len(proposed), 1)
        self.assertEqual(proposed[0].verdict, "confirm_required")
        self.assertEqual(proposed[0].details["draft_id"], proposal.draft_id)
        self.assertNotIn("objective", proposed[0].details)
        self.assertNotIn("raw", " ".join(proposed[0].details))

    def test_content_hash_is_stable_across_equivalent_proposals_and_bound_to_ceiling(self) -> None:
        first = ProposalFacts("write", ("SPIKE-1", "SPIKE-2"), 30)
        second = ProposalFacts("write", ("SPIKE-2", "SPIKE-1"), 30)
        third = ProposalFacts("write", ("SPIKE-1", "SPIKE-2"), 31)
        sha = self.policy_binding.content_sha256
        self.assertEqual(first.content_sha256(environment="sandbox", policy_sha256=sha),
                         second.content_sha256(environment="sandbox", policy_sha256=sha))
        self.assertNotEqual(first.content_sha256(environment="sandbox", policy_sha256=sha),
                            third.content_sha256(environment="sandbox", policy_sha256=sha))
        self.assertNotEqual(first.content_sha256(environment="sandbox", policy_sha256=sha),
                            first.content_sha256(environment="sandbox", policy_sha256="0" * 64))

    def test_single_pending_invariant_supersedes_and_audits_the_older_draft(self) -> None:
        first, _ = self.propose(targets=["SPIKE-1"])
        second, superseded = self.propose(targets=["SPIKE-2"])
        self.assertIsNotNone(superseded)
        assert superseded is not None
        self.assertEqual(superseded.draft_id, first.draft_id)
        self.assertEqual(superseded.state, "superseded")
        self.assertEqual(superseded.resolution, "newer_proposal")
        self.assertEqual(superseded.superseded_by, second.draft_id)
        self.assertEqual(second.proposal_number, 2)
        self.assertEqual(self.service.pending(), second)
        stale = self.service.get(first.draft_id)
        assert stale is not None
        self.assertEqual(stale.state, "superseded")
        with self.assertRaises(ProposalStateError) as raised:
            self.service.require_confirmable(first.draft_id)
        self.assertEqual(raised.exception.reason_code, "proposal:superseded")
        self.assertEqual(len(self.events("task_proposal_superseded")), 1)
        self.assertEqual([item.draft_id for item in self.service.history()], [first.draft_id])

    def test_expiry_retires_the_draft_and_blocks_confirmation(self) -> None:
        proposal, _ = self.propose()
        self.clock.advance(minutes=15)
        self.assertIsNone(self.service.pending())
        expired = self.service.get(proposal.draft_id)
        assert expired is not None
        self.assertEqual(expired.state, "expired")
        with self.assertRaises(ProposalStateError) as raised:
            self.service.require_confirmable(proposal.draft_id)
        self.assertEqual(raised.exception.reason_code, "proposal:expired")
        self.assertEqual(len(self.events("task_proposal_expired")), 1)

    def test_ceiling_rejections_name_the_field(self) -> None:
        cases = [
            (ProposalFacts("write", ("PROD-1",), 30), "supervision:issue_out_of_scope", "issue_ids"),
            (ProposalFacts("write", ("SPIKE-1",), 0), "proposal:duration_invalid", "minutes"),
            (ProposalFacts("write", ("SPIKE-1",), 9 * 60), "proposal:duration_exceeds_ceiling", "minutes"),
            (ProposalFacts("write", tuple(f"SPIKE-{n}" for n in range(1, 22)), 30), "proposal:too_many_targets", "issue_ids"),
            (ProposalFacts("delete", ("SPIKE-1",), 30), "supervision:operation_forbidden", "operation"),  # type: ignore[arg-type]
        ]
        for facts, code, field in cases:
            with self.subTest(code=code):
                with self.assertRaises(ProposalValidationError) as raised:
                    self.service.propose(facts, request_id="req", adapter_session_id=None)
                self.assertEqual(raised.exception.reason_code, code)
                self.assertEqual(raised.exception.field, field)
                self.assertTrue(raised.exception.guidance)
        self.assertIsNone(self.service.pending())
        self.assertEqual(self.events("task_proposed"), [])

    def test_confirm_and_dismiss_are_terminal_and_audited(self) -> None:
        proposal, _ = self.propose()
        confirmed = self.service.confirm(proposal.draft_id, contract_id="c-1", task_id="t-1", request_id="req")
        self.assertEqual(confirmed.state, "confirmed")
        self.assertEqual(confirmed.confirmed_contract_id, "c-1")
        self.assertIsNone(self.service.pending())
        with self.assertRaises(ProposalStateError) as raised:
            self.service.confirm(proposal.draft_id, contract_id="c-2", task_id="t-2", request_id="req")
        self.assertEqual(raised.exception.reason_code, "proposal:confirmed")
        confirmed_events = self.events("task_proposal_confirmed")
        self.assertEqual(len(confirmed_events), 1)
        self.assertEqual(confirmed_events[0].contract_id, "c-1")
        self.assertEqual(confirmed_events[0].task_id, "t-1")

        second, _ = self.propose(targets=["SPIKE-2"])
        dismissed = self.service.dismiss(second.draft_id, resolution="human_dismissed", request_id="req")
        self.assertEqual(dismissed.state, "dismissed")
        third, _ = self.propose(targets=["SPIKE-3"])
        adjusted = self.service.dismiss(third.draft_id, resolution="adjusted_in_full_form", request_id="req")
        self.assertEqual(adjusted.state, "superseded")
        self.assertEqual(adjusted.resolution, "adjusted_in_full_form")
        self.assertEqual(len(self.events("task_proposal_dismissed")), 2)

    def test_history_is_bounded(self) -> None:
        ids = []
        for n in range(1, 6):
            proposal, _ = self.propose(targets=[f"SPIKE-{n}"])
            ids.append(proposal.draft_id)
        history = self.service.history()
        self.assertEqual(len(history), 3)
        self.assertEqual([item.draft_id for item in history], [ids[3], ids[2], ids[1]])
        self.assertIsNone(self.service.get(ids[0]))
        self.assertIsNotNone(self.service.get(ids[4]))

    def test_facts_from_arguments_rejects_bad_shapes_and_dedupes(self) -> None:
        facts = facts_from_arguments("read", ["SPIKE-1", "SPIKE-1", "SPIKE-2"], 20)
        self.assertEqual(facts.exact_targets, ("SPIKE-1", "SPIKE-2"))
        for operation, ids, minutes, code in [
            ("delete", ["SPIKE-1"], 20, "proposal:operation_invalid"),
            ("read", [], 20, "proposal:targets_required"),
            ("read", "SPIKE-1", 20, "proposal:targets_required"),
            ("read", ["SPIKE 1"], 20, "proposal:target_invalid"),
            ("read", [1], 20, "proposal:target_invalid"),
            ("read", ["SPIKE-1"], "20", "proposal:duration_invalid"),
            ("read", ["SPIKE-1"], True, "proposal:duration_invalid"),
        ]:
            with self.subTest(code=code):
                with self.assertRaises(ProposalValidationError) as raised:
                    facts_from_arguments(operation, ids, minutes)
                self.assertEqual(raised.exception.reason_code, code)


if __name__ == "__main__":
    unittest.main()
