"""Week 14, revised: in-scope writes run; the write limit is a runaway bound.

Under a matching active task, a note in the ceiling's middle tier runs with no
card and no count shown to anyone. The task's write limit comes from the
ceiling alone, is never chosen by the agent or offered to the person, and when
a looping agent reaches it the write is *blocked* with a clear next step, not
turned into a stream of approval cards. Everything that already passed the
exact scope check is unchanged; nothing here can widen a block.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_mcp_mediation_api import (  # noqa: E402
    UI_ORIGIN,
    call,
    fixture_contract,
    mediated_client,
    pair,
)
from test_task_proposal_api import active_authority, confirm, pending, propose  # noqa: E402

from sentinel.contracts import ActionContract  # noqa: E402
from sentinel.mcp.mediation import WriteBudgetState, decide_mcp_action  # noqa: E402
from sentinel.proposals import ProposalFacts  # noqa: E402
from sentinel.supervision import CeilingDecision, week12_fixture_policy  # noqa: E402

HEADERS = {"Origin": UI_ORIGIN}
RUNAWAY_LIMIT = week12_fixture_policy().max_write_budget


def limited_contract(limit: int, *, targets: list[str] | None = None) -> ActionContract:
    base = fixture_contract(targets=targets)
    payload = base.model_dump(mode="python", warnings=False)
    payload["write_budget"] = limit
    return ActionContract(**payload)


def note(ctx: dict[str, Any], issue_id: str, body: str, attempt_id: str):
    return call(ctx, "sentinel_issue_add_note", {"issue_id": issue_id, "body": body},
                attempt_id=f"attempt-w14-{attempt_id}").json()


def manual_draft(**overrides: Any) -> dict[str, Any]:
    accepted: dict[str, Any] = {
        "operation": "write",
        "exact_targets": ["SPIKE-1"],
        "environment": "sandbox",
        "expected_side_effects": ["notes"],
        "allowed_effects": ["read", "write"],
        "forbidden_operations": ["delete"],
        "forbidden_effects": ["none"],
        "forbidden_effect_codes": ["delete"],
        "rollback_plan": "disposable",
        "dry_run_required": False,
        "expires_in_minutes": 30,
        "tool_family": "sentinel_issue_fixture",
    }
    accepted.update(overrides)
    return {"raw_prompt": "manual", "accepted_contract": accepted}


class InScopeWritesRunTests(unittest.TestCase):
    def test_every_in_scope_note_runs_with_no_card_and_no_count_in_guidance(self) -> None:
        with mediated_client(contract=limited_contract(RUNAWAY_LIMIT)) as ctx:
            pair(ctx["client"])
            results = [note(ctx, f"SPIKE-{1 + (n % 2)}", f"note {n}", str(n)) for n in range(8)]
            approvals = ctx["client"].get("/control/approvals", headers=HEADERS).json()["approvals"]
            notes = ctx["fixture"].note_count()
            admitted = ctx["audit"].query(event_type="execution_admitted")
        for body in results:
            self.assertEqual((body["verdict"], body["reason_code"]), ("allow", "mcp:budgeted_write"), body)
            self.assertNotRegex(body["guidance"], r"\d", "no count is ever surfaced to the agent")
        self.assertEqual(approvals, [], "an in-scope note never produces a card")
        self.assertEqual(notes, 8)
        self.assertEqual(len([e for e in admitted if "mcp:budgeted_write" in e.reason_codes]), 8)

    def test_runaway_limit_blocks_with_a_next_step_instead_of_a_card(self) -> None:
        with mediated_client(contract=limited_contract(2)) as ctx:
            pair(ctx["client"])
            first = note(ctx, "SPIKE-1", "one", "1")
            second = note(ctx, "SPIKE-2", "two", "2")
            third = note(ctx, "SPIKE-1", "three", "3")
            fourth = note(ctx, "SPIKE-1", "four", "4")
            approvals = ctx["client"].get("/control/approvals", headers=HEADERS).json()["approvals"]
            notes = ctx["fixture"].note_count()
        self.assertEqual(first["reason_code"], "mcp:budgeted_write")
        self.assertEqual(second["reason_code"], "mcp:budgeted_write")
        for body in (third, fourth):
            self.assertEqual(body["verdict"], "block")
            self.assertEqual(body["reason_code"], "supervision:write_budget_exhausted")
            self.assertIn("sentinel_task_propose", body["guidance"])
        self.assertEqual(approvals, [], "a looping agent must never become a stream of cards")
        self.assertEqual(notes, 2)

    def test_zero_limit_means_every_note_asks_exactly_as_week_13(self) -> None:
        with mediated_client(contract=limited_contract(0)) as ctx:
            pair(ctx["client"])
            write = note(ctx, "SPIKE-1", "one", "1")
            approved = ctx["client"].post(
                f"/control/approvals/{write['approval_id']}/approve", headers=HEADERS, json={}
            ).json()
            notes = ctx["fixture"].note_count()
        self.assertEqual(write["verdict"], "confirm_required")
        self.assertEqual(write["reason_code"], "supervision:confirm_operation")
        self.assertEqual(approved["retry"]["verdict"], "allow")
        self.assertEqual(notes, 1)

    def test_out_of_scope_write_is_blocked_and_spends_nothing(self) -> None:
        with mediated_client(contract=limited_contract(1, targets=["SPIKE-1"])) as ctx:
            outside = note(ctx, "SPIKE-2", "nope", "out")
            prod = note(ctx, "PROD-1", "nope", "prod")
            inside = note(ctx, "SPIKE-1", "yes", "in")
            notes = ctx["fixture"].note_count()
        self.assertEqual(outside["verdict"], "block")
        self.assertTrue(outside["reason_code"].startswith("contract:"))
        self.assertEqual(prod["verdict"], "block")
        self.assertEqual(prod["reason_code"], "supervision:issue_out_of_scope")
        self.assertEqual((inside["verdict"], inside["reason_code"]), ("allow", "mcp:budgeted_write"),
                         "blocked attempts must not have consumed the one remaining write")
        self.assertEqual(notes, 1)

    def test_retry_of_an_applied_write_never_double_spends_even_at_the_limit(self) -> None:
        with mediated_client(contract=limited_contract(1)) as ctx:
            first = note(ctx, "SPIKE-1", "one", "same")
            # The limit is now reached *by* this write. A retry of it must report
            # the truthful outcome (already applied), not a fresh block.
            replays = [note(ctx, "SPIKE-1", "one", "same") for _ in range(3)]
            other = note(ctx, "SPIKE-1", "two", "other")
            reused = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-2", "body": "one"},
                          attempt_id="attempt-w14-same").json()
            notes = ctx["fixture"].note_count()
        self.assertEqual(first["reason_code"], "mcp:budgeted_write")
        for body in replays:
            self.assertEqual((body["verdict"], body["reason_code"]), ("allow", "mcp:already_applied"))
            self.assertTrue(body["result"]["duplicate_suppressed"])
        self.assertEqual(other["reason_code"], "supervision:write_budget_exhausted")
        self.assertEqual(reused["verdict"], "block", "same attempt ID with a changed action is still rejected")
        self.assertEqual(notes, 1)

    def test_replacement_task_starts_with_its_own_count(self) -> None:
        with mediated_client(contract=limited_contract(1, targets=["SPIKE-1"])) as ctx:
            pair(ctx["client"])
            original = ctx["record"]
            used = note(ctx, "SPIKE-1", "one", "1")
            limited = note(ctx, "SPIKE-1", "two", "2")
            draft_id = propose(ctx, issue_ids=["SPIKE-1", "SPIKE-2"]).json()["result"]["draft_id"]
            confirmed = confirm(ctx, draft_id, {"expected_active_task_id": original.task_id}).json()
            fresh = [note(ctx, "SPIKE-2", f"n{n}", f"f{n}") for n in range(3)]
            notes = ctx["fixture"].note_count()
        self.assertEqual(used["reason_code"], "mcp:budgeted_write")
        self.assertEqual(limited["verdict"], "block")
        self.assertEqual(confirmed["active_contract"]["contract"]["write_budget"], RUNAWAY_LIMIT)
        for body in fresh:
            self.assertEqual(body["reason_code"], "mcp:budgeted_write")
        self.assertEqual(notes, 4)


class WriteLimitAuthorityTests(unittest.TestCase):
    def test_proposals_carry_the_ceiling_limit_and_reads_carry_none(self) -> None:
        with mediated_client(activate=False) as ctx:
            pair(ctx["client"])
            propose(ctx, issue_ids=["SPIKE-1"])
            one_issue = pending(ctx).json()["proposal"]
            propose(ctx, issue_ids=[f"SPIKE-{n}" for n in range(1, 9)])
            eight_issues = pending(ctx).json()["proposal"]
            propose(ctx, operation="read", issue_ids=["SPIKE-1", "SPIKE-2"])
            read_only = pending(ctx).json()["proposal"]
        self.assertEqual(one_issue["write_budget"], RUNAWAY_LIMIT, "not one-per-issue; the limit is the ceiling's")
        self.assertEqual(eight_issues["write_budget"], RUNAWAY_LIMIT)
        self.assertEqual(read_only["write_budget"], 0)

    def test_manual_form_cannot_raise_the_limit_and_does_not_choose_it(self) -> None:
        with mediated_client(activate=False) as ctx:
            pair(ctx["client"])
            client = ctx["client"]
            over = client.post("/control/contracts/draft", headers=HEADERS,
                               json=manual_draft(write_budget=RUNAWAY_LIMIT + 1))
            read_with_budget = client.post(
                "/control/contracts/draft", headers=HEADERS,
                json=manual_draft(operation="read", allowed_effects=["read"], write_budget=1),
            )
            plain = client.post("/control/contracts/draft", headers=HEADERS, json=manual_draft())
            lower = client.post("/control/contracts/draft", headers=HEADERS, json=manual_draft(write_budget=3))
            authority = active_authority(ctx)
        self.assertEqual(over.status_code, 422, over.text)
        self.assertIn(f"caps write budgets at {RUNAWAY_LIMIT}", over.json()["detail"])
        self.assertEqual(read_with_budget.status_code, 422, read_with_budget.text)
        self.assertEqual(plain.status_code, 200, plain.text)
        self.assertEqual(plain.json()["proposed_contract"]["contract"]["write_budget"], RUNAWAY_LIMIT,
                         "the form sends no count; the server stamps the ceiling's limit")
        self.assertEqual(lower.json()["proposed_contract"]["contract"]["write_budget"], RUNAWAY_LIMIT,
                         "a lower request is not a knob either; the limit is not a per-task choice")
        self.assertIsNone(authority, "drafting never activates")

    def test_confirm_tier_operation_can_never_run_without_a_card(self) -> None:
        confirming = week12_fixture_policy(
            confirm_operations=frozenset({"issue_add_note"}),
            budgetable_operations=frozenset(),
            max_write_budget=0,
        )
        with mediated_client(activate=False, policy=confirming) as ctx:
            pair(ctx["client"])
            manual = ctx["client"].post("/control/contracts/draft", headers=HEADERS,
                                        json=manual_draft(write_budget=1))
            propose(ctx, issue_ids=["SPIKE-1", "SPIKE-2"])
            card = pending(ctx).json()["proposal"]
            service = ctx["app"].state.task_proposals
            with self.assertRaises(Exception) as raised:
                service.validate(ProposalFacts("write", ("SPIKE-1",), 30, write_budget=1))
        self.assertEqual(manual.status_code, 422, manual.text)
        self.assertIn("does not allow a write budget", manual.json()["detail"])
        self.assertEqual(card["write_budget"], 0, "a confirm-only ceiling grants no card-free writes")
        self.assertEqual(getattr(raised.exception, "reason_code", None), "proposal:budget_not_allowed")

    def test_agent_and_confirmation_body_cannot_carry_a_limit(self) -> None:
        with mediated_client(activate=False) as ctx:
            pair(ctx["client"])
            draft_id = propose(ctx).json()["result"]["draft_id"]
            smuggled = confirm(ctx, draft_id, {"expected_active_task_id": None, "write_budget": 500})
            tool_arg = call(ctx, "sentinel_task_propose",
                            {"operation": "write", "issue_ids": ["SPIKE-1"], "minutes": 30, "write_budget": 500}).json()
            authority = active_authority(ctx)
        self.assertEqual(smuggled.status_code, 422, smuggled.text)
        self.assertEqual(tool_arg["verdict"], "block")
        self.assertEqual(tool_arg["reason_code"], "mcp:unknown_argument")
        self.assertIsNone(authority)

    def test_hash_and_json_carry_the_limit(self) -> None:
        one = ProposalFacts("write", ("SPIKE-1",), 30, write_budget=1)
        two = ProposalFacts("write", ("SPIKE-1",), 30, write_budget=2)
        sha = "0" * 64
        self.assertNotEqual(one.content_sha256(environment="sandbox", policy_sha256=sha),
                            two.content_sha256(environment="sandbox", policy_sha256=sha))
        self.assertEqual(fixture_contract().write_budget, 0)
        self.assertEqual(limited_contract(3).model_dump(mode="json", warnings=False)["write_budget"], 3)
        with self.assertRaises(Exception):
            limited_contract(-1)


class DecisionCompositionTests(unittest.TestCase):
    """The pure decision never lets the limit widen a block or a mismatch."""

    def _ceiling(self, verdict: str) -> CeilingDecision:
        return CeilingDecision(verdict, f"supervision:{verdict}", verdict)  # type: ignore[arg-type]

    def test_limit_is_ignored_without_a_matching_contract(self) -> None:
        budget = WriteBudgetState(granted=5, spent=0)
        no_task = decide_mcp_action(self._ceiling("budgetable"), None, budget=budget)
        self.assertEqual((no_task.verdict, no_task.reason_code), ("block", "contract:not_found"))

        class Mismatch:
            matches = False
            reason_codes = ["contract:target_mismatch"]

        mismatch = decide_mcp_action(self._ceiling("budgetable"), Mismatch(), budget=budget)  # type: ignore[arg-type]
        self.assertEqual(mismatch.verdict, "block")
        forbidden = decide_mcp_action(self._ceiling("forbidden"), None, budget=budget, standing_read=True)
        self.assertEqual(forbidden.verdict, "block")

    def test_tiers(self) -> None:
        class Match:
            matches = True
            reason_codes: list[str] = []

        match = Match()
        cases = [
            (None, "confirm_required", "supervision:confirm_operation"),
            (WriteBudgetState(0, 0), "confirm_required", "supervision:confirm_operation"),
            (WriteBudgetState(2, 0), "allow", "mcp:budgeted_write"),
            (WriteBudgetState(2, 1), "allow", "mcp:budgeted_write"),
            (WriteBudgetState(2, 2), "block", "supervision:write_budget_exhausted"),
            (WriteBudgetState(2, 7), "block", "supervision:write_budget_exhausted"),
        ]
        for budget, verdict, code in cases:
            with self.subTest(budget=budget):
                decision = decide_mcp_action(self._ceiling("budgetable"), match, budget=budget)  # type: ignore[arg-type]
                self.assertEqual((decision.verdict, decision.reason_code), (verdict, code))
        confirm = decide_mcp_action(self._ceiling("confirm_required"), match, budget=WriteBudgetState(5, 0))  # type: ignore[arg-type]
        self.assertEqual(confirm.verdict, "confirm_required")


if __name__ == "__main__":
    unittest.main()
