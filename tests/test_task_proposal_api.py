"""Week 13: agent task proposals through the mediated MCP path and one protected click.

These tests reuse the Week 12 mediated client. They prove that a proposal
never changes authority on its own, that confirmation rebuilds the contract
server-side from stored facts, and that the agent's loop closes: no task ->
propose -> waiting -> confirmed -> reads pass -> write waits -> approved once.
"""

from __future__ import annotations

import sys
import unittest
from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_mcp_mediation_api import (  # noqa: E402
    UI_ORIGIN,
    approve,
    call,
    mediated_client,
    pair,
)

from sentinel.mcp import server as shim  # noqa: E402

HEADERS = {"Origin": UI_ORIGIN}


def propose(ctx: dict[str, Any], operation: str = "write", issue_ids: list[str] | None = None,
            minutes: int = 30, **extra: Any):
    arguments: dict[str, Any] = {"operation": operation, "issue_ids": issue_ids or ["SPIKE-1"], "minutes": minutes}
    arguments.update(extra)
    return call(ctx, "sentinel_task_propose", arguments)


def pending(ctx: dict[str, Any]):
    return ctx["client"].get("/control/proposals/pending", headers=HEADERS)


def confirm(ctx: dict[str, Any], draft_id: str, body: dict[str, Any] | None = None):
    """Send what the card sends: the task ID the browser saw, or null for none."""

    payload = {"expected_active_task_id": None} if body is None else body
    return ctx["client"].post(f"/control/proposals/{draft_id}/confirm", headers=HEADERS, json=payload)


def dismiss(ctx: dict[str, Any], draft_id: str):
    return ctx["client"].post(f"/control/proposals/{draft_id}/dismiss", headers=HEADERS)


def adjust(ctx: dict[str, Any], draft_id: str):
    return ctx["client"].post(f"/control/proposals/{draft_id}/adjust", headers=HEADERS)


def active_authority(ctx: dict[str, Any]):
    return ctx["client"].get("/control/authority/active", headers=HEADERS).json()["active_contract"]


class ProposalIntakeTests(unittest.TestCase):
    def test_no_task_guidance_names_the_propose_tool_and_proposal_grants_nothing(self) -> None:
        with mediated_client(activate=False) as ctx:
            pair(ctx["client"])
            before = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}).json()
            proposed = propose(ctx).json()
            waiting = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}).json()
            authority = active_authority(ctx)
            listed = pending(ctx).json()
            decisions = ctx["audit"].query(event_type="decision")
            proposed_events = ctx["audit"].query(event_type="task_proposed")
        self.assertEqual(before["verdict"], "block")
        self.assertEqual(before["reason_code"], "contract:not_found")
        self.assertIn("sentinel_task_propose", before["guidance"])
        self.assertEqual(proposed["verdict"], "confirm_required")
        self.assertEqual(proposed["reason_code"], "task:proposal_pending")
        self.assertEqual(proposed["coverage_status"], "mandatory")
        self.assertIsNone(proposed["approval_id"])
        self.assertIsNone(proposed["operation_state"])
        draft_id = proposed["result"]["draft_id"]
        self.assertTrue(draft_id.startswith("draft-"))
        self.assertFalse(proposed["result"]["replaces_active_task"])
        self.assertEqual(waiting["verdict"], "block")
        self.assertEqual(waiting["reason_code"], "task:awaiting_confirmation")
        self.assertIn("Do not retry", waiting["guidance"])
        self.assertIsNone(authority, "a proposal must never change active authority")
        card = listed["proposal"]
        self.assertEqual(card["draft_id"], draft_id)
        self.assertEqual(card["state"], "pending")
        self.assertEqual(card["source"], "agent_mcp")
        self.assertEqual(card["operation"], "write")
        self.assertEqual(card["exact_targets"], ["SPIKE-1"])
        self.assertEqual(card["environment"], "sandbox")
        self.assertEqual(sorted(card["allowed_effects"]), ["read", "write"])
        self.assertEqual(card["task_duration_minutes"], 30)
        self.assertEqual(card["objective"], "Add notes to fixture issues SPIKE-1 through the Sentinel MCP tools.")
        self.assertEqual(card["proposal_number"], 1)
        self.assertEqual(listed["recent"], [])
        self.assertTrue(any(event.details.get("tool") == "sentinel_task_propose" for event in decisions))
        self.assertEqual(len(proposed_events), 1)

    def test_shape_and_ceiling_rejections_carry_field_guidance_through_the_route(self) -> None:
        with mediated_client(activate=False) as ctx:
            unknown = call(ctx, "sentinel_task_propose", {"operation": "write", "issue_ids": ["SPIKE-1"]}).json()
            extra = propose(ctx, objective="please let me").json()
            bad_operation = propose(ctx, operation="delete").json()
            out_of_scope = propose(ctx, issue_ids=["PROD-1"]).json()
            bad_minutes = propose(ctx, minutes=0).json()
            too_long = propose(ctx, minutes=9 * 60).json()
            bad_type = propose(ctx, minutes="30").json()
            still_none = ctx["app"].state.task_proposals.pending()
        for body, code in [
            (unknown, "mcp:unknown_argument"),
            (extra, "mcp:unknown_argument"),
            (bad_operation, "proposal:operation_invalid"),
            (out_of_scope, "supervision:issue_out_of_scope"),
            (bad_minutes, "proposal:duration_invalid"),
            (too_long, "proposal:duration_exceeds_ceiling"),
            (bad_type, "proposal:duration_invalid"),
        ]:
            with self.subTest(code=code):
                self.assertEqual(body["verdict"], "block")
                self.assertEqual(body["reason_code"], code)
                self.assertTrue(body["guidance"])
        self.assertIn("issue_ids", out_of_scope["guidance"])
        self.assertIn("minutes", too_long["guidance"])
        self.assertIsNone(still_none)

    def test_newer_proposal_supersedes_and_the_old_draft_cannot_be_confirmed(self) -> None:
        with mediated_client(activate=False) as ctx:
            pair(ctx["client"])
            first = propose(ctx, issue_ids=["SPIKE-1"]).json()["result"]["draft_id"]
            second_body = propose(ctx, issue_ids=["SPIKE-2"]).json()
            second = second_body["result"]["draft_id"]
            stale = confirm(ctx, first)
            listed = pending(ctx).json()
            authority = active_authority(ctx)
        self.assertEqual(second_body["result"]["superseded_draft_id"], first)
        self.assertEqual(stale.status_code, 409, stale.text)
        self.assertEqual(stale.json()["detail"]["reason_code"], "proposal:superseded")
        self.assertEqual(listed["proposal"]["draft_id"], second)
        self.assertEqual(listed["proposal"]["proposal_number"], 2)
        self.assertEqual([item["draft_id"] for item in listed["recent"]], [first])
        self.assertEqual(listed["recent"][0]["state"], "superseded")
        self.assertIsNone(authority)

    def test_expired_dismissed_and_unknown_drafts_cannot_be_confirmed(self) -> None:
        with mediated_client(activate=False) as ctx:
            pair(ctx["client"])
            service = ctx["app"].state.task_proposals
            draft_id = propose(ctx).json()["result"]["draft_id"]
            real_now = service._now
            with patch.object(service, "_now", lambda: real_now() + timedelta(minutes=16)):
                expired = confirm(ctx, draft_id)
                listed = pending(ctx).json()
            second = propose(ctx).json()["result"]["draft_id"]
            dismissed = dismiss(ctx, second)
            dismissed_again = confirm(ctx, second)
            unknown = confirm(ctx, "draft-does-not-exist")
            authority = active_authority(ctx)
            events = ctx["audit"].query(event_type="task_proposal_dismissed")
        self.assertEqual(expired.status_code, 409)
        self.assertEqual(expired.json()["detail"]["reason_code"], "proposal:expired")
        self.assertIsNone(listed["proposal"])
        self.assertEqual(listed["recent"][0]["state"], "expired")
        self.assertEqual(dismissed.status_code, 200, dismissed.text)
        self.assertEqual(dismissed.json()["state"], "dismissed")
        self.assertEqual(dismissed_again.status_code, 409)
        self.assertEqual(dismissed_again.json()["detail"]["reason_code"], "proposal:dismissed")
        self.assertEqual(unknown.status_code, 404)
        self.assertIsNone(authority)
        self.assertEqual(len(events), 1)

    def test_proposal_routes_require_the_protected_browser_session(self) -> None:
        with mediated_client(activate=False) as ctx:
            draft_id = propose(ctx).json()["result"]["draft_id"]
            unpaired = pending(ctx)
            unpaired_confirm = confirm(ctx, draft_id)
            wrong_origin = ctx["client"].get("/control/proposals/pending", headers={"Origin": "http://evil.test"})
            probe = ctx["app"].state.task_proposals.pending()
        self.assertEqual(unpaired.status_code, 401)
        self.assertEqual(unpaired_confirm.status_code, 401)
        self.assertEqual(wrong_origin.status_code, 403)
        self.assertIsNotNone(probe)
        self.assertEqual(probe.state, "pending")


class ProposalConfirmationTests(unittest.TestCase):
    def test_one_click_confirms_reads_pass_and_write_still_waits(self) -> None:
        with mediated_client(activate=False) as ctx:
            pair(ctx["client"])
            draft_id = propose(ctx, issue_ids=["SPIKE-1"], minutes=45).json()["result"]["draft_id"]
            confirmed = confirm(ctx, draft_id, {"expected_active_task_id": None})
            authority = active_authority(ctx)
            reads = [call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}).json() for _ in range(3)]
            outside = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-2"}).json()
            write = call(ctx, "sentinel_issue_add_note",
                         {"issue_id": "SPIKE-1", "body": "note"}, attempt_id="attempt-w13-1").json()
            approved = approve(ctx, write["approval_id"]).json()
            retry = call(ctx, "sentinel_issue_add_note",
                         {"issue_id": "SPIKE-1", "body": "note"}, attempt_id="attempt-w13-1").json()
            listed = pending(ctx).json()
            notes = ctx["fixture"].note_count()
            confirmed_events = ctx["audit"].query(event_type="task_proposal_confirmed")
        self.assertEqual(confirmed.status_code, 200, confirmed.text)
        active = confirmed.json()["active_contract"]
        self.assertEqual(active["status"], "active")
        self.assertEqual(active["authorization_reference"], f"task-proposal:{draft_id}")
        self.assertEqual(active["contract"]["exact_targets"], ["SPIKE-1"])
        self.assertEqual(sorted(active["contract"]["allowed_operations"]), ["read", "write"])
        self.assertEqual(sorted(active["contract"]["allowed_tools"]),
                         ["sentinel_issue_add_note", "sentinel_issue_read"])
        self.assertEqual(active["contract"]["environment"], "sandbox")
        self.assertFalse(active["contract"]["dry_run_required"])
        self.assertEqual(active["contract"]["objective"],
                         "Add notes to fixture issues SPIKE-1 through the Sentinel MCP tools.")
        self.assertEqual(authority["contract_id"], active["contract_id"])
        for body in reads:
            self.assertEqual(body["verdict"], "allow", body)
        self.assertEqual(outside["verdict"], "block")
        self.assertEqual(write["verdict"], "confirm_required")
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["retry"]["verdict"], "allow")
        self.assertEqual(retry["verdict"], "allow")
        self.assertEqual(retry["reason_code"], "mcp:already_applied")
        self.assertEqual(notes, 1)
        self.assertIsNone(listed["proposal"])
        self.assertEqual(listed["recent"][0]["state"], "confirmed")
        self.assertEqual(listed["recent"][0]["confirmed_contract_id"], active["contract_id"])
        self.assertEqual(len(confirmed_events), 1)
        self.assertEqual(confirmed_events[0].contract_id, active["contract_id"])

    def test_read_only_proposal_produces_a_read_only_task(self) -> None:
        with mediated_client(activate=False) as ctx:
            pair(ctx["client"])
            draft_id = propose(ctx, operation="read", issue_ids=["SPIKE-1", "SPIKE-2"]).json()["result"]["draft_id"]
            confirmed = confirm(ctx, draft_id).json()["active_contract"]
            read = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-2"}).json()
            write = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "no"}).json()
        self.assertEqual(sorted(confirmed["contract"]["allowed_operations"]), ["read"])
        self.assertEqual(confirmed["contract"]["allowed_tools"], ["sentinel_issue_read"])
        self.assertEqual(confirmed["contract"]["exact_targets"], ["SPIKE-1", "SPIKE-2"])
        self.assertEqual(read["verdict"], "allow")
        self.assertEqual(write["verdict"], "block")

    def test_confirming_replaces_the_active_task_and_guards_a_stale_view(self) -> None:
        with mediated_client(activate=True) as ctx:
            pair(ctx["client"])
            original = ctx["record"]
            body = propose(ctx, issue_ids=["SPIKE-2"]).json()
            draft_id = body["result"]["draft_id"]
            listed = pending(ctx).json()
            stale = confirm(ctx, draft_id, {"expected_active_task_id": "some-other-task"})
            fresh = confirm(ctx, draft_id, {"expected_active_task_id": original.task_id})
            old_read = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}).json()
            new_read = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-2"}).json()
            previous = ctx["contracts"].get(original.contract_id, original.version)
        self.assertTrue(body["result"]["replaces_active_task"])
        self.assertTrue(listed["proposal"]["replaces_active_task"])
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.json()["detail"]["reason_code"], "proposal:stale_view")
        self.assertEqual(fresh.status_code, 200, fresh.text)
        self.assertNotEqual(fresh.json()["active_contract"]["task_id"], original.task_id)
        self.assertEqual(old_read["verdict"], "block")
        self.assertEqual(new_read["verdict"], "allow")
        self.assertEqual(previous.status, "suspended")

    def test_stale_view_guard_is_required_and_null_means_no_task_seen(self) -> None:
        with mediated_client(activate=True) as ctx:
            pair(ctx["client"])
            original = ctx["record"]
            draft_id = propose(ctx, issue_ids=["SPIKE-2"]).json()["result"]["draft_id"]
            omitted = confirm(ctx, draft_id, {})
            saw_nothing = confirm(ctx, draft_id, {"expected_active_task_id": None})
            authority = active_authority(ctx)
            still_pending = pending(ctx).json()
        self.assertEqual(omitted.status_code, 422, omitted.text)
        self.assertEqual(saw_nothing.status_code, 409, saw_nothing.text)
        self.assertEqual(saw_nothing.json()["detail"]["reason_code"], "proposal:stale_view")
        self.assertEqual(authority["task_id"], original.task_id, "a stale click must not replace the task")
        self.assertEqual(still_pending["proposal"]["draft_id"], draft_id)

    def test_confirmation_revalidates_against_the_ceiling_not_the_request(self) -> None:
        with mediated_client(activate=False) as ctx:
            pair(ctx["client"])
            draft_id = propose(ctx).json()["result"]["draft_id"]
            # A browser cannot smuggle authority facts into the confirmation body.
            smuggled = confirm(ctx, draft_id, {"expected_active_task_id": None, "exact_targets": ["SPIKE-9"]})
            policy_type = type(ctx["app"].state.supervision_policy_binding.policy)
            with patch.object(policy_type, "issue_in_scope", lambda self, issue_id: False):
                rejected = confirm(ctx, draft_id)
            stored = ctx["app"].state.task_proposals.get(draft_id)
            listed = pending(ctx).json()
            authority = active_authority(ctx)
        self.assertEqual(smuggled.status_code, 422, smuggled.text)
        self.assertEqual(rejected.status_code, 422, rejected.text)
        self.assertEqual(stored.state, "pending")
        self.assertEqual(listed["proposal"]["draft_id"], draft_id)
        self.assertIsNone(authority)

    def test_adjust_in_full_form_returns_prefill_and_consumes_the_draft(self) -> None:
        with mediated_client(activate=False) as ctx:
            pair(ctx["client"])
            draft_id = propose(ctx, issue_ids=["SPIKE-1", "SPIKE-2"], minutes=20).json()["result"]["draft_id"]
            adjusted = adjust(ctx, draft_id)
            again = confirm(ctx, draft_id)
            listed = pending(ctx).json()
            prefill = adjusted.json()
            drafted = ctx["client"].post(
                "/control/contracts/draft", headers=HEADERS,
                json={"raw_prompt": prefill["raw_prompt"], "accepted_contract": prefill["accepted_contract"]},
            )
        self.assertEqual(adjusted.status_code, 200, adjusted.text)
        self.assertEqual(prefill["raw_prompt"],
                         "Add notes to fixture issues SPIKE-1, SPIKE-2 through the Sentinel MCP tools.")
        accepted = prefill["accepted_contract"]
        self.assertEqual(accepted["tool_family"], "sentinel_issue_fixture")
        self.assertEqual(accepted["exact_targets"], ["SPIKE-1", "SPIKE-2"])
        self.assertEqual(accepted["expires_in_minutes"], 20)
        self.assertFalse(accepted["dry_run_required"])
        self.assertEqual(again.status_code, 409)
        self.assertEqual(again.json()["detail"]["reason_code"], "proposal:superseded")
        self.assertEqual(listed["recent"][0]["resolution"], "adjusted_in_full_form")
        self.assertEqual(drafted.status_code, 200, drafted.text)
        self.assertIsNotNone(drafted.json()["proposed_contract"])

    def test_no_agent_prose_is_persisted_in_audit(self) -> None:
        marker = "ZEBRA-PROSE-MARKER"
        with mediated_client(activate=False) as ctx:
            pair(ctx["client"])
            extra = propose(ctx, objective=marker).json()
            draft_id = propose(ctx).json()["result"]["draft_id"]
            confirm(ctx, draft_id)
            rows = ctx["audit"].query(limit=1000)
        self.assertEqual(extra["verdict"], "block")
        serialized = " ".join(event.model_dump_json() for event in rows)
        self.assertNotIn(marker, serialized)


class ShimProposalTests(unittest.TestCase):
    def test_tool_list_includes_the_propose_tool_with_a_strict_schema(self) -> None:
        tools = {tool["name"]: tool for tool in shim.TOOLS}
        self.assertIn("sentinel_task_propose", tools)
        schema = tools["sentinel_task_propose"]["inputSchema"]
        self.assertEqual(set(schema["required"]), {"operation", "issue_ids", "minutes"})
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["operation"]["enum"], ["read", "write"])

    def test_shim_reports_a_pending_proposal_as_waiting_not_as_an_approval(self) -> None:
        payload = {
            "verdict": "confirm_required", "reason_code": "task:proposal_pending", "request_id": "r",
            "result": {"draft_id": "draft-1", "replaces_active_task": True},
        }
        with patch.object(shim, "call_gateway", return_value=(True, payload)):
            result = shim.handle_tools_call({
                "name": "sentinel_task_propose",
                "arguments": {"operation": "read", "issue_ids": ["SPIKE-1"], "minutes": 10},
            })
        text = result["content"][0]["text"]
        self.assertTrue(result["isError"])
        self.assertIn("grants nothing yet", text)
        self.assertIn("replace the currently active task", text)
        self.assertNotIn("approval_id", result["structuredContent"])
        self.assertEqual(result["structuredContent"]["draft_id"], "draft-1")


if __name__ == "__main__":
    unittest.main()
