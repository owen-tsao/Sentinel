"""The MCP gateway writes the typed decision record on its live path, and a
record that cannot be built never changes the response."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sentinel.mcp.gateway import McpMediator  # noqa: E402

from test_mcp_mediation_api import call, mediated_client, pair  # noqa: E402


class GatewayDecisionRecordTests(unittest.TestCase):
    def test_allowed_read_writes_a_resource_record(self) -> None:
        with mediated_client() as ctx:
            body = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}).json()
            events = ctx["audit"].query(event_type="decision")
        self.assertEqual(body["verdict"], "allow")
        record = events[-1].decision
        self.assertIsNotNone(record)
        self.assertEqual((record.action.family, record.action.host, record.action.tool),
                         ("mcp", "mcp_gateway", "sentinel_issue_read"))
        target = record.action.targets[0]
        self.assertEqual((target.surface, target.kind, target.resource.resource_type, target.resource.resource_id),
                         ("resource", "read", "issue", "SPIKE-1"))
        self.assertEqual(record.judgment.verdict, "allow")
        self.assertEqual(record.judgment.decided_by, "ceiling")
        self.assertEqual(record.judgment.enforcement, "mandatory")
        self.assertEqual(events[-1].verdict, "allow")
        # Legacy details are still written for readers that have not moved yet.
        self.assertEqual(events[-1].details["tool"], "sentinel_issue_read")

    def test_confirm_required_write_records_guidance_rule_and_message(self) -> None:
        with mediated_client() as ctx:
            pair(ctx["client"])
            body = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note"}).json()
            events = [e for e in ctx["audit"].query(event_type="decision") if e.decision is not None]
        self.assertEqual(body["verdict"], "confirm_required")
        record = events[-1].decision
        self.assertEqual(record.judgment.verdict, "confirm_required")
        self.assertEqual(record.judgment.rule_id, body["reason_code"])
        self.assertEqual(record.judgment.agent_guidance, body["guidance"])
        self.assertEqual(record.judgment.message, "sent")
        self.assertEqual(record.action.targets[0].kind, "write")
        self.assertEqual(record.action.payload_sha256, events[-1].details["payload_sha256"])
        # The note body is not in the row; only its hash is.
        self.assertNotIn("note", events[-1].decision.canonical_json().replace("add_note", ""))

    def test_unsupported_tool_records_unsupported_enforcement(self) -> None:
        with mediated_client() as ctx:
            body = call(ctx, "sentinel_issue_delete", {"issue_id": "SPIKE-1"}).json()
            events = ctx["audit"].query(event_type="decision")
        self.assertEqual((body["verdict"], body["coverage_status"]), ("block", "unsupported"))
        record = events[-1].decision
        self.assertEqual(record.judgment.enforcement, "unsupported")
        self.assertEqual(record.judgment.rule_id, "mcp:unsupported_tool")
        self.assertEqual(record.action.targets, [])

    def test_record_that_cannot_be_built_leaves_the_response_and_legacy_row_intact(self) -> None:
        with mediated_client() as ctx:
            with patch.object(McpMediator, "_decision_record", side_effect=RuntimeError("boom")):
                broken = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}).json()
            intact = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}).json()
            events = ctx["audit"].query(event_type="decision")
        self.assertEqual(broken["verdict"], "allow")
        self.assertEqual(broken["result"], intact["result"])
        # Both calls wrote a decision event; the broken one simply has no record.
        self.assertEqual(len(events), 2)
        self.assertIsNone(events[0].decision)
        self.assertEqual(events[0].details["tool"], "sentinel_issue_read")
        self.assertIsNotNone(events[1].decision)

    def test_invalid_record_falls_back_to_none_rather_than_raising(self) -> None:
        from sentinel.mcp.mediation import McpDecision
        from sentinel.api.integration_schemas import McpCallRequest

        payload = McpCallRequest(tool="sentinel_issue_read", arguments={"issue_id": "SPIKE-1"}, attempt_id=f"a-{uuid4()}")
        # A block with no guidance violates invariant 3; the builder must swallow it.
        bad = McpDecision("block", "x:y", "reason", ("x:y",), "")
        self.assertIsNone(McpMediator._decision_record(payload, bad, None, "mandatory"))
        good = McpDecision("block", "x:y", "reason", ("x:y",), "do this instead")
        record = McpMediator._decision_record(payload, good, None, "unavailable")
        self.assertEqual(record.judgment.enforcement, "unsupported")


if __name__ == "__main__":
    unittest.main()
