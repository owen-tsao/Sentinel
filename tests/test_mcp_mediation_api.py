from __future__ import annotations

import os
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import Mock, patch
from uuid import uuid4

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.api.main import create_app  # noqa: E402
from sentinel.audit import SQLiteAuditStore  # noqa: E402
from sentinel.audit.base import AuditStoreError  # noqa: E402
from sentinel.contracts import (  # noqa: E402
    ActionContract,
    InMemoryContractStore,
    InMemoryTrustedEventConsumer,
    TrustedPromptEnvelope,
)
from sentinel.control import (  # noqa: E402
    ControlConfig,
    SQLiteWorkspaceBindingStore,
    review_workspace,
)
from sentinel.execution import DockerExecutor  # noqa: E402
from sentinel.integrations import AdapterSessionRegistry  # noqa: E402
from sentinel.mcp import SQLiteIssueFixture  # noqa: E402
from sentinel.supervision import week12_fixture_policy  # noqa: E402

API_HOST = "127.0.0.1:8000"
UI_ORIGIN = "http://127.0.0.1:3000"
PAIRING = "mcp-pairing-" + ("a" * 32)
FIXTURE_ISSUES = {"SPIKE-1": "Login page returns 500", "SPIKE-2": "Export drops unicode rows"}


def fixture_contract(*, targets: list[str] | None = None) -> ActionContract:
    return ActionContract(
        objective="Read fixture issues and add one reviewed note.",
        allowed_operations={"read", "write"},
        allowed_tools={"sentinel_issue_read", "sentinel_issue_add_note"},
        exact_targets=targets or ["SPIKE-1", "SPIKE-2"],
        environment="sandbox",
        maximum_scope="exact",
        expected_side_effects=["One internal note on a fixture issue."],
        allowed_effects={"read", "write"},
        forbidden_operations={"delete", "network", "credential_access"},
        forbidden_effects=["No deletion, network, or credential access."],
        forbidden_effect_codes={"delete", "network", "credential_access"},
        rollback_plan="Notes are disposable fixture data.",
        dry_run_required=False,
        authorization_reference="mcp-mediation-test",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )


@contextmanager
def mediated_client(*, activate: bool = True) -> Iterator[dict[str, Any]]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        repository = root / "repository"
        repository.mkdir()
        (repository / ".git").mkdir()
        database = root / "sentinel.sqlite3"
        binding_store = SQLiteWorkspaceBindingStore(database)
        supervision = binding_store.bind(review_workspace(repository))
        host_id = f"sentinel-control:{supervision.workspace.identity_sha256}"
        consumer = InMemoryTrustedEventConsumer(
            host_id=host_id, session_id=supervision.session_id, channel="protected_local_ui"
        )
        contracts = InMemoryContractStore(trusted_event_consumer=consumer)
        record = None
        if activate:
            now = datetime.now(timezone.utc)
            contract_id = str(uuid4())
            receipt = consumer.consume(
                TrustedPromptEnvelope(
                    event_id=f"event-{uuid4()}", nonce=f"nonce-{uuid4().hex}", host_id=host_id,
                    session_id=supervision.session_id, channel="protected_local_ui",
                    prompt="Activate the fixture task.", purpose="task_transition",
                    contract_id=contract_id, contract_version=1, decision="approve",
                    issued_at=now - timedelta(seconds=1), expires_at=now + timedelta(minutes=5),
                    authenticated=True,
                ),
                now=now,
            )
            record = contracts.create_active(
                fixture_contract(), session_id=supervision.session_id,
                authorization_source="protected_local_ui", created_at=now, contract_id=contract_id,
                expected_active_task_id=None, trusted_event=receipt,
            )
        fixture = SQLiteIssueFixture(root / "fixture.sqlite3")
        fixture.seed(FIXTURE_ISSUES)
        registry = AdapterSessionRegistry(supervision_session_id=supervision.session_id)
        issued = registry.issue(adapter_kind="cursor_mcp", tool_family="sentinel_issue_fixture")
        audit = SQLiteAuditStore(database)
        config = ControlConfig(
            workspace=repository, pairing_capability=PAIRING, api_host=API_HOST, ui_origin=UI_ORIGIN
        )
        with patch.dict(os.environ, {"SENTINEL_STATE_DB": str(database)}, clear=False):
            app = create_app(
                load_model=False, load_policy=False, contract_store=contracts, audit_store=audit,
                executor=DockerExecutor(workspace=repository, runner=Mock()),
                execution_environment="sandbox", control_config=config,
                control_binding_store=binding_store, supervision_policy=week12_fixture_policy(),
                mcp_fixture=fixture, adapter_registry=registry,
            )
            with TestClient(app, base_url=f"http://{API_HOST}") as client:
                yield {
                    "client": client, "app": app, "bearer": issued.capability, "fixture": fixture,
                    "registry": registry, "audit": audit, "record": record, "contracts": contracts,
                }
        audit.close()
        binding_store.close()


def call(ctx: dict[str, Any], tool: str, arguments: dict[str, Any], *, attempt_id: str | None = None,
         bearer: str | None = "default", extra_headers: dict[str, str] | None = None,
         body_extra: dict[str, Any] | None = None):
    headers = {}
    if bearer == "default":
        headers["Authorization"] = f"Bearer {ctx['bearer']}"
    elif bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    headers.update(extra_headers or {})
    body = {"tool": tool, "arguments": arguments, "attempt_id": attempt_id or f"attempt-{uuid4()}"}
    body.update(body_extra or {})
    return ctx["client"].post("/integration/mcp/call", json=body, headers=headers)


def pair(client: TestClient) -> None:
    response = client.post("/control/pair/exchange", headers={"Origin": UI_ORIGIN}, json={"capability": PAIRING})
    assert response.status_code == 200, response.text


def approve(ctx: dict[str, Any], approval_id: str):
    return ctx["client"].post(
        f"/control/approvals/{approval_id}/approve", headers={"Origin": UI_ORIGIN}, json={"typed_target": "SPIKE-1"}
    )


def deny(ctx: dict[str, Any], approval_id: str):
    return ctx["client"].post(f"/control/approvals/{approval_id}/deny", headers={"Origin": UI_ORIGIN}, json={})


class McpMediationRouteTests(unittest.TestCase):
    def test_matching_reads_are_admitted_and_repeatable(self) -> None:
        with mediated_client() as ctx:
            responses = [call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}).json() for _ in range(3)]
            events = ctx["audit"].query(event_type="execution_admitted")
        for body in responses:
            self.assertEqual(body["verdict"], "allow")
            self.assertEqual(body["coverage_status"], "mandatory")
            self.assertEqual(body["result"]["title"], FIXTURE_ISSUES["SPIKE-1"])
            self.assertEqual(body["operation_state"], "succeeded")
        self.assertEqual(len(events), 3)

    def test_adapter_authentication_fails_closed(self) -> None:
        with mediated_client() as ctx:
            missing = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}, bearer=None)
            wrong = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}, bearer="forged")
            ctx["registry"].issue(adapter_kind="cursor_mcp", tool_family="sentinel_issue_fixture")
            rotated = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"})
            browser = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}, extra_headers={"Origin": UI_ORIGIN})
            wrong_host = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}, extra_headers={"Host": "localhost:8000"})
            notes = ctx["fixture"].note_count()
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(missing.json()["detail"]["reason_code"], "adapter:capability_missing")
        self.assertEqual(wrong.json()["detail"]["reason_code"], "adapter:capability_unknown")
        self.assertEqual(rotated.json()["detail"]["reason_code"], "adapter:capability_revoked")
        self.assertEqual(browser.status_code, 403)
        self.assertEqual(wrong_host.status_code, 421)
        self.assertEqual(notes, 0)

    def test_caller_selected_fields_and_unknown_tools_are_rejected(self) -> None:
        with mediated_client() as ctx:
            verdict = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}, body_extra={"verdict": "allow"})
            session = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}, body_extra={"session_id": "other"})
            unknown_tool = call(ctx, "sentinel_issue_delete", {"issue_id": "SPIKE-1"}).json()
            unknown_arg = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1", "force": True}).json()
            out_of_scope = call(ctx, "sentinel_issue_read", {"issue_id": "PROD-1"}).json()
            unknown_issue = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-9"}).json()
        self.assertEqual(verdict.status_code, 422)
        self.assertEqual(session.status_code, 422)
        self.assertEqual((unknown_tool["verdict"], unknown_tool["coverage_status"]), ("block", "unsupported"))
        self.assertEqual(unknown_arg["reason_code"], "mcp:unknown_argument")
        self.assertEqual(out_of_scope["reason_code"], "supervision:issue_out_of_scope")
        self.assertEqual(unknown_issue["verdict"], "block")
        self.assertTrue(unknown_issue["reason_code"].startswith("contract:"))

    def test_without_an_active_task_everything_is_blocked(self) -> None:
        with mediated_client(activate=False) as ctx:
            read = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}).json()
            write = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "x"}).json()
            pending = ctx["client"].get("/control/approvals", headers={"Origin": UI_ORIGIN})
            notes = ctx["fixture"].note_count()
        self.assertEqual(read["reason_code"], "contract:not_found")
        self.assertEqual(write["reason_code"], "contract:not_found")
        self.assertEqual(notes, 0)
        self.assertEqual(pending.status_code, 401)

    def test_denied_write_has_zero_effect_and_retry_reports_denial(self) -> None:
        with mediated_client() as ctx:
            pair(ctx["client"])
            attempt = f"attempt-{uuid4()}"
            first = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note A"}, attempt_id=attempt).json()
            self.assertEqual(first["verdict"], "confirm_required")
            self.assertEqual(ctx["fixture"].note_count(), 0)
            listed = ctx["client"].get("/control/approvals", headers={"Origin": UI_ORIGIN}).json()["approvals"]
            denied = deny(ctx, first["approval_id"])
            retry = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note A"}, attempt_id=attempt).json()
            denial_events = ctx["audit"].query(event_type="exact_action_denied")
            notes = ctx["fixture"].note_count()
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["operation"], "write")
        self.assertEqual(listed[0]["targets"], ["SPIKE-1"])
        self.assertEqual(denied.status_code, 200)
        self.assertEqual(retry["verdict"], "block")
        self.assertEqual(retry["reason_code"], "mcp:attempt_failed")
        self.assertEqual(notes, 0)
        self.assertEqual(len(denial_events), 1)

    def test_approved_write_applies_exactly_once_and_rejects_replay_and_change(self) -> None:
        with mediated_client() as ctx:
            pair(ctx["client"])
            attempt = f"attempt-{uuid4()}"
            pending = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note B"}, attempt_id=attempt).json()
            same_again = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note B"}, attempt_id=attempt).json()
            approved = approve(ctx, pending["approval_id"])
            second_click = approve(ctx, pending["approval_id"])
            replay = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note B"}, attempt_id=attempt).json()
            changed = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note B!"}, attempt_id=attempt).json()
            redirected = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-2", "body": "note B"}, attempt_id=attempt).json()
            issue = ctx["fixture"].issue("SPIKE-1")
            admitted = ctx["audit"].query(event_type="execution_admitted")
            approved_events = ctx["audit"].query(event_type="exact_action_approved")
        self.assertEqual(same_again["approval_id"], pending["approval_id"])
        self.assertEqual(approved.status_code, 200, approved.text)
        self.assertEqual(approved.json()["retry"]["verdict"], "allow")
        self.assertIn("mcp:approved_write_applied", approved.json()["retry"]["reasons"])
        self.assertEqual(second_click.status_code, 409)
        self.assertEqual(replay["reason_code"], "mcp:already_applied")
        self.assertFalse(replay["result"]["note_added"])
        self.assertEqual(changed["reason_code"], "fixture:attempt_binding_mismatch")
        self.assertEqual(redirected["reason_code"], "fixture:attempt_binding_mismatch")
        self.assertEqual(issue.notes, ("note B",))
        self.assertEqual(len([e for e in admitted if e.details.get("attempt_id") == attempt]), 1)
        self.assertEqual(len(approved_events), 1)
        self.assertNotIn("token", approved.text.lower().replace("typed_target", ""))

    def test_adapter_rotation_between_request_and_approval_blocks_cleanly(self) -> None:
        with mediated_client() as ctx:
            pair(ctx["client"])
            attempt = f"attempt-{uuid4()}"
            pending = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note R"}, attempt_id=attempt).json()
            # The shim reconnects (new adapter capability) while the approval is pending.
            rotated = ctx["registry"].issue(adapter_kind="cursor_mcp", tool_family="sentinel_issue_fixture")
            approved = approve(ctx, pending["approval_id"])
            retry = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note R"},
                         attempt_id=attempt, bearer=rotated.capability).json()
            issue = ctx["fixture"].issue("SPIKE-1")
            operation = ctx["fixture"].get(attempt)
            admitted = ctx["audit"].query(event_type="execution_admitted")
        self.assertEqual(approved.status_code, 200, approved.text)
        self.assertEqual(approved.json()["retry"]["verdict"], "block")
        self.assertIn("approval:binding_mismatch", approved.json()["retry"]["reasons"])
        self.assertEqual(operation.state, "failed")
        self.assertEqual(retry["reason_code"], "fixture:attempt_binding_mismatch")
        self.assertEqual(issue.notes, ())
        self.assertEqual([e for e in admitted if e.details.get("attempt_id") == attempt], [])

    def test_unreconciled_applying_operation_reports_unknown_without_readmission(self) -> None:
        with mediated_client() as ctx:
            pair(ctx["client"])
            attempt = f"attempt-{uuid4()}"
            pending = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note U"}, attempt_id=attempt).json()
            # Crash inside the effect after `applying` is durable: the process
            # survives, so the state stays `applying` until a restart reconciles it.
            with patch.object(SQLiteIssueFixture, "_effect", side_effect=RuntimeError("simulated crash")):
                with self.assertRaises(RuntimeError):
                    approve(ctx, pending["approval_id"])
            stuck = ctx["fixture"].get(attempt)
            admitted_before = [e for e in ctx["audit"].query(event_type="execution_admitted")
                               if e.details.get("attempt_id") == attempt]
            retry = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note U"}, attempt_id=attempt)
            admitted_after = [e for e in ctx["audit"].query(event_type="execution_admitted")
                              if e.details.get("attempt_id") == attempt]
            notes = ctx["fixture"].issue("SPIKE-1").notes
        self.assertEqual(stuck.state, "applying")
        self.assertEqual(retry.status_code, 200, retry.text)
        self.assertEqual(retry.json()["verdict"], "block")
        self.assertEqual(retry.json()["reason_code"], "mcp:outcome_unknown")
        self.assertEqual(retry.json()["operation_state"], "applying")
        self.assertEqual(len(admitted_before), 1)
        self.assertEqual(len(admitted_after), 1, "a stuck operation must not accumulate admission evidence")
        self.assertEqual(notes, ())

    def test_admission_audit_failure_blocks_and_leaves_attempt_retryable(self) -> None:
        with mediated_client() as ctx:
            attempt = f"attempt-{uuid4()}"
            with patch.object(ctx["audit"], "write_required", side_effect=AuditStoreError("disk full")):
                blocked = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}, attempt_id=attempt).json()
            after_failure = ctx["fixture"].get(attempt)
            recovered = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}, attempt_id=attempt).json()
        self.assertEqual(blocked["verdict"], "block")
        self.assertEqual(blocked["reason_code"], "audit:admission_failed")
        self.assertEqual(blocked["coverage_status"], "unavailable")
        self.assertEqual(after_failure.state, "prepared")
        self.assertEqual(recovered["verdict"], "allow")
        self.assertEqual(recovered["operation_state"], "succeeded")

    def test_expired_ceiling_fails_closed_and_status_reports_unavailable(self) -> None:
        with mediated_client() as ctx:
            pair(ctx["client"])
            binding_type = type(ctx["app"].state.mcp_mediator._policy_binding)
            with patch.object(binding_type, "is_expired", return_value=True):
                blocked = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}).json()
                status = ctx["client"].get("/control/status", headers={"Origin": UI_ORIGIN}).json()
        self.assertEqual(blocked["verdict"], "block")
        self.assertEqual(blocked["reason_code"], "supervision:ceiling_expired")
        self.assertEqual(blocked["coverage_status"], "unavailable")
        self.assertEqual(status["integration"]["gateway"]["status"], "unavailable")
        self.assertTrue(status["integration"]["ceiling"]["expired"])
        fixture_family = next(c for c in status["integration"]["coverage"] if c["family"] == "sentinel_issue_fixture")
        self.assertEqual(fixture_family["status"], "unavailable")

    def test_concurrent_approval_clicks_and_retries_produce_one_note(self) -> None:
        with mediated_client() as ctx:
            pair(ctx["client"])
            attempt = f"attempt-{uuid4()}"
            pending = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-2", "body": "note C"}, attempt_id=attempt).json()
            with ThreadPoolExecutor(max_workers=8) as pool:
                clicks = list(pool.map(lambda _: approve(ctx, pending["approval_id"]).status_code, range(8)))
            with ThreadPoolExecutor(max_workers=8) as pool:
                retries = list(pool.map(
                    lambda _: call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-2", "body": "note C"},
                                   attempt_id=attempt).json()["reason_code"],
                    range(8),
                ))
            notes = ctx["fixture"].note_count()
        self.assertEqual(clicks.count(200), 1)
        self.assertEqual(set(retries), {"mcp:already_applied"})
        self.assertEqual(notes, 1)

    def test_authority_change_invalidates_pending_mcp_approval(self) -> None:
        with mediated_client() as ctx:
            pair(ctx["client"])
            attempt = f"attempt-{uuid4()}"
            pending = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "stale"}, attempt_id=attempt).json()
            ctx["app"].state.authority_service.suspend(
                ctx["record"].contract_id, expected_version=ctx["record"].version,
                suspended_at=datetime.now(timezone.utc),
            )
            late = approve(ctx, pending["approval_id"])
            retry = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "stale"}, attempt_id=attempt).json()
            notes = ctx["fixture"].note_count()
        self.assertEqual(late.status_code, 409)
        self.assertEqual(retry["verdict"], "block")
        self.assertEqual(notes, 0)

    def test_status_reports_honest_integration_coverage_and_connection(self) -> None:
        with mediated_client() as ctx:
            pair(ctx["client"])
            before = ctx["client"].get("/control/status", headers={"Origin": UI_ORIGIN}).json()
            call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"})
            call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}, bearer="forged")
            hooks_dir = ctx["app"].state.supervision_binding.workspace.path / ".cursor"
            hooks_dir.mkdir()
            (hooks_dir / "hooks.json").write_text(
                (Path(__file__).resolve().parents[1] / "policies" / "cursor" / "hooks.json").read_text()
            )
            after = ctx["client"].get("/control/status", headers={"Origin": UI_ORIGIN}).json()
        self.assertFalse(before["mandatory_agent_connected"])
        self.assertEqual(before["integration"]["agent"]["status"], "never_connected")
        self.assertEqual(before["integration"]["hooks"]["status"], "unavailable")
        self.assertTrue(after["mandatory_agent_connected"])
        self.assertIn("fixture tool family is mandatory", after["connection_message"])
        agent = after["integration"]["agent"]
        self.assertEqual((agent["status"], agent["last_tool"], agent["last_verdict"]), ("connected", "sentinel_issue_read", "allow"))
        self.assertEqual((agent["mediated_calls"], agent["rejected_calls"]), (1, 1))
        self.assertEqual(after["integration"]["hooks"]["status"], "ready")
        self.assertEqual(after["integration"]["sandbox"]["status"], "unavailable")
        self.assertEqual(after["integration"]["gateway"]["status"], "ready")
        self.assertFalse(after["integration"]["ceiling"]["expired"])
        coverage = {entry["family"]: entry["status"] for entry in after["integration"]["coverage"]}
        self.assertEqual(coverage["sentinel_issue_fixture"], "mandatory")
        self.assertEqual(coverage["shell"], "advisory")
        self.assertEqual(coverage["browser"], "unsupported")
        self.assertNotIn("protected", after["connection_message"].lower())

    def test_pending_mcp_approval_exposes_tool_and_exact_arguments(self) -> None:
        with mediated_client() as ctx:
            pair(ctx["client"])
            call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-2", "body": "exact body"})
            listed = ctx["client"].get("/control/approvals", headers={"Origin": UI_ORIGIN}).json()["approvals"]
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["family"], "mcp")
        self.assertEqual(listed[0]["tool"], "sentinel_issue_add_note")
        self.assertEqual(listed[0]["arguments"], {"issue_id": "SPIKE-2", "body": "exact body"})
        self.assertEqual(listed[0]["targets"], ["SPIKE-2"])
        self.assertEqual(listed[0]["operation"], "write")

    def test_fixture_task_can_be_drafted_and_activated_through_the_control_flow(self) -> None:
        accepted = {
            "operation": "write", "exact_targets": ["SPIKE-1"], "environment": "sandbox",
            "expected_side_effects": ["One internal note on SPIKE-1."], "allowed_effects": ["write"],
            "forbidden_operations": ["delete", "network", "credential_access"],
            "forbidden_effects": ["No deletion, network, or credential access."],
            "forbidden_effect_codes": ["delete", "network", "credential_access"],
            "rollback_plan": "Notes are disposable fixture data.", "dry_run_required": False,
            "tool_family": "sentinel_issue_fixture",
        }
        with mediated_client(activate=False) as ctx:
            pair(ctx["client"])
            headers = {"Origin": UI_ORIGIN}
            bad_target = ctx["client"].post(
                "/control/contracts/draft", headers=headers,
                json={"raw_prompt": "Add a note to PROD-1", "accepted_contract": {**accepted, "exact_targets": ["PROD-1"]}},
            )
            dry_run = ctx["client"].post(
                "/control/contracts/draft", headers=headers,
                json={"raw_prompt": "Add a note to SPIKE-1", "accepted_contract": {**accepted, "dry_run_required": True}},
            )
            obligations = [
                ctx["client"].post(
                    "/control/contracts/draft", headers=headers,
                    json={"raw_prompt": "Add a note to SPIKE-1", "accepted_contract": {**accepted, flag: True}},
                )
                for flag in ("rollback_required", "transaction_required", "backup_required")
            ]
            drafted = ctx["client"].post(
                "/control/contracts/draft", headers=headers,
                json={"raw_prompt": "Add a note to SPIKE-1", "accepted_contract": accepted},
            )
            proposed = drafted.json()["proposed_contract"]
            activated = ctx["client"].post(
                "/control/contracts/activate", headers=headers,
                json={"contract_id": proposed["contract_id"], "expected_version": proposed["version"],
                      "expected_active_task_id": None},
            )
            read = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-1"}).json()
            other = call(ctx, "sentinel_issue_read", {"issue_id": "SPIKE-2"}).json()
            write = call(ctx, "sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "hi"}).json()
        self.assertEqual(bad_target.status_code, 422, bad_target.text)
        self.assertEqual(dry_run.status_code, 422, dry_run.text)
        for response in obligations:
            self.assertEqual(response.status_code, 422, response.text)
            self.assertIn("do not support these safeguards", response.text)
        self.assertEqual(drafted.status_code, 200, drafted.text)
        self.assertEqual(sorted(proposed["contract"]["allowed_tools"]), ["sentinel_issue_add_note", "sentinel_issue_read"])
        self.assertEqual(sorted(proposed["contract"]["allowed_operations"]), ["read", "write"])
        self.assertEqual(proposed["contract"]["exact_targets"], ["SPIKE-1"])
        self.assertEqual(activated.status_code, 200, activated.text)
        self.assertEqual(read["verdict"], "allow")
        self.assertEqual(other["verdict"], "block")
        self.assertEqual(write["verdict"], "confirm_required")

    def test_evaluate_and_execute_routes_are_untouched_by_mcp_wiring(self) -> None:
        with mediated_client() as ctx:
            health = ctx["client"].get("/health")
        self.assertEqual(health.status_code, 200)


if __name__ == "__main__":
    unittest.main()
