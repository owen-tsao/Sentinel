"""Week 18 step B: the shared service's host parameters.

docs/Week 18 Plan.md §3 step B. The same floor, inferrer, detector, and
budget serve Claude Code and Cursor; what differs is passed in. These tests
run the service with non-default host parameters and check that (a) rows and
records carry the host, (b) the restart rebuild only reads its own host's
rows, (c) the enforcement evaluator replaces the managed-settings check,
(d) the `ask` person channel turns the one budgeted stuck message into the
host's approval prompt, (e) exempt tools never enter the stuck ring, and
(f) `Delete` is judged as a delete.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any

from sentinel.audit.models import AuditEvent
from sentinel.hosts.claude_code import ClaudeCodeHookService
from sentinel.hosts.claude_code.session import SessionRegistry
from sentinel.hosts.claude_code.settings_check import EnforcementReport
from sentinel.supervision.floor_policy import FloorPolicy
from test_claude_code_adapter import HOME, PROJ, MemoryAudit, facts, kind, pre
from test_week17_advisory import failure, post


def cursor_like_service(audit: MemoryAudit | None = None, *, evaluator=None, exempt=frozenset()):
    audit = audit if audit is not None else MemoryAudit()
    service = ClaudeCodeHookService(
        policy=FloorPolicy(), audit_store=audit, home=HOME, managed_settings=Path("/managed.json"),
        facts_collector=lambda: facts(), snapshot_reader=lambda path: None,
        host="cursor", enforcement_evaluator=evaluator or (lambda s: EnforcementReport("mandatory", (), s.seen_pre_tool_use)),
        doctor_command="sentinel cursor doctor", person_channel="ask", detector_exempt_tools=exempt,
    )
    return service, audit


class HostStamp(unittest.TestCase):
    def test_rows_and_records_carry_the_host(self) -> None:
        service, audit = cursor_like_service()
        service.pre_tool_use(pre("Bash", {"command": "ls"}))
        service.pre_tool_use(pre("Write", {"file_path": f"{PROJ}/a.py", "content": ""}, tool_use_id="t2"))
        service.pre_tool_use(pre("WebFetch", {"url": "https://example.com"}, tool_use_id="t3"))
        decisions = [e for e in audit.events if e.event_type == "decision"]
        self.assertEqual(len(decisions), 3)
        for row in decisions:
            self.assertEqual(row.details["host"], "cursor")
            self.assertEqual(row.agent_id, "cursor")
            self.assertIsNotNone(row.decision)
            self.assertEqual(row.decision.action.host, "cursor")

    def test_default_service_is_still_claude_code(self) -> None:
        audit = MemoryAudit()
        service = ClaudeCodeHookService(policy=FloorPolicy(), audit_store=audit, home=HOME,
                                        managed_settings=Path("/managed.json"), facts_collector=lambda: facts(),
                                        snapshot_reader=lambda path: None)
        service.pre_tool_use(pre("Bash", {"command": "ls"}))
        row = audit.events[-1]
        self.assertEqual((row.details["host"], row.agent_id, row.decision.action.host), ("claude_code",) * 3)

    def test_unknown_person_channel_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            ClaudeCodeHookService(policy=FloorPolicy(), audit_store=MemoryAudit(), person_channel="popup")


class EnforcementEvaluator(unittest.TestCase):
    def test_evaluator_replaces_managed_settings_check(self) -> None:
        calls: list[str] = []

        def evaluator(session):
            calls.append(session.session_id)
            return EnforcementReport("advisory", ("hooks_not_locked",), session.seen_pre_tool_use)

        service, audit = cursor_like_service(evaluator=evaluator)
        body = service.pre_tool_use(pre("Bash", {"command": "rm -rf ~/.ssh"}))
        self.assertEqual(calls, ["s1"])
        self.assertEqual(kind(body), "deny")
        # The advisory note names this host's doctor, not Claude Code's.
        self.assertIn("sentinel cursor doctor", body["systemMessage"])
        self.assertNotIn("claude-code", body["systemMessage"])
        self.assertEqual(audit.events[-1].details["enforcement"], "advisory")
        self.assertEqual(audit.events[-1].decision.judgment.enforcement, "advisory")

    def test_evaluator_crash_is_advisory_not_a_pass(self) -> None:
        def evaluator(session):
            raise RuntimeError("boom")

        service, audit = cursor_like_service(evaluator=evaluator)
        body = service.pre_tool_use(pre("Bash", {"command": "ls"}))
        self.assertEqual(kind(body), "empty")   # allow is still allow; the claim is what changes
        self.assertEqual(audit.events[-1].details["enforcement"], "advisory")
        self.assertIn("evaluator_error", audit.events[-1].details["enforcement_failed"])


class AskChannel(unittest.TestCase):
    """On Cursor there is no systemMessage; the one budgeted message is `ask`."""

    def _loop_until_message(self, service, *, tool="Bash", command="pytest tests/x.py"):
        last = None
        for n in range(1, 8):
            tid = f"t{n}"
            last = service.pre_tool_use(pre(tool, {"command": command}, tool_use_id=tid))
            if kind(last) == "ask":
                return last, n
            service.failure_or_post = None
            service.post_tool_use_failure(failure(tool, {"command": command}, "Exit code 1\nE  assert 1 == 2", tool_use_id=tid))
        return last, None

    def test_budgeted_stuck_message_becomes_ask(self) -> None:
        service, audit = cursor_like_service()
        body, n = self._loop_until_message(service)
        self.assertIsNotNone(n, "the detector never reached its person-facing message")
        hook = body["hookSpecificOutput"]
        self.assertEqual(hook["permissionDecision"], "ask")
        self.assertNotIn("systemMessage", body)
        self.assertNotIn("additionalContext", hook)   # the nudge rides in the ask reason, not beside it
        row = audit.events[-1]
        self.assertEqual(row.details["detector"]["delivered"], "ask")
        self.assertTrue(row.details["detector"]["message_sent"])
        self.assertEqual(row.details["response"], "empty")   # the floor's own response is still recorded
        # The ask is attributed to Sentinel, so a later permission_request is marked caused_by_sentinel.
        session = service.sessions.get("s1")
        self.assertIn(f"t{n}", session.asked_tool_use_ids)

    def test_first_firing_is_a_nudge_not_an_ask(self) -> None:
        service, audit = cursor_like_service()
        responses = []
        for n in range(1, 4):
            responses.append(service.pre_tool_use(pre("Bash", {"command": "pytest tests/x.py"}, tool_use_id=f"t{n}")))
            service.post_tool_use_failure(failure("Bash", {"command": "pytest tests/x.py"}, "Exit code 1\nE  boom", tool_use_id=f"t{n}"))
        kinds = [kind(r) for r in responses]
        self.assertIn("context", kinds)       # a nudge was given before any ask
        self.assertNotIn("ask", kinds[: kinds.index("context") + 1])

    def test_system_message_channel_unchanged(self) -> None:
        service = ClaudeCodeHookService(policy=FloorPolicy(), audit_store=MemoryAudit(), home=HOME,
                                        managed_settings=Path("/managed.json"), facts_collector=lambda: facts(),
                                        snapshot_reader=lambda path: None)
        last, n = None, None
        for i in range(1, 8):
            last = service.pre_tool_use(pre("Bash", {"command": "pytest tests/x.py"}, tool_use_id=f"t{i}"))
            if "systemMessage" in last:
                n = i
                break
            service.post_tool_use_failure(failure("Bash", {"command": "pytest tests/x.py"}, "Exit code 1\nE  boom", tool_use_id=f"t{i}"))
        self.assertIsNotNone(n)
        self.assertNotEqual(kind(last), "ask")


class ExemptTools(unittest.TestCase):
    def test_exempt_tool_never_enters_the_ring(self) -> None:
        service, audit = cursor_like_service(exempt=frozenset({"AwaitShell"}))
        for i in range(1, 8):
            tid = f"t{i}"
            body = service.pre_tool_use(pre("AwaitShell", {"id": "bg1"}, tool_use_id=tid))
            self.assertEqual(kind(body), "empty")
            service.post_tool_use(post("AwaitShell", {"id": "bg1"}, "still running", tool_use_id=tid))
        session = service.sessions.get("s1")
        self.assertEqual(session.stuck.nudged, set())
        self.assertEqual(session.advisory_messages_sent, 0)
        self.assertTrue(all("detector" not in e.details for e in audit.events if e.event_type == "decision"))

    def test_non_exempt_tool_still_detected(self) -> None:
        service, _ = cursor_like_service(exempt=frozenset({"AwaitShell"}))
        fired = False
        for i in range(1, 8):
            body = service.pre_tool_use(pre("Bash", {"command": "pytest tests/x.py"}, tool_use_id=f"t{i}"))
            fired = fired or kind(body) in {"context", "ask"}
            service.post_tool_use_failure(failure("Bash", {"command": "pytest tests/x.py"}, "Exit code 1\nE  boom", tool_use_id=f"t{i}"))
        self.assertTrue(fired)


class DeleteTool(unittest.TestCase):
    def _judge(self, path: Any):
        service, audit = cursor_like_service()
        body = service.pre_tool_use(pre("Delete", {"path": path} if path is not None else {}))
        return kind(body), audit.events[-1]

    def test_inside_allows(self) -> None:
        k, row = self._judge(f"{PROJ}/build/out.txt")
        self.assertEqual(k, "empty")
        self.assertEqual((row.decision.judgment.verdict, row.decision.judgment.rule_id), ("allow", None))
        self.assertEqual(row.decision.action.tool, "Delete")

    def test_outside_confirms(self) -> None:
        k, row = self._judge("/Users/owen/other/file.txt")
        self.assertEqual(k, "ask")
        self.assertEqual(row.decision.judgment.rule_id, "F5.destructive_outside")

    def test_home_config_and_credential_block(self) -> None:
        for path, rule in [(f"{HOME}/.zshrc", "F1.delete_home"), (f"{HOME}/.ssh/id_rsa", "F1.delete_credential"),
                           (f"{PROJ}/.cursor/hooks.json", "F1.delete_protected_config"), ("/etc/hosts", "F1.delete_system")]:
            with self.subTest(path=path):
                k, row = self._judge(path)
                self.assertEqual(k, "deny")
                self.assertEqual(row.decision.judgment.rule_id, rule)

    def test_relative_or_missing_path_blocks_with_delete_wording(self) -> None:
        for path in ["src/a.py", None, 7]:
            with self.subTest(path=path):
                k, row = self._judge(path)
                self.assertEqual(k, "deny")
                self.assertEqual(row.decision.judgment.rule_id, "F1.delete_unresolved")
                self.assertIn("the delete cannot be checked", row.decision.judgment.reason)


class DeleteMatchesRm(unittest.TestCase):
    """The week's rule for `Delete`: the same verdict `rm` gets for the same path."""

    def test_parity(self) -> None:
        for path in [f"{PROJ}/build/x", f"{HOME}/Desktop/x", f"{HOME}/.zshrc", f"{HOME}/.ssh/id_rsa",
                     f"{HOME}/.config/foo/settings.json", "/etc/hosts", "/Users/other/repo/x", f"{PROJ}/.cursor/hooks.json"]:
            with self.subTest(path=path):
                service, audit = cursor_like_service()
                a = service.pre_tool_use(pre("Delete", {"path": path}, tool_use_id="d"))
                b = service.pre_tool_use(pre("Bash", {"command": f"rm -rf {path}"}, tool_use_id="r"))
                self.assertEqual(kind(a), kind(b), f"Delete={kind(a)} rm={kind(b)}")
                decisions = [e for e in audit.events if e.event_type == "decision"]
                self.assertEqual(decisions[0].decision.judgment.verdict, decisions[1].decision.judgment.verdict)


class EnvironmentFollowsNarrowing(unittest.TestCase):
    """Review B1, Claude Code side: a session first seen from a wide cwd and
    then narrowed by SessionStart to a production repo must judge as production."""

    def test_session_start_narrow_rederives_environment(self) -> None:
        audit = MemoryAudit()
        policy = FloorPolicy(environments={PROJ: "production"})
        service = ClaudeCodeHookService(policy=policy, audit_store=audit, home=HOME, managed_settings=Path("/managed.json"),
                                        facts_collector=lambda: facts(), snapshot_reader=lambda path: None)
        service.pre_tool_use(pre("Bash", {"command": "ls"}, cwd="/"))
        self.assertEqual(service.sessions.get("s1").environment, "dev")
        service.session_start({"session_id": "s1", "project_dir": PROJ, "source": "startup"})
        session = service.sessions.get("s1")
        self.assertEqual((session.launch_cwd, session.environment, session.current_boundary().environment),
                         (PROJ, "production", "production"))
        body = service.pre_tool_use(pre("Bash", {"command": "alembic upgrade head"}, tool_use_id="t2"))
        self.assertEqual(kind(body), "ask")
        self.assertEqual(audit.events[-1].decision.judgment.rule_id, "F8.schema_change_prod")

    def test_restart_rebuild_rederives_environment_from_recorded_launch_dir(self) -> None:
        """Review finding (October 15), the restart path: the rows say the session
        was launched in a production repo; the first post-restart event arrives
        from `/` (the agent had `cd`'d out). The rebuilt session must be production."""
        from sentinel.hosts.claude_code.session import SessionRegistry

        audit = MemoryAudit()
        policy = FloorPolicy(environments={PROJ: "production"})
        service = ClaudeCodeHookService(policy=policy, audit_store=audit, home=HOME, managed_settings=Path("/managed.json"),
                                        facts_collector=lambda: facts(), snapshot_reader=lambda path: None)
        service.pre_tool_use(pre("Bash", {"command": "ls"}, cwd=PROJ))
        self.assertEqual(service.sessions.get("s1").environment, "production")
        fresh = ClaudeCodeHookService(policy=policy, audit_store=audit, home=HOME, managed_settings=Path("/managed.json"),
                                      facts_collector=lambda: facts(), snapshot_reader=lambda path: None,
                                      sessions=SessionRegistry(audit_store=audit))
        body = fresh.pre_tool_use(pre("Bash", {"command": "alembic upgrade head"}, cwd="/", tool_use_id="t2"))
        session = fresh.sessions.get("s1")
        self.assertEqual((session.launch_cwd, session.environment, session.current_boundary().environment),
                         (PROJ, "production", "production"))
        self.assertEqual(kind(body), "ask")
        self.assertEqual(audit.events[-1].decision.judgment.rule_id, "F8.schema_change_prod")


class RestartRebuildFilters(unittest.TestCase):
    def test_rebuild_reads_only_its_own_hosts_rows(self) -> None:
        """A Claude Code session and a Cursor session that happen to share a
        session_id (different hosts, independent id spaces) must not read
        each other's budget."""
        audit = MemoryAudit()
        cc_service, _ = cursor_like_service(audit)   # writes cursor rows
        # A hand-written claude_code boundary row (a budgeted caution) for the same session id.
        audit.write(AuditEvent(event_type="boundary", session_id="s1", agent_id="claude_code",
                               details={"host": "claude_code", "focus": f"{PROJ}/claude-only", "boundary_root": PROJ,
                                        "prompt_sha256": "x", "message_counted": True}))
        cc_service.pre_tool_use(pre("Bash", {"command": "ls"}))
        # Fresh registry for the cursor host rebuilds s1 from rows: the claude_code spend is ignored.
        registry = SessionRegistry(audit_store=audit, host="cursor")
        session = registry.ensure("s1", launch_cwd=PROJ, source="hook_payload", environment="dev")
        self.assertEqual(session.current_boundary().root, PROJ)
        self.assertEqual(session.advisory_messages_sent, 0)
        # And the claude_code registry does see it (the boundary is the launch directory on both).
        registry_cc = SessionRegistry(audit_store=audit, host="claude_code")
        session_cc = registry_cc.ensure("s1", launch_cwd=PROJ, source="hook_payload", environment="dev")
        self.assertEqual(session_cc.current_boundary().root, PROJ)
        self.assertEqual(session_cc.advisory_messages_sent, 1)


if __name__ == "__main__":
    unittest.main()
