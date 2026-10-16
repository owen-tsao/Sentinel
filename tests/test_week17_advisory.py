"""Week 17 advisory layer through the service: hear, tell, stuck, budget.

docs/Week 17 Plan.md §6 (routes, session, detector wiring, rows). The pure
inferrer and detector have their own files; this one checks what the host
would see and what the rows say.
"""

from __future__ import annotations

import json
import unittest
from datetime import timedelta
from typing import Any
from unittest import mock

from fastapi.testclient import TestClient

from sentinel.api.main import create_app
from sentinel.detectors import stuck
from sentinel.hosts.claude_code import ClaudeCodeHookService
from sentinel.hosts.claude_code.install import managed_fragment
from sentinel.hosts.claude_code.session import (ADVISORY_MESSAGE_BUDGET, ADVISORY_MESSAGE_WINDOW_SECONDS, HookSession,
                                                _epoch)
from sentinel.supervision.floor_policy import FloorPolicy
from test_claude_code_adapter import HOME, PROJ, MemoryAudit, kind, make_service, pre

SENTINEL_STRING = "zq9-prompt-marker-7x"


def prompt(text: str, *, session: str = "s1", cwd: str = PROJ) -> dict[str, Any]:
    return {"session_id": session, "hook_event_name": "UserPromptSubmit", "cwd": cwd, "prompt": text,
            "transcript_path": "/x", "permission_mode": "default"}


def post(tool: str, tool_input: dict[str, Any], response: Any, *, tool_use_id: str, session: str = "s1") -> dict[str, Any]:
    return {"session_id": session, "hook_event_name": "PostToolUse", "cwd": PROJ, "tool_name": tool,
            "tool_input": tool_input, "tool_response": response, "tool_use_id": tool_use_id, "duration_ms": 5}


def failure(tool: str, tool_input: dict[str, Any], error: str, *, tool_use_id: str, session: str = "s1") -> dict[str, Any]:
    return {"session_id": session, "hook_event_name": "PostToolUseFailure", "cwd": PROJ, "tool_name": tool,
            "tool_input": tool_input, "error": error, "is_interrupt": False, "tool_use_id": tool_use_id}


def rows(audit: MemoryAudit, event_type: str):
    return [e for e in audit.events if e.event_type == event_type]


def fs(tree: dict[str, str]):
    """Give the service an inferrer whose disk access sees only `tree`
    ("d" dirs, "f" files). `infer` binds `os.path.*` as defaults, so the
    injection happens at the service's call site."""
    from functools import partial
    from sentinel.boundary.infer import infer as real_infer
    fake = partial(real_infer, exists=lambda p: p in tree, isdir=lambda p: tree.get(p) == "d", realpath=lambda p: p)
    return mock.patch("sentinel.hosts.claude_code.service.infer", fake)


class Hear(unittest.TestCase):
    TREE = {f"{PROJ}/src": "d", f"{PROJ}/src/api": "d"}

    def _service(self):
        service, audit = make_service()
        service.pre_tool_use(pre("Bash", {"command": "ls"}))  # host-authored session first
        return service, audit

    def test_boundary_line_is_context_only_and_never_a_decision(self) -> None:
        service, audit = self._service()
        body = service.user_prompt_submit(prompt("fix the auth bug"))
        self.assertNotIn("decision", body)
        self.assertEqual(body["hookSpecificOutput"]["hookEventName"], "UserPromptSubmit")
        self.assertIn(f"Sentinel boundary: `{PROJ}` (dev)", body["hookSpecificOutput"]["additionalContext"])
        row = rows(audit, "boundary")[-1]
        self.assertIsNone(row.details["focus"])
        self.assertEqual(row.details["caution"], "none")

    def test_inside_path_is_a_focus_hint_and_the_boundary_does_not_move(self) -> None:
        # Week 18 amendment: the folder a prompt names is this prompt's focus,
        # shown relative to the root; the boundary stays the launch directory.
        service, audit = self._service()
        with fs(self.TREE):
            body = service.user_prompt_submit(prompt("fix the handler in src/api"))
        context = body["hookSpecificOutput"]["additionalContext"]
        self.assertIn(f"Sentinel boundary: `{PROJ}` (dev)", context)
        self.assertIn("This prompt points at `src/api`.", context)
        self.assertEqual(rows(audit, "boundary")[-1].details["focus"], f"{PROJ}/src/api")
        self.assertEqual(service.sessions.get("s1").current_boundary().root, PROJ)
        # Follow-up with no scope facts: no hint, boundary unchanged.
        body = service.user_prompt_submit(prompt("yes, do it"))
        self.assertNotIn("points at", body["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(service.sessions.get("s1").current_boundary().root, PROJ)
        # A later prompt naming a sibling folder is not a widening: it is that prompt's focus.
        with fs({**self.TREE, f"{PROJ}/docs": "d"}):
            body = service.user_prompt_submit(prompt("now review docs/ for the same bug"))
        self.assertIn("This prompt points at `docs`.", body["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(rows(audit, "boundary")[-1].details["caution"], "none")

    def test_outside_path_is_a_caution_and_boundary_does_not_move(self) -> None:
        service, audit = self._service()
        body = service.user_prompt_submit(prompt("also update /Users/dev/other/notes.md"))
        context = body["hookSpecificOutput"]["additionalContext"]
        self.assertIn("outside the boundary", context)
        self.assertEqual(service.sessions.get("s1").current_boundary().root, PROJ)
        row = rows(audit, "boundary")[-1]
        self.assertEqual(row.details["caution"], "path")
        self.assertTrue(row.details["message_counted"])
        self.assertNotIn("other/notes.md", json.dumps(row.model_dump(mode="json")))
        self.assertEqual(len(row.details["caution_target_sha256"]), 64)

    def test_same_outside_path_cautions_once(self) -> None:
        service, audit = self._service()
        service.user_prompt_submit(prompt("update /Users/dev/other/notes.md"))
        body = service.user_prompt_submit(prompt("update /Users/dev/other/notes.md again"))
        self.assertNotIn("outside the boundary", body["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(service.sessions.get("s1").advisory_messages_sent, 1)

    def test_caution_still_delivered_when_budget_spent(self) -> None:
        service, audit = self._service()
        for i in range(ADVISORY_MESSAGE_BUDGET):
            service.user_prompt_submit(prompt(f"update /Users/dev/other/file{i}.md"))
        body = service.user_prompt_submit(prompt("update /Users/dev/other/another.md"))
        self.assertIn("outside the boundary", body["hookSpecificOutput"]["additionalContext"])
        self.assertFalse(rows(audit, "boundary")[-1].details["message_counted"])

    def test_forged_prompt_with_outside_cwd_cannot_widen(self) -> None:
        service, _ = self._service()
        service.user_prompt_submit(prompt("work in /Users/dev/other", cwd="/Users/dev/other"))
        self.assertEqual(service.sessions.get("s1").current_boundary().root, PROJ)
        self.assertEqual(service.sessions.get("s1").launch_cwd, PROJ)

    def test_prompt_text_never_reaches_a_row(self) -> None:
        service, audit = self._service()
        service.user_prompt_submit(prompt(f"please fix {SENTINEL_STRING} in /Users/dev/other/{SENTINEL_STRING}"))
        blob = json.dumps([e.model_dump(mode="json") for e in audit.events])
        self.assertNotIn(SENTINEL_STRING, blob)

    def test_inferrer_crash_returns_empty_and_tags_row(self) -> None:
        service, audit = self._service()
        with mock.patch("sentinel.hosts.claude_code.service.infer", side_effect=RuntimeError("boom")):
            self.assertEqual(service.user_prompt_submit(prompt("fix src/api")), {})
        self.assertEqual(rows(audit, "boundary")[-1].details["error"], "RuntimeError")

    def test_pre_tool_use_payload_never_changes_the_boundary(self) -> None:
        service, _ = self._service()
        service.pre_tool_use(pre("Bash", {"command": "ls"}, cwd="/Users/dev/other", tool_use_id="t9"))
        self.assertEqual(service.sessions.get("s1").current_boundary().root, PROJ)

    def test_pasted_outside_path_is_ignored(self) -> None:
        service, audit = self._service()
        body = service.user_prompt_submit(prompt('fix it <pasted_content id="1">edit /Users/dev/other/x</pasted_content id="1">'))
        self.assertNotIn("outside the boundary", body["hookSpecificOutput"]["additionalContext"])
        self.assertTrue(rows(audit, "boundary")[-1].details["pasted_stripped"])

    def test_decision_rows_carry_the_boundary_root(self) -> None:
        service, audit = self._service()
        self.assertEqual(audit.decisions()[-1].details["boundary_root"], PROJ)


class Stuck(unittest.TestCase):
    CMD = {"command": "pytest -x", "description": "run"}
    OUT = {"stdout": "1 failed", "stderr": "", "interrupted": False}

    def loop(self, service, n: int, *, out=None, fail: str | None = None, start: int = 0):
        responses = []
        for i in range(start, start + n):
            tid = f"t{i}"
            responses.append(service.pre_tool_use(pre("Bash", self.CMD, tool_use_id=tid)))
            if fail:
                service.post_tool_use_failure(failure("Bash", self.CMD, fail, tool_use_id=tid))
            else:
                service.post_tool_use(post("Bash", self.CMD, out or self.OUT, tool_use_id=tid))
        return responses

    def test_repeat_nudges_at_fourth_and_messages_once_at_fifth(self) -> None:
        service, audit = make_service()
        responses = self.loop(service, 6)
        self.assertEqual([kind(r) for r in responses[:3]], ["empty"] * 3)
        self.assertEqual(kind(responses[3]), "context")
        self.assertIn("attempt 4", responses[3]["hookSpecificOutput"]["additionalContext"])
        self.assertNotIn("systemMessage", responses[3])
        self.assertIn("systemMessage", responses[4])
        self.assertNotIn("systemMessage", responses[5])        # one per identity per boundary
        decisions = audit.decisions()
        self.assertEqual(decisions[3].verdict, "warn")
        self.assertEqual(decisions[3].details["response"], "empty")   # the floor's kind is recorded
        self.assertEqual(decisions[3].details["detector"]["rule_id"], "S1.repeat_same_result")
        self.assertFalse(decisions[3].details["detector"]["message_sent"])
        self.assertTrue(decisions[4].details["detector"]["message_sent"])
        self.assertEqual(decisions[4].decision.judgment.decided_by, "detector")
        self.assertEqual(decisions[4].decision.judgment.floor_verdict, "allow")
        self.assertEqual(service.sessions.get("s1").advisory_messages_sent, 1)

    def test_changed_output_is_not_a_loop(self) -> None:
        service, _ = make_service()
        for i in range(5):
            tid = f"t{i}"
            r = service.pre_tool_use(pre("Bash", self.CMD, tool_use_id=tid))
            self.assertEqual(kind(r), "empty")
            service.post_tool_use(post("Bash", self.CMD, {**self.OUT, "stdout": f"run {i}"}, tool_use_id=tid))

    def test_error_loop_fires_at_third(self) -> None:
        service, audit = make_service()
        responses = self.loop(service, 3, fail="Exit code 1\nError: no module")
        self.assertEqual(kind(responses[2]), "context")
        self.assertIn("failed each time", responses[2]["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(rows(audit, "post_execution_failure")[0].details["exit_code"], 1)
        blob = json.dumps([e.model_dump(mode="json") for e in audit.events])
        self.assertNotIn("no module", blob)
        self.assertNotIn("Exit code", blob)   # the error text itself is never stored

    def test_detector_merges_into_floor_warn_context(self) -> None:
        service, _ = make_service()
        cmd = {"command": "git reset --hard"}
        for i in range(3):
            service.pre_tool_use(pre("Bash", cmd, tool_use_id=f"t{i}"))
            service.post_tool_use(post("Bash", cmd, self.OUT, tool_use_id=f"t{i}"))
        body = service.pre_tool_use(pre("Bash", cmd, tool_use_id="t3"))
        context = body["hookSpecificOutput"]["additionalContext"]
        self.assertIn("Sentinel note", context)        # the floor's warn
        self.assertIn("attempt 4", context)            # the detector's nudge, appended
        self.assertNotIn("permissionDecision", body["hookSpecificOutput"])

    def test_floor_deny_is_untouched_by_detector(self) -> None:
        service, audit = make_service()
        cmd = {"command": "cat ~/.ssh/id_rsa"}
        bodies = [service.pre_tool_use(pre("Bash", cmd, tool_use_id=f"t{i}")) for i in range(5)]
        self.assertTrue(all(kind(b) == "deny" for b in bodies))
        self.assertTrue(all("detector" not in d.details for d in audit.decisions()))

    def test_detector_crash_leaves_floor_response_byte_identical(self) -> None:
        service, audit = make_service()
        clean = service.pre_tool_use(pre("Bash", {"command": "ls"}, tool_use_id="a"))
        with mock.patch.object(stuck, "evaluate", side_effect=RuntimeError("ring corrupted")):
            body = service.pre_tool_use(pre("Bash", {"command": "ls"}, tool_use_id="b"))
        self.assertEqual(body, clean)
        self.assertEqual(audit.decisions()[-1].details["detector"]["error"], "RuntimeError")
        self.assertIn("detector:error", audit.decisions()[-1].reason_codes)
        self.assertEqual(audit.decisions()[-1].verdict, "allow")

    def test_a_prompt_naming_a_folder_resets_nothing(self) -> None:
        # Week 18 amendment: the focus hint is per prompt; the ring and the
        # rolling budget are untouched by it (the window ages spends out).
        service, _ = make_service()
        self.loop(service, 5)                                  # nudge + one message
        self.assertEqual(service.sessions.get("s1").advisory_messages_sent, 1)
        with fs({f"{PROJ}/src": "d"}):
            service.user_prompt_submit(prompt("try again in src/"))
        session = service.sessions.get("s1")
        self.assertEqual(session.advisory_messages_sent, 1)
        self.assertNotEqual(len(session.stuck.ring), 0)
        self.assertEqual(session.current_boundary().root, PROJ)

    def test_caution_plus_stuck_message_exhaust_the_budget(self) -> None:
        service, _ = make_service()
        service.pre_tool_use(pre("Bash", {"command": "ls"}, tool_use_id="warm"))
        service.user_prompt_submit(prompt("update /Users/dev/other/a.md"))     # counted: 1
        responses = self.loop(service, 5)                                      # message at 5th: 2
        self.assertIn("systemMessage", responses[4])
        other = {"command": "make", "description": "x"}
        for i in range(5):
            service.pre_tool_use(pre("Bash", other, tool_use_id=f"m{i}"))
            service.post_tool_use(post("Bash", other, self.OUT, tool_use_id=f"m{i}"))
        body = service.pre_tool_use(pre("Bash", other, tool_use_id="m5"))
        self.assertEqual(kind(body), "context")                # still nudges
        self.assertNotIn("systemMessage", body)                # budget spent: tagged only

    def test_mixed_result_error_loop_nudges_before_it_messages(self) -> None:
        """Review #1: a success before the failures made `streak` overshoot the
        threshold on the first firing, so the person was messaged with no prior nudge."""
        service, _ = make_service()
        cmd = {"command": "make", "description": "x"}
        service.pre_tool_use(pre("Bash", cmd, tool_use_id="ok"))
        service.post_tool_use(post("Bash", cmd, self.OUT, tool_use_id="ok"))
        for i in range(2):
            service.pre_tool_use(pre("Bash", cmd, tool_use_id=f"f{i}"))
            service.post_tool_use_failure(failure("Bash", cmd, "Exit code 2\nerr", tool_use_id=f"f{i}"))
        first = service.pre_tool_use(pre("Bash", cmd, tool_use_id="f2"))
        self.assertEqual(kind(first), "context")
        self.assertNotIn("systemMessage", first)                   # nudge only
        service.post_tool_use_failure(failure("Bash", cmd, "Exit code 2\nerr", tool_use_id="f2"))
        second = service.pre_tool_use(pre("Bash", cmd, tool_use_id="f3"))
        self.assertIn("systemMessage", second)                      # second firing: one message

    def test_alternation_messages_on_its_second_firing(self) -> None:
        """Review #2: S3's streak equalled its threshold, so it could never message."""
        service, _ = make_service()
        a = {"command": "npm test", "description": "x"}
        b_in = {"file_path": f"{PROJ}/test.log"}
        bodies = []
        for i in range(8):
            if i % 2 == 0:
                bodies.append(service.pre_tool_use(pre("Bash", a, tool_use_id=f"s{i}")))
                service.post_tool_use(post("Bash", a, self.OUT, tool_use_id=f"s{i}"))
            else:
                bodies.append(service.pre_tool_use(pre("Read", b_in, tool_use_id=f"s{i}")))
                service.post_tool_use(post("Read", b_in, {"type": "text", "file": {"content": "same"}}, tool_use_id=f"s{i}"))
        self.assertEqual(kind(bodies[5]), "context")                # 6th step: first firing, nudge
        self.assertNotIn("systemMessage", bodies[5])
        self.assertIn("systemMessage", bodies[6])                   # 7th: second firing, one message
        self.assertNotIn("systemMessage", bodies[7])                # one per identity per boundary

    def test_launch_narrowing_re_anchors_a_wider_boundary(self) -> None:
        """Review #7: SessionStart may narrow launch_cwd after the boundary exists;
        the boundary must never sit outside the floor's directory."""
        service, _ = make_service()
        service.pre_tool_use(pre("Bash", {"command": "ls"}, tool_use_id="w"))
        session = service.sessions.get("s1")
        self.assertEqual(session.current_boundary().root, PROJ)
        session.advisory_messages_sent = 1
        self.assertTrue(session.narrow_launch_cwd(f"{PROJ}/sub"))
        self.assertEqual(session.current_boundary().root, f"{PROJ}/sub")
        self.assertEqual(session.advisory_messages_sent, 0)

    def test_post_execution_rows_carry_a_hash_not_the_output(self) -> None:
        service, audit = make_service()
        service.pre_tool_use(pre("Bash", self.CMD, tool_use_id="t0"))
        service.post_tool_use(post("Bash", self.CMD, {"stdout": "SECRET-OUTPUT-42", "stderr": ""}, tool_use_id="t0"))
        row = rows(audit, "post_execution")[0]
        self.assertEqual(len(row.details["result_sha256"]), 32)
        self.assertNotIn("SECRET-OUTPUT-42", json.dumps(row.model_dump(mode="json")))

    def test_floor_verdicts_unchanged_by_prompts_and_focus(self) -> None:
        """The floor never reads the boundary or the focus: incident commands decide identically."""
        incidents = ["rm -rf ~/", "rm -rf /", "cat ~/.aws/credentials", "git push --force origin main", "npm test"]
        wide, _ = make_service()
        focused, _ = make_service()
        focused.pre_tool_use(pre("Bash", {"command": "ls"}, tool_use_id="w"))
        with fs({f"{PROJ}/src": "d"}):
            focused.user_prompt_submit(prompt("work only in src/"))
        for i, cmd in enumerate(incidents):
            a = wide.pre_tool_use(pre("Bash", {"command": cmd}, tool_use_id=f"a{i}"))
            b = focused.pre_tool_use(pre("Bash", {"command": cmd}, tool_use_id=f"b{i}"))
            self.assertEqual(kind(a), kind(b), cmd)


class RollingBudget(unittest.TestCase):
    """Week 18 (gate C-H5): the budget is two messages per rolling window, not
    two per boundary lifetime. On Cursor the boundary is the workspace root for
    the whole conversation, so a lifetime budget went permanently silent."""

    CMD = {"command": "make lint", "description": "lint"}

    def _stuck_loop(self, service, n: int, *, start: int = 0) -> list[dict[str, Any]]:
        out = []
        for i in range(start, start + n):
            out.append(service.pre_tool_use(pre("Bash", self.CMD, tool_use_id=f"t{i}")))
            service.post_tool_use_failure(failure("Bash", self.CMD, "exit 1", tool_use_id=f"t{i}"))
        return out

    def test_window_refills_after_it_elapses(self) -> None:
        now = [1_000_000.0]
        service, audit = make_service(wall_clock=lambda: now[0])
        service.pre_tool_use(pre("Bash", {"command": "ls"}, tool_use_id="w"))
        for i in range(ADVISORY_MESSAGE_BUDGET):
            service.user_prompt_submit(prompt(f"update /Users/dev/other/f{i}.md"))
        self.assertTrue(rows(audit, "boundary")[-1].details["message_counted"])
        # Budget spent: a persisting stuck loop only nudges, no systemMessage.
        self._stuck_loop(service, 4)
        self.assertNotIn("systemMessage", service.pre_tool_use(pre("Bash", self.CMD, tool_use_id="t4")))
        self.assertFalse(audit.decisions()[-1].details["detector"]["message_sent"])
        # Thirty-one minutes later, same boundary, same loop: the person hears about it.
        now[0] += ADVISORY_MESSAGE_WINDOW_SECONDS + 60
        service.post_tool_use_failure(failure("Bash", self.CMD, "exit 1", tool_use_id="t4"))
        body = service.pre_tool_use(pre("Bash", self.CMD, tool_use_id="t5"))
        self.assertIn("systemMessage", body)
        self.assertTrue(audit.decisions()[-1].details["detector"]["message_sent"])
        session = service.sessions.get("s1")
        self.assertEqual(session.advisory_messages_sent, ADVISORY_MESSAGE_BUDGET + 1)   # lifetime count keeps growing
        self.assertEqual(len(session.advisory_message_times), 1)                          # window holds only the fresh one

    def test_only_spends_inside_the_window_count(self) -> None:
        session = HookSession(session_id="s", launch_cwd=PROJ, working_directory_source="launch", environment="dev")
        session.spend_advisory_message(now=0.0)
        session.spend_advisory_message(now=ADVISORY_MESSAGE_WINDOW_SECONDS - 1)
        self.assertFalse(session.advisory_budget_left(now=ADVISORY_MESSAGE_WINDOW_SECONDS - 1))
        self.assertTrue(session.advisory_budget_left(now=ADVISORY_MESSAGE_WINDOW_SECONDS + 1))   # first spend aged out
        session.spend_advisory_message(now=ADVISORY_MESSAGE_WINDOW_SECONDS + 1)
        self.assertFalse(session.advisory_budget_left(now=ADVISORY_MESSAGE_WINDOW_SECONDS + 2))
        self.assertEqual(session.advisory_messages_sent, 3)

    def test_restart_rebuild_ages_out_old_spends(self) -> None:
        from pathlib import Path
        from sentinel.hosts.claude_code.session import SessionRegistry

        service, audit = make_service()
        service.pre_tool_use(pre("Bash", {"command": "ls"}, tool_use_id="w"))
        for i in range(ADVISORY_MESSAGE_BUDGET):
            service.user_prompt_submit(prompt(f"update /Users/dev/other/f{i}.md"))
        # Backdate the counted rows by an hour, as if the restart happened later.
        hour = timedelta(hours=1)
        for row in rows(audit, "boundary"):
            if row.details.get("message_counted"):
                row.timestamp = row.timestamp - hour
        fresh = ClaudeCodeHookService(policy=FloorPolicy(), audit_store=audit, home=HOME, managed_settings=Path("/managed.json"),
                                      facts_collector=service._collect_facts, snapshot_reader=lambda p: None,
                                      sessions=SessionRegistry(audit_store=audit))
        fresh.pre_tool_use(pre("Bash", {"command": "ls"}, tool_use_id="after"))
        rebuilt = fresh.sessions.get("s1")
        self.assertEqual(rebuilt.advisory_messages_sent, ADVISORY_MESSAGE_BUDGET)   # rows still count toward the lifetime number
        self.assertTrue(rebuilt.advisory_budget_left())                             # but they are outside the window
        # Unreadable timestamps count as now: a bad row can only tighten the budget.
        self.assertGreater(_epoch("not-a-date"), 0)
        self.assertAlmostEqual(_epoch("2026-10-13T06:00:00Z"), 1_791_871_200.0, delta=1)


class Restart(unittest.TestCase):
    def test_boundary_and_budget_survive_a_restart_ring_does_not(self) -> None:
        from pathlib import Path
        from sentinel.hosts.claude_code.session import SessionRegistry

        service, audit = make_service()
        service.pre_tool_use(pre("Bash", {"command": "ls"}, tool_use_id="w"))
        with fs({f"{PROJ}/src": "d"}):
            service.user_prompt_submit(prompt("update /Users/dev/other/a.md"))   # counted: 1
            service.user_prompt_submit(prompt("work in src/"))                   # focus hint only; nothing resets
            service.user_prompt_submit(prompt("update /Users/dev/other/b.md"))   # counted: 2 (budget spent)
        cmd = {"command": "pytest", "description": "x"}
        for i in range(5):                                                       # stuck signal at the 5th: withheld, budget is 2/2
            service.pre_tool_use(pre("Bash", cmd, tool_use_id=f"t{i}"))
            service.post_tool_use(post("Bash", cmd, {"stdout": "f", "stderr": "", "interrupted": False}, tool_use_id=f"t{i}"))
        live = service.sessions.get("s1")
        self.assertEqual((live.current_boundary().root, live.advisory_messages_sent), (PROJ, 2))

        fresh = ClaudeCodeHookService(policy=FloorPolicy(), audit_store=audit, home=HOME, managed_settings=Path("/managed.json"),
                                      facts_collector=service._collect_facts, snapshot_reader=lambda p: None,
                                      sessions=SessionRegistry(audit_store=audit))
        fresh.pre_tool_use(pre("Bash", {"command": "ls"}, tool_use_id="after"))
        rebuilt = fresh.sessions.get("s1")
        self.assertEqual(rebuilt.current_boundary().root, PROJ)
        self.assertEqual(rebuilt.advisory_messages_sent, 2)
        self.assertEqual(len(rebuilt.stuck.ring), 0)
        # A tampered row naming any other root changes nothing: the boundary is the launch directory.
        audit.events.append(type(audit.events[0])(event_type="boundary", session_id="s1", agent_id="x",
                                                   details={"host": "claude_code", "focus": "/Users/dev", "boundary_root": "/Users/dev"}))
        again = ClaudeCodeHookService(policy=FloorPolicy(), audit_store=audit, home=HOME, managed_settings=Path("/managed.json"),
                                      facts_collector=service._collect_facts, snapshot_reader=lambda p: None,
                                      sessions=SessionRegistry(audit_store=audit))
        again.pre_tool_use(pre("Bash", {"command": "ls"}, tool_use_id="again"))
        self.assertEqual(again.sessions.get("s1").current_boundary().root, PROJ)


class Routes(unittest.TestCase):
    def test_new_routes_exist_and_fail_open(self) -> None:
        app = create_app()
        service = ClaudeCodeHookService(policy=FloorPolicy(), audit_store=MemoryAudit(), home=HOME,
                                        facts_collector=lambda: None, snapshot_reader=lambda p: None)  # type: ignore[arg-type]
        from sentinel.hosts.claude_code.routes import build_claude_code_router
        app.include_router(build_claude_code_router(service=service, api_host="testserver"))
        client = TestClient(app)
        r = client.post("/hooks/claude-code/user-prompt-submit", content=b"not json", headers={"host": "testserver"})
        self.assertEqual((r.status_code, r.json()), (200, {}))
        r = client.post("/hooks/claude-code/post-tool-use-failure", content=b"{", headers={"host": "testserver"})
        self.assertEqual((r.status_code, r.json()), (200, {}))

    def test_fragment_declares_both_advisory_events(self) -> None:
        hooks = managed_fragment(FloorPolicy(), python="/usr/bin/python3")["hooks"]
        self.assertIn("UserPromptSubmit", hooks)
        self.assertIn("PostToolUseFailure", hooks)
        self.assertTrue(hooks["UserPromptSubmit"][0]["hooks"][0]["url"].endswith("/user-prompt-submit"))


if __name__ == "__main__":
    unittest.main()
