"""Week 18 step D: `CursorHookService` and its routes.

docs/Week 18 Plan.md §7 "Session" and "Translation" (route-level parts).
Payloads are the shapes Cursor 3.24.12 sent in the spike, with the two
fields the forwarder adds.
"""

from __future__ import annotations

import json
import logging
import unittest
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from sentinel.api.main import create_app
from sentinel.hosts.cursor.service import CursorHookService
from sentinel.hosts.cursor.translate import response_kind
from sentinel.supervision.floor_policy import FloorPolicy
from test_claude_code_adapter import HOME, MemoryAudit

ROOT = "/Users/owen/proj"
SID = "e6acc81b-be31-4c95-bd74-82c0c172f4e0"
HOOKS_TEXT = json.dumps({"version": 1, "hooks": {"preToolUse": [{"command": "/usr/bin/python3 /Users/owen/.cursor/hooks/sentinel_forward.py"}]}})


def make_service(audit: MemoryAudit | None = None, *, hooks_text: str | None = HOOKS_TEXT, policy: FloorPolicy | None = None):
    audit = audit if audit is not None else MemoryAudit()
    service = CursorHookService(policy=policy or FloorPolicy(), audit_store=audit, home=HOME,
                                hooks_file=Path("/Users/owen/.cursor/hooks.json"), hooks_file_reader=lambda p: hooks_text)
    return service, audit


def event(name: str, *, session: str = SID, roots: list[str] | None = None, launch_dir: str | None = ROOT, **fields: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"conversation_id": session, "session_id": session, "hook_event_name": name, "cursor_version": "3.24.12",
                            "workspace_roots": [ROOT] if roots is None else roots, "user_email": "someone@example.com",
                            "transcript_path": "/x", "cwd": "", "forwarder_ms": 4.0}
    if launch_dir is not None:
        body["launch_dir"] = launch_dir
    body.update(fields)
    return body


def shell(command: str, *, tool_use_id: str = "t1", **extra: Any) -> dict[str, Any]:
    return event("preToolUse", tool_name="Shell", tool_input={"command": command, "cwd": "", "timeout": 30000},
                 tool_use_id=tool_use_id, **extra)


def before_shell(command: str, *, tool_use_id: str = "t1", **extra: Any) -> dict[str, Any]:
    """The `beforeShellExecution` payload Cursor sends ~80 ms after `preToolUse`
    for the same call (spike C2): command at top level, same `tool_use_id`."""
    return event("beforeShellExecution", command=command, sandbox=False, tool_use_id=tool_use_id, **extra)


def shell_pair(service: CursorHookService, command: str, *, tool_use_id: str = "t1", **extra: Any) -> tuple[dict, dict]:
    """Both gating events for one shell call, in Cursor's order."""
    pre = service.handle("preToolUse", shell(command, tool_use_id=tool_use_id, **extra))
    before = service.handle("beforeShellExecution", before_shell(command, tool_use_id=tool_use_id, **extra))
    return pre, before


def rows(audit: MemoryAudit, event_type: str):
    return [e for e in audit.events if e.event_type == event_type]


class Sessions(unittest.TestCase):
    def test_first_event_creates_the_session_at_the_workspace_root(self) -> None:
        service, audit = make_service()
        out = service.handle("preToolUse", shell("ls"))
        self.assertEqual(out, {})
        session = service.sessions.get(SID)
        self.assertEqual((session.launch_cwd, session.working_directory_source), (ROOT, "cursor_workspace_root"))
        self.assertEqual(rows(audit, "session_start")[0].details["first_event"], "preToolUse")
        decision = rows(audit, "decision")[-1]
        self.assertEqual(decision.details["working_directory_source"], "cursor_workspace_root")
        self.assertEqual(decision.details["host"], "cursor")
        self.assertEqual(decision.decision.action.working_directory, ROOT)

    def test_forwarder_cwd_inside_root_is_used_and_labelled(self) -> None:
        service, _ = make_service()
        service.handle("preToolUse", shell("ls", launch_dir=f"{ROOT}/pkg"))
        session = service.sessions.get(SID)
        self.assertEqual((session.launch_cwd, session.working_directory_source), (f"{ROOT}/pkg", "cursor_forwarder"))

    def test_launch_dir_outside_every_root_is_replaced_by_the_root(self) -> None:
        service, _ = make_service()
        for bad in ["/", "/Users/owen", "/Users/owen/proj-sibling", f"{ROOT}/../other"]:
            with self.subTest(bad=bad):
                sid = f"s-{bad}"
                service.handle("preToolUse", shell("ls", session=sid, launch_dir=bad))
                self.assertEqual(service.sessions.get(sid).launch_cwd, ROOT)
                self.assertEqual(service.sessions.get(sid).working_directory_source, "cursor_workspace_root")

    def test_later_events_narrow_but_never_widen(self) -> None:
        service, audit = make_service()
        service.handle("preToolUse", shell("ls"))
        service.handle("preToolUse", shell("ls", tool_use_id="t2", launch_dir=f"{ROOT}/sub"))
        self.assertEqual(service.sessions.get(SID).launch_cwd, f"{ROOT}/sub")
        service.handle("preToolUse", shell("ls", tool_use_id="t3", launch_dir=ROOT, roots=[ROOT]))
        self.assertEqual(service.sessions.get(SID).launch_cwd, f"{ROOT}/sub")
        rejected = [r for r in rows(audit, "session_start") if "rejected_widening_to" in r.details]
        self.assertEqual(rejected[-1].details["rejected_widening_to"], ROOT)

    def test_forged_root_elsewhere_cannot_move_an_existing_session(self) -> None:
        service, _ = make_service()
        service.handle("preToolUse", shell("ls"))
        service.handle("preToolUse", shell("ls", tool_use_id="t2", roots=["/"], launch_dir="/"))
        self.assertEqual(service.sessions.get(SID).launch_cwd, ROOT)

    def test_no_roots_and_no_launch_dir_denies_gating_and_passes_prompts(self) -> None:
        service, audit = make_service()
        out = service.handle("preToolUse", shell("ls", roots=[], launch_dir=None))
        self.assertEqual(response_kind(out), "deny")
        self.assertIn("project directory", out["user_message"])
        self.assertEqual(rows(audit, "decision")[-1].reason_codes, ["adapter:no_launch_dir"])
        self.assertIsNone(service.sessions.get(SID))
        out = service.handle("beforeSubmitPrompt", event("beforeSubmitPrompt", prompt="hi", roots=[], launch_dir=None))
        self.assertEqual(out, {"continue": True})

    def test_no_roots_uses_forwarder_cwd(self) -> None:
        service, _ = make_service()
        service.handle("preToolUse", shell("ls", roots=[], launch_dir="/Users/owen/scratch"))
        self.assertEqual(service.sessions.get(SID).launch_cwd, "/Users/owen/scratch")

    def test_two_conversations_are_two_sessions(self) -> None:
        service, _ = make_service()
        service.handle("preToolUse", shell("ls", session="a"))
        service.handle("preToolUse", shell("ls", session="b", launch_dir=f"{ROOT}/b"))
        self.assertEqual(service.sessions.get("a").launch_cwd, ROOT)
        self.assertEqual(service.sessions.get("b").launch_cwd, f"{ROOT}/b")

    def test_missing_conversation_id(self) -> None:
        service, _ = make_service()
        body = shell("ls")
        del body["conversation_id"]
        del body["session_id"]
        self.assertEqual(response_kind(service.handle("preToolUse", body)), "deny")
        body = event("postToolUse", tool_name="Shell", tool_input={"command": "ls"}, tool_output="{}", tool_use_id="t1")
        del body["conversation_id"]
        del body["session_id"]
        self.assertEqual(service.handle("postToolUse", body), {})


class Decisions(unittest.TestCase):
    def test_floor_block_is_a_cursor_deny_with_reason_and_doctor(self) -> None:
        service, audit = make_service()
        out = service.handle("preToolUse", shell("cat ~/.ssh/id_ed25519"))
        self.assertEqual(out["permission"], "deny")
        self.assertIn("credential", out["user_message"].lower())
        self.assertIn("sentinel cursor doctor", out["user_message"])    # advisory enforcement, folded in
        self.assertNotIn("claude", out["user_message"].lower())
        row = rows(audit, "decision")[-1]
        self.assertEqual((row.verdict, row.details["enforcement"]), ("block", "advisory"))
        self.assertEqual(row.details["enforcement_failed"], ["hooks_file_user_writable"])

    def test_missing_hooks_file_is_unsupported(self) -> None:
        service, audit = make_service(hooks_text=None)
        service.handle("preToolUse", shell("ls"))
        self.assertEqual(rows(audit, "decision")[-1].details["enforcement"], "unsupported")

    def test_delete_tool_three_ways(self) -> None:
        service, audit = make_service()
        # `~/Desktop/x` is `confirm_required`, like `rm -rf ~/Desktop/x`: one file
        # outside the project is destructive-but-possibly-authorised, not a block.
        # Cursor has no event that can ask for a file tool (spike C2), so the
        # confirm is delivered as a deny with guidance; the row keeps the verdict.
        cases = [(f"{ROOT}/build/x", "empty", None, "allow"),
                 ("/Users/owen/other-repo/x", "deny", "F5.destructive_outside", "confirm_required"),
                 (f"{HOME}/Desktop/x", "deny", "F5.destructive_outside", "confirm_required"),
                 (f"{HOME}/.zshrc", "deny", "F1.delete_home", "block")]
        for i, (path, want, rule, verdict) in enumerate(cases):
            with self.subTest(path=path):
                out = service.handle("preToolUse", event("preToolUse", tool_name="Delete", tool_input={"path": path}, tool_use_id=f"d{i}"))
                self.assertEqual(response_kind(out), want)
                row = rows(audit, "decision")[-1]
                self.assertEqual((row.decision.judgment.rule_id, row.verdict), (rule, verdict))
                if verdict == "confirm_required":
                    self.assertIn("Ask the user in chat", out["user_message"])
                    self.assertIn("Delete tool", out["user_message"])
                    self.assertEqual(row.details["response"], "deny")
        self.assertEqual(service.sessions.get(SID).pending_asks, {})
        self.assertEqual(list(service.sessions.get(SID).asked_tool_use_ids), [])

    def test_hooks_file_write_blocks(self) -> None:
        service, audit = make_service()
        out = service.handle("preToolUse", event("preToolUse", tool_name="StrReplace", tool_use_id="w1",
                                                 tool_input={"path": "/Users/owen/.cursor/hooks.json", "old_string": "a", "new_string": "b"}))
        self.assertEqual(response_kind(out), "deny")
        self.assertEqual(rows(audit, "decision")[-1].decision.judgment.rule_id, "F1.write_protected_config")

    def test_apply_patch_without_headers_confirms_as_deny_with_guidance(self) -> None:
        """A patch whose file headers cannot be read stays the opaque-write
        confirm, delivered on Cursor as a deny with chat guidance (no event
        can show an ask for ApplyPatch)."""
        service, audit = make_service()
        out = service.handle("preToolUse", event("preToolUse", tool_name="ApplyPatch", tool_input="*** Begin Patch", tool_use_id="p1"))
        self.assertEqual(response_kind(out), "deny")
        self.assertIn("Ask the user in chat", out["user_message"])
        row = rows(audit, "decision")[-1]
        self.assertEqual((row.decision.judgment.rule_id, row.verdict, row.details["response"]),
                         ("F5.opaque_write", "confirm_required", "deny"))

    def test_apply_patch_in_repo_update_allows(self) -> None:
        """Week 19 item 1: the 1,759-patch corpus case. An in-repo edit is
        ordinary work and gets the same answer Write gets for that path."""
        service, audit = make_service()
        patch = f"*** Begin Patch\n*** Update File: {ROOT}/src/app.py\n@@\n-old\n+new\n*** End Patch\n"
        out = service.handle("preToolUse", event("preToolUse", tool_name="ApplyPatch", tool_input=patch, tool_use_id="p2"))
        self.assertEqual(response_kind(out), "empty")
        row = rows(audit, "decision")[-1]
        self.assertEqual((row.verdict, row.decision.judgment.rule_id), ("allow", None))
        self.assertEqual([t.filesystem.zone for t in row.decision.action.targets], ["inside"])
        self.assertNotIn("old", json.dumps(row.details))   # the body is never recorded

    def test_apply_patch_add_under_ssh_blocks(self) -> None:
        service, audit = make_service()
        patch = f"*** Begin Patch\n*** Add File: {HOME}/.ssh/authorized_keys\n+ssh-ed25519 AAAA\n*** End Patch\n"
        out = service.handle("preToolUse", event("preToolUse", tool_name="ApplyPatch", tool_input=patch, tool_use_id="p3"))
        self.assertEqual(response_kind(out), "deny")
        self.assertIn("credential store", out["user_message"])
        row = rows(audit, "decision")[-1]
        self.assertEqual((row.verdict, row.decision.judgment.rule_id), ("block", "F1.write_credential"))
        self.assertNotIn("AAAA", json.dumps(row.details))

    def test_apply_patch_delete_outside_repo_confirms(self) -> None:
        service, audit = make_service()
        patch = f"*** Begin Patch\n*** Delete File: {HOME}/other-repo/notes.txt\n*** End Patch\n"
        out = service.handle("preToolUse", event("preToolUse", tool_name="ApplyPatch", tool_input=patch, tool_use_id="p4"))
        self.assertEqual(response_kind(out), "deny")             # confirm with no capable event → deny + guidance
        self.assertIn("Ask the user in chat", out["user_message"])
        row = rows(audit, "decision")[-1]
        self.assertEqual((row.verdict, row.decision.judgment.rule_id, row.details["response"]),
                         ("confirm_required", "F5.destructive_outside", "deny"))

    def test_apply_patch_mixed_most_severe_wins(self) -> None:
        service, audit = make_service()
        patch = (f"*** Begin Patch\n*** Update File: {ROOT}/src/app.py\n@@\n-a\n+b\n"
                 f"*** Delete File: {HOME}/other-repo/notes.txt\n"
                 f"*** Update File: {HOME}/.cursor/hooks.json\n@@\n-x\n+y\n*** End Patch\n")
        out = service.handle("preToolUse", event("preToolUse", tool_name="ApplyPatch", tool_input=patch, tool_use_id="p5"))
        self.assertEqual(response_kind(out), "deny")
        self.assertIn("names 3 files", out["user_message"])
        row = rows(audit, "decision")[-1]
        self.assertEqual((row.verdict, row.decision.judgment.rule_id), ("block", "F1.write_protected_config"))
        self.assertEqual([t.filesystem.zone for t in row.decision.action.targets], ["inside", "outside", "protected_config"])

    def test_apply_patch_relative_path_resolves_against_the_session_root(self) -> None:
        """A relative header joins the server-owned launch directory, as a
        relative Write path does; it never widens to anything the payload says."""
        service, audit = make_service()
        patch = "*** Begin Patch\n*** Update File: src/app.py\n@@\n-a\n+b\n*** End Patch\n"
        out = service.handle("preToolUse", event("preToolUse", tool_name="ApplyPatch", tool_input=patch, tool_use_id="p6"))
        self.assertEqual(response_kind(out), "empty")
        self.assertEqual(rows(audit, "decision")[-1].decision.action.targets[0].filesystem.resolved, f"{ROOT}/src/app.py")

    def test_shell_confirm_is_deferred_to_before_shell_execution(self) -> None:
        """Spike C2: `preToolUse` answers with context only; the `ask` goes out
        on `beforeShellExecution` for the same id, once, with the reason."""
        service, audit = make_service()
        pre, before = shell_pair(service, "rm -rf /Users/owen/other-repo/build", tool_use_id="c1")
        self.assertEqual(response_kind(pre), "context")
        self.assertIn("being asked", pre["additional_context"])
        self.assertEqual(response_kind(before), "ask")
        self.assertIn("Sentinel:", before["user_message"])
        self.assertIn("outside the working directory", before["user_message"])
        decisions = [r for r in rows(audit, "decision") if r.request_id == "c1"]
        self.assertEqual(len(decisions), 1)                                  # judged once
        self.assertEqual((decisions[0].verdict, decisions[0].details["response"]), ("confirm_required", "ask"))
        self.assertEqual(rows(audit, "ask_delivered")[-1].request_id, "c1")
        self.assertEqual(service.sessions.get(SID).pending_asks, {})
        # A second beforeShellExecution for the same id (never seen live) adds nothing.
        self.assertEqual(service.handle("beforeShellExecution", before_shell("rm -rf /Users/owen/other-repo/build", tool_use_id="c1")), {})
        post = service.handle("postToolUse", event("postToolUse", tool_name="Shell", tool_use_id="c1", duration=5.0,
                                                   tool_input={"command": "rm -rf /Users/owen/other-repo/build"},
                                                   tool_output=json.dumps({"output": "", "exitCode": 0})))
        self.assertEqual(post, {})
        self.assertTrue(rows(audit, "post_execution")[-1].details["was_asked"])
        self.assertFalse(rows(audit, "ask_undelivered"))

    def test_held_confirm_lost_to_a_restart_is_rejudged_not_passed(self) -> None:
        """Review finding (October 15): a confirm held on `preToolUse` lives only
        in memory. If the process restarts before `beforeShellExecution`
        arrives, the rebuilt session must re-judge the call (and ask), not
        treat the remembered id as already answered and return `{}`."""
        audit = MemoryAudit()
        first, _ = make_service(audit)
        pre = first.handle("preToolUse", shell("rm -rf /Users/owen/other-repo/build", tool_use_id="c1"))
        self.assertEqual(response_kind(pre), "context")
        # New process, same store: pre_tool_use_ids is rebuilt from rows, the held ask is not.
        second, _ = make_service(audit)
        before = second.handle("beforeShellExecution", before_shell("rm -rf /Users/owen/other-repo/build", tool_use_id="c1"))
        self.assertEqual(response_kind(before), "ask")
        self.assertIn("outside the working directory", before["user_message"])

    def test_before_shell_execution_for_a_judged_allow_adds_nothing(self) -> None:
        service, audit = make_service()
        pre, before = shell_pair(service, "ls", tool_use_id="a1")
        self.assertEqual((pre, before), ({}, {}))
        self.assertEqual(len([r for r in rows(audit, "decision") if r.request_id == "a1"]), 1)

    def test_before_shell_execution_alone_is_judged(self) -> None:
        """A host where `preToolUse` did not fire: the capable event judges the
        command itself, so block stays deny and confirm is a real ask."""
        service, audit = make_service()
        out = service.handle("beforeShellExecution", before_shell("cat ~/.ssh/id_ed25519", tool_use_id="s1"))
        self.assertEqual(response_kind(out), "deny")
        self.assertEqual(rows(audit, "decision")[-1].decision.judgment.rule_id, "F3.credential_read")
        out = service.handle("beforeShellExecution", before_shell("rm -rf /Users/owen/other-repo/build", tool_use_id="s2"))
        self.assertEqual(response_kind(out), "ask")
        self.assertEqual(rows(audit, "decision")[-1].decision.action.tool, "Bash")
        self.assertEqual(service.handle("beforeShellExecution", before_shell("ls", tool_use_id="s3")), {})

    def test_undelivered_ask_is_recorded_when_the_call_finishes(self) -> None:
        service, audit = make_service()
        pre = service.handle("preToolUse", shell("rm -rf /Users/owen/other-repo/build", tool_use_id="u1"))
        self.assertEqual(response_kind(pre), "context")
        service.handle("postToolUse", event("postToolUse", tool_name="Shell", tool_use_id="u1", duration=5.0,
                                            tool_input={"command": "rm -rf /Users/owen/other-repo/build"},
                                            tool_output=json.dumps({"output": "", "exitCode": 0})))
        self.assertEqual(rows(audit, "ask_undelivered")[-1].request_id, "u1")
        self.assertEqual(service.sessions.get(SID).pending_asks, {})

    def test_before_shell_execution_fails_closed(self) -> None:
        service, _ = make_service()
        self.assertEqual(response_kind(service.handle("beforeShellExecution", {"hook_event_name": "beforeShellExecution"})), "deny")
        self.assertEqual(response_kind(service.handle("beforeShellExecution", before_shell("ls", roots=[], launch_dir=None))), "deny")
        self.assertEqual(response_kind(service.handle("beforeShellExecution", "garbage")), "deny")

    def test_shell_working_directory_moves_the_floor_cwd(self) -> None:
        service, audit = make_service()
        out = service.handle("preToolUse", event("preToolUse", tool_name="Shell", tool_use_id="c1",
                                                 tool_input={"command": "rm -rf build", "working_directory": "/Users/owen/other"}))
        self.assertEqual(response_kind(out), "context")   # outside the launch directory: confirm, held for beforeShellExecution
        self.assertEqual(rows(audit, "decision")[-1].decision.judgment.rule_id, "F5.destructive_outside")
        self.assertEqual(service.sessions.get(SID).pending_asks.keys(), {"c1"})

    def test_prompt_tells_the_boundary_and_does_not_move_it(self) -> None:
        service, audit = make_service()
        service.handle("preToolUse", shell("ls"))
        out = service.handle("beforeSubmitPrompt", event("beforeSubmitPrompt", prompt="fix the handler in src/api"))
        self.assertTrue(out["continue"])
        self.assertIn("Sentinel boundary:", out["additional_context"])
        row = rows(audit, "boundary")[-1]
        self.assertEqual(row.details["host"], "cursor")
        self.assertNotIn("fix the handler", json.dumps(row.model_dump(mode="json")))
        self.assertEqual(service.sessions.get(SID).current_boundary().root, service.sessions.get(SID).launch_cwd)

    def test_mcp_confirm_is_delivered_on_before_mcp_execution(self) -> None:
        """`preToolUse` (as `MCP:<tool>`) judges; `beforeMCPExecution`, the
        ask-capable event, carries the confirm (spike C2). One decision row."""
        service, audit = make_service()
        pre = service.handle("preToolUse", event("preToolUse", tool_name="MCP:read_file", tool_use_id="m1",
                                                 tool_input={"path": "/etc/passwd"}))
        self.assertEqual(response_kind(pre), "context")   # F5.mcp_path_outside, held
        before = service.handle("beforeMCPExecution", event("beforeMCPExecution", tool_name="read_file", tool_use_id="m1",
                                                            tool_input=json.dumps({"path": "/etc/passwd"}),
                                                            mcp_server_name="fs", mcp_server_url="http://x"))
        self.assertEqual(response_kind(before), "ask")
        self.assertEqual(len([r for r in rows(audit, "decision") if r.request_id == "m1"]), 1)
        self.assertEqual(rows(audit, "ask_delivered")[-1].details["hook_event"], "beforeMCPExecution")

    def test_mcp_dedupe_between_pre_tool_use_and_before_mcp_execution(self) -> None:
        service, audit = make_service()
        pre = service.handle("preToolUse", event("preToolUse", tool_name="MCP:read_file", tool_use_id="m1",
                                                 tool_input={"path": f"{ROOT}/README.md"}))
        self.assertEqual(pre, {})
        before = service.handle("beforeMCPExecution", event("beforeMCPExecution", tool_name="read_file", tool_use_id="m1",
                                                            tool_input=json.dumps({"path": f"{ROOT}/README.md"}),
                                                            mcp_server_name="fs", mcp_server_url="http://x"))
        self.assertEqual(before, {})
        self.assertEqual(len([r for r in rows(audit, "decision") if r.request_id == "m1"]), 1)
        self.assertEqual(rows(audit, "mcp_execution")[-1].details["server"], "fs")

    def test_before_mcp_execution_alone_is_judged(self) -> None:
        service, audit = make_service()
        out = service.handle("beforeMCPExecution", event("beforeMCPExecution", tool_name="read_file", tool_use_id="m2",
                                                         tool_input=json.dumps({"path": "/etc/passwd"}), mcp_server_name="fs"))
        self.assertEqual(response_kind(out), "ask")
        self.assertEqual(rows(audit, "decision")[-1].decision.action.tool, "mcp__fs__read_file")

    def test_call_dynamic_tool_confirm_is_a_deny_not_a_held_ask(self) -> None:
        """`CallDynamicTool` translates to `mcp__*` like the verified `MCP:`
        shape, but no spike has shown `beforeMCPExecution` follows it. Holding
        the ask would be fail-open (review M1), so the shared service denies
        with guidance and the row records `response: deny`, not `ask`."""
        service, audit = make_service()
        for host_tool, tool_input in (("CallDynamicTool", {"namespace": "fs", "toolName": "read_file", "arguments": {"path": "/etc/passwd"}}),
                                      ("CallMcpTool", {"server": "fs", "toolName": "read_file", "arguments": {"path": "/etc/passwd"}})):
            out = service.handle("preToolUse", event("preToolUse", tool_name=host_tool, tool_use_id=f"d-{host_tool}",
                                                     tool_input=tool_input))
            self.assertEqual(response_kind(out), "deny", host_tool)
            self.assertIn("Ask the user in chat", out["user_message"])
            row = [r for r in rows(audit, "decision") if r.request_id == f"d-{host_tool}"][-1]
            self.assertEqual((row.verdict, row.details["response"]), ("confirm_required", "deny"))
            self.assertEqual(row.decision.action.tool, "mcp__fs__read_file")
            # Nothing is held: a later capable event for this id has nothing to deliver and re-judges nothing.
            self.assertEqual(service.sessions.get(SID).pending_asks, {})
        self.assertEqual(rows(audit, "ask_delivered"), [])

    def test_before_mcp_execution_without_server_name_is_judged_as_mcp(self) -> None:
        service, audit = make_service()
        out = service.handle("beforeMCPExecution", event("beforeMCPExecution", tool_name="Read", tool_use_id="m3",
                                                         tool_input=json.dumps({"path": "/etc/passwd"})))
        self.assertEqual(response_kind(out), "ask")   # F5.mcp_path_outside on the capable event, not the built-in Read allow
        row = rows(audit, "decision")[-1]
        self.assertEqual((row.decision.action.tool, row.decision.judgment.rule_id), ("mcp__unknown__Read", "F5.mcp_path_outside"))

    def test_empty_tool_use_id_is_no_id(self) -> None:
        """Cursor sends `tool_use_id: ""` on some subagent reads and host-internal
        writes (live, October 14: 83 rows). It must behave exactly like a
        missing id: no orphan tag, no entry in the id rings, nothing deferred."""
        service, audit = make_service()
        pre = service.handle("preToolUse", event("preToolUse", tool_name="Read", tool_use_id="",
                                                 tool_input={"path": f"{ROOT}/README.md"}, parent_tool_call_id="p1"))
        self.assertEqual(pre, {})
        self.assertIsNone(rows(audit, "decision")[-1].request_id)
        self.assertNotIn("", service.sessions.get(SID).pre_tool_use_ids)
        post = service.handle("postToolUse", event("postToolUse", tool_name="Read", tool_use_id="",
                                                   tool_input={"path": f"{ROOT}/README.md"}, tool_output="x", duration=1.0))
        self.assertEqual(post, {})
        self.assertFalse(rows(audit, "post_execution")[-1].details["orphan"])
        # A confirm with no id cannot be held, so it is delivered as a deny rather than lost.
        out = service.handle("preToolUse", event("preToolUse", tool_name="Shell", tool_use_id="",
                                                 tool_input={"command": "rm -rf ~/Desktop/x", "cwd": "", "timeout": 1}))
        self.assertEqual(response_kind(out), "deny")
        self.assertEqual(service.sessions.get(SID).pending_asks, {})

    def test_stuck_loop_nudges_then_asks_once(self) -> None:
        """The nudge is context on `preToolUse`; the one budgeted popup is held
        there and delivered as `ask` on `beforeShellExecution` (spike C2)."""
        service, audit = make_service()
        pre_kinds, before_kinds = [], []
        for i in range(1, 8):
            tid = f"l{i}"
            pre, before = shell_pair(service, "make lint", tool_use_id=tid)
            pre_kinds.append(response_kind(pre))
            before_kinds.append(response_kind(before))
            service.handle("postToolUse", event("postToolUse", tool_name="Shell", tool_use_id=tid, duration=10.0,
                                                tool_input={"command": "make lint", "cwd": "", "timeout": 30000},
                                                tool_output=json.dumps({"output": "lint: error E1\n", "exitCode": 2})))
        self.assertIn("context", pre_kinds)
        self.assertNotIn("ask", pre_kinds)                               # never on the event Cursor ignores
        self.assertEqual(before_kinds.count("ask"), 1, before_kinds)
        self.assertLess(pre_kinds.index("context"), before_kinds.index("ask"))
        asked = [r for r in rows(audit, "decision") if (r.details.get("detector") or {}).get("delivered") == "ask"]
        self.assertEqual(len(asked), 1)
        self.assertEqual(rows(audit, "ask_delivered")[-1].request_id, asked[0].request_id)
        self.assertFalse(rows(audit, "ask_undelivered"))
        # Non-zero exit went down the failure path, like Claude Code's PostToolUseFailure.
        self.assertTrue(rows(audit, "post_execution_failure"))
        self.assertEqual(rows(audit, "post_execution_failure")[0].details["exit_code"], 2)

    def test_await_shell_between_retries_does_not_break_the_streak(self) -> None:
        """`make lint` fails, `AwaitShell` polls, `make lint` fails... S2 must
        fire at the third `make lint`; without the exemption the ring would be
        L A L A L and S3.alternation would fire instead (review L5)."""
        service, audit = make_service()
        rules: list[str | None] = []
        for i in range(1, 5):
            service.handle("preToolUse", shell("make lint", tool_use_id=f"l{i}"))
            row = rows(audit, "decision")[-1]
            rules.append((row.details.get("detector") or {}).get("rule_id"))
            service.handle("postToolUse", event("postToolUse", tool_name="Shell", tool_use_id=f"l{i}",
                                                tool_input={"command": "make lint"}, tool_output=json.dumps({"output": "x", "exitCode": 1})))
            service.handle("preToolUse", event("preToolUse", tool_name="AwaitShell", tool_use_id=f"a{i}", tool_input={"shell_id": "1"}))
            service.handle("postToolUse", event("postToolUse", tool_name="AwaitShell", tool_use_id=f"a{i}",
                                                tool_input={"shell_id": "1"}, tool_output="done"))
        self.assertEqual(rules[2], "S2.repeat_error", rules)
        self.assertNotIn("S3.alternation", rules)

    def test_read_polling_gets_a_nudge_but_never_the_popup(self) -> None:
        """The spike log had 34 identical terminal-file reads (review M4). On
        Cursor the popup is reserved for shell retries."""
        service, audit = make_service()
        kinds = []
        for i in range(1, 12):
            tid = f"r{i}"
            out = service.handle("preToolUse", event("preToolUse", tool_name="Read", tool_use_id=tid,
                                                     tool_input={"file_path": f"{ROOT}/terminals/1.txt"}))
            kinds.append(response_kind(out))
            service.handle("postToolUse", event("postToolUse", tool_name="Read", tool_use_id=tid,
                                                tool_input={"file_path": f"{ROOT}/terminals/1.txt"},
                                                tool_output=json.dumps({"file_path": f"{ROOT}/terminals/1.txt", "content_length": 213})))
        self.assertIn("context", kinds)
        self.assertNotIn("ask", kinds)
        self.assertEqual(service.sessions.get(SID).advisory_messages_sent, 0)
        withheld = [r for r in rows(audit, "decision") if (r.details.get("detector") or {}).get("popup_withheld")]
        self.assertTrue(withheld)

    def test_environment_is_rederived_when_the_launch_dir_narrows(self) -> None:
        """Review B1: a wide first event (`/`) must not pin `dev` on a session
        whose real root is a production repository."""
        policy = FloorPolicy(environments={ROOT: "production"})
        service, audit = make_service(policy=policy)
        service.handle("postToolUse", event("postToolUse", tool_name="Shell", tool_use_id="x0", roots=["/"], launch_dir="/",
                                            tool_input={"command": "ls"}, tool_output="{}"))
        self.assertEqual(service.sessions.get(SID).environment, "dev")
        out = service.handle("preToolUse", shell("alembic upgrade head", tool_use_id="x1"))
        session = service.sessions.get(SID)
        self.assertEqual((session.launch_cwd, session.environment, session.current_boundary().environment), (ROOT, "production", "production"))
        self.assertEqual(response_kind(out), "context")    # confirm, held for beforeShellExecution
        self.assertEqual(rows(audit, "decision")[-1].decision.judgment.rule_id, "F8.schema_change_prod")
        self.assertEqual(rows(audit, "decision")[-1].environment, "production")
        self.assertEqual(response_kind(service.handle("beforeShellExecution", before_shell("alembic upgrade head", tool_use_id="x1"))), "ask")

    def test_shell_relative_and_tilde_working_directory_resolve(self) -> None:
        service, audit = make_service()
        out = service.handle("preToolUse", event("preToolUse", tool_name="Shell", tool_use_id="w1",
                                                 tool_input={"command": "rm -rf build", "working_directory": "../other"}))
        self.assertEqual(response_kind(out), "context")    # confirm, held
        self.assertEqual(rows(audit, "decision")[-1].decision.judgment.rule_id, "F5.destructive_outside")
        out = service.handle("preToolUse", event("preToolUse", tool_name="Shell", tool_use_id="w2",
                                                 tool_input={"command": "echo x > hooks.json", "working_directory": "~/.cursor"}))
        self.assertEqual(response_kind(out), "deny")
        self.assertEqual(rows(audit, "decision")[-1].decision.judgment.rule_id, "F1.write_protected_config")
        out = service.handle("preToolUse", event("preToolUse", tool_name="Shell", tool_use_id="w3",
                                                 tool_input={"command": "rm -rf build", "working_directory": "pkg"}))
        self.assertEqual(response_kind(out), "empty")

    def test_project_mcp_json_is_protected(self) -> None:
        service, audit = make_service()
        out = service.handle("preToolUse", event("preToolUse", tool_name="Write", tool_use_id="m1",
                                                 tool_input={"path": f"{ROOT}/.cursor/mcp.json", "contents": "{}"}))
        self.assertEqual(response_kind(out), "deny")
        self.assertEqual(rows(audit, "decision")[-1].decision.judgment.rule_id, "F1.write_protected_config")

    def test_mcp_tool_named_like_a_builtin_is_judged_as_mcp(self) -> None:
        service, audit = make_service()
        out = service.handle("beforeMCPExecution", event("beforeMCPExecution", tool_name="Grep", tool_use_id="g1",
                                                         tool_input=json.dumps({"path": "/etc"}), mcp_server_name="fs"))
        self.assertEqual(response_kind(out), "ask")
        self.assertEqual(rows(audit, "decision")[-1].decision.action.tool, "mcp__fs__Grep")

    def test_widening_rejection_is_logged_once(self) -> None:
        service, audit = make_service()
        service.handle("preToolUse", shell("ls"))
        for i in range(3):
            service.handle("preToolUse", shell("ls", tool_use_id=f"w{i}", roots=["/"], launch_dir="/"))
        rejected = [r for r in rows(audit, "session_start") if "rejected_widening_to" in r.details]
        self.assertEqual(len(rejected), 1)

    def test_timing_row(self) -> None:
        service, audit = make_service()
        service.handle("preToolUse", shell("ls"))
        timing = rows(audit, "hook_timing")[-1]
        self.assertEqual(timing.details["forwarder_ms"], 4.0)
        self.assertIn("server_ms", timing.details)


class FailClosedSplit(unittest.TestCase):
    def test_unreadable_payload(self) -> None:
        service, audit = make_service()
        with self.assertLogs("sentinel.hosts.cursor", level=logging.WARNING) as captured:
            out = service.handle("preToolUse", {"hook_event_name": "preToolUse", "user_email": "secret@x", "tool_input": {"command": "secret-cmd"},
                                                "prompt": "secret prompt", "workspace_roots": "not-a-list"})
        self.assertEqual(response_kind(out), "deny")
        joined = "\n".join(captured.output)
        for secret in ("secret@x", "secret-cmd", "secret prompt"):
            self.assertNotIn(secret, joined)
        self.assertEqual(rows(audit, "decision")[-1].reason_codes, ["adapter:invalid_payload"])
        self.assertEqual(service.handle("postToolUse", {"hook_event_name": "postToolUse", "workspace_roots": 5}), {})
        self.assertEqual(service.handle("beforeSubmitPrompt", {"hook_event_name": "beforeSubmitPrompt", "workspace_roots": 5}), {"continue": True})

    def test_event_name_mismatch(self) -> None:
        service, _ = make_service()
        body = shell("ls")
        body["hook_event_name"] = "postToolUse"
        self.assertEqual(response_kind(service.handle("preToolUse", body)), "deny")

    def test_unknown_event_passes(self) -> None:
        service, _ = make_service()
        self.assertEqual(service.handle("subagentStart", {"hook_event_name": "subagentStart"}), {})

    def test_audit_write_failure_denies_pre_tool_use(self) -> None:
        audit = MemoryAudit()
        service, _ = make_service(audit)

        def boom(_event):
            raise RuntimeError("disk full")
        audit.write_required = boom  # type: ignore[assignment]
        out = service.handle("preToolUse", shell("ls"))
        self.assertEqual(response_kind(out), "deny")
        self.assertIn("audit", out["user_message"].lower())


class Routes(unittest.TestCase):
    def setUp(self) -> None:
        self.service, self.audit = make_service()
        app = create_app(audit_store=self.audit, cursor_service=self.service, hook_api_host="127.0.0.1:8000", load_policy=False)
        self.client = TestClient(app, base_url="http://127.0.0.1:8000")

    def test_pre_tool_use_round_trip(self) -> None:
        r = self.client.post("/hooks/cursor/preToolUse", json=shell("cat ~/.ssh/id_ed25519"))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["permission"], "deny")
        r = self.client.post("/hooks/cursor/preToolUse", json=shell("ls", tool_use_id="t2"))
        self.assertEqual(r.json(), {})

    def test_prompt_round_trip(self) -> None:
        r = self.client.post("/hooks/cursor/beforeSubmitPrompt", json=event("beforeSubmitPrompt", prompt="hello"))
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["continue"])

    def test_non_json_body(self) -> None:
        r = self.client.post("/hooks/cursor/preToolUse", content=b"{not json", headers={"content-type": "application/json"})
        self.assertEqual((r.status_code, r.json()["permission"]), (200, "deny"))
        r = self.client.post("/hooks/cursor/postToolUse", content=b"{not json", headers={"content-type": "application/json"})
        self.assertEqual((r.status_code, r.json()), (200, {}))
        r = self.client.post("/hooks/cursor/beforeSubmitPrompt", content=b"x", headers={"content-type": "application/json"})
        self.assertEqual(r.json(), {"continue": True})

    def test_browser_and_wrong_host_rejected(self) -> None:
        r = self.client.post("/hooks/cursor/preToolUse", json=shell("ls"), headers={"origin": "http://evil"})
        self.assertEqual(r.status_code, 403)
        r = self.client.post("/hooks/cursor/preToolUse", json=shell("ls"), headers={"host": "localhost:8000"})
        self.assertEqual(r.status_code, 421)

    def test_all_five_routes_exist_and_nothing_else(self) -> None:
        for name in ["preToolUse", "beforeMCPExecution", "postToolUse", "postToolUseFailure", "beforeSubmitPrompt"]:
            r = self.client.post(f"/hooks/cursor/{name}", json={})
            self.assertEqual(r.status_code, 200, name)
        self.assertEqual(self.client.post("/hooks/cursor/session", json={}).status_code, 404)

    def test_large_write_body_is_not_413(self) -> None:
        big = event("preToolUse", tool_name="Write", tool_use_id="w1", tool_input={"path": f"{ROOT}/big.txt", "contents": "x" * 2_000_000})
        r = self.client.post("/hooks/cursor/preToolUse", json=big)
        self.assertEqual((r.status_code, r.json()), (200, {}))


if __name__ == "__main__":
    unittest.main()
