"""Week 18 step C: the Cursor translation layer, pure.

docs/Week 18 Plan.md §2 translation tables and §7. Payload shapes are the
ones Cursor 3.24.12 produced in the spike (`spikes/week18/cursor_inject/`)
plus the 14 most common tool-input shapes from this person's transcripts.
"""

from __future__ import annotations

import json
import unittest
from typing import Any

from sentinel.detectors import stuck
from sentinel.hosts.cursor import translate
from sentinel.hosts.cursor.schemas import CursorHookPayload, strip_sensitive

ROOT = "/private/tmp/cursor-probe"
SID = "e6acc81b-be31-4c95-bd74-82c0c172f4e0"


def payload(event: str, **fields: Any) -> CursorHookPayload:
    base = {"conversation_id": SID, "session_id": SID, "hook_event_name": event, "cursor_version": "3.24.12",
            "workspace_roots": [ROOT], "user_email": "someone@example.com", "transcript_path": "/x", "cwd": "",
            "launch_dir": ROOT, "launch_dir_source": "cursor_forwarder", "forwarder_ms": 3.2}
    base.update(fields)
    return CursorHookPayload.model_validate(base)


def envelope(event: str, **fields: Any) -> dict[str, Any]:
    return translate.to_envelope(payload(event, **fields), launch_cwd=ROOT).envelope


class ToolTranslation(unittest.TestCase):
    def test_shell_becomes_bash_without_volatile_fields(self) -> None:
        env = envelope("preToolUse", tool_name="Shell", tool_use_id="t1",
                       tool_input={"command": "echo one", "cwd": "", "timeout": 30000, "description": "Say one",
                                   "block_until_ms": 5000, "working_directory": ""})
        self.assertEqual((env["tool_name"], env["tool_input"]), ("Bash", {"command": "echo one"}))
        self.assertEqual(env["cwd"], ROOT)          # empty cwd strings never leak into the envelope
        self.assertEqual(env["hook_event_name"], "PreToolUse")

    def test_shell_working_directory_is_the_floors_cwd(self) -> None:
        env = envelope("preToolUse", tool_name="Shell", tool_input={"command": "rm -rf build", "working_directory": "/other/repo"})
        self.assertEqual(env["cwd"], "/other/repo")
        self.assertEqual(env["tool_input"], {"command": "rm -rf build"})

    def test_two_shell_runs_with_different_timeouts_share_an_identity(self) -> None:
        a = envelope("preToolUse", tool_name="Shell", tool_input={"command": "make lint", "timeout": 30000, "description": "a"})
        b = envelope("preToolUse", tool_name="Shell", tool_input={"command": "make lint ", "block_until_ms": 1, "description": "b"})
        self.assertEqual(stuck.identity(a["tool_name"], a["tool_input"]), stuck.identity(b["tool_name"], b["tool_input"]))

    def test_file_tools(self) -> None:
        cases = [
            ("Read", {"file_path": f"{ROOT}/a.py"}, "Read", {"file_path": f"{ROOT}/a.py"}),
            ("Read", {"path": f"{ROOT}/a.py", "offset": 1, "limit": 5}, "Read", {"file_path": f"{ROOT}/a.py", "offset": 1, "limit": 5}),
            ("ReadFile", {"path": f"{ROOT}/a.py"}, "Read", {"file_path": f"{ROOT}/a.py"}),
            ("Write", {"path": f"{ROOT}/a.py", "contents": "x"}, "Write", {"file_path": f"{ROOT}/a.py", "content": "x"}),
            ("StrReplace", {"path": f"{ROOT}/a.py", "old_string": "a", "new_string": "b", "replace_all": True},
             "Edit", {"file_path": f"{ROOT}/a.py", "old_string": "a", "new_string": "b", "replace_all": True}),
            ("Delete", {"path": f"{ROOT}/a.py"}, "Delete", {"file_path": f"{ROOT}/a.py"}),
            ("Glob", {"glob_pattern": "*.py", "target_directory": f"{ROOT}/src"}, "Glob", {"pattern": "*.py", "path": f"{ROOT}/src"}),
            ("Glob", {"glob_pattern": "*.py"}, "Glob", {"pattern": "*.py"}),
            ("Grep", {"pattern": "x", "path": f"{ROOT}/src", "output_mode": "content", "-n": True}, "Grep", {"pattern": "x", "path": f"{ROOT}/src"}),
            ("WebSearch", {"search_term": "pydantic v2", "explanation": "why"}, "WebSearch", {"query": "pydantic v2"}),
            ("WebFetch", {"url": "https://example.com/x"}, "WebFetch", {"url": "https://example.com/x"}),
        ]
        for cursor_tool, cursor_input, want_tool, want_input in cases:
            with self.subTest(tool=cursor_tool, keys=sorted(cursor_input)):
                env = envelope("preToolUse", tool_name=cursor_tool, tool_input=cursor_input)
                self.assertEqual((env["tool_name"], env["tool_input"]), (want_tool, want_input))

    def test_relative_path_resolves_against_launch_cwd_not_workspace_roots(self) -> None:
        p = payload("preToolUse", tool_name="Write", tool_input={"path": "src/a.py", "contents": ""},
                    workspace_roots=["/somewhere/else"])
        env = translate.to_envelope(p, launch_cwd="/srv/project").envelope
        self.assertEqual(env["tool_input"]["file_path"], "/srv/project/src/a.py")

    def test_missing_path_stays_missing(self) -> None:
        env = envelope("preToolUse", tool_name="Write", tool_input={"contents": "x"})
        self.assertNotIn("file_path", env["tool_input"])   # the floor blocks it as unresolved
        env = envelope("preToolUse", tool_name="Write", tool_input="raw string")
        self.assertEqual(env["tool_input"], {"_raw": "raw string", })

    def test_apply_patch_extracts_file_headers_and_keeps_no_patch_body(self) -> None:
        """Week 19: the envelope carries the files the patch names (op + resolved
        path) and the body stays out, as it did when the whole patch was opaque."""
        text = (f"*** Begin Patch\n*** Update File: {ROOT}/src/a.py\n@@\n-SECRET_BODY_LINE\n+new\n"
                "*** Add File: ~/.ssh/authorized_keys\n+ssh-ed25519 KEYMATERIAL\n"
                "*** Delete File: relative/old.txt\n*** Add File: \n*** End Patch\n")
        env = envelope("preToolUse", tool_name="ApplyPatch", tool_input=text)
        self.assertEqual(env["tool_name"], "ApplyPatch")
        self.assertEqual(set(env["tool_input"]), {"patch_sha256", "patch_length", "files"})
        self.assertEqual(env["tool_input"]["files"], [
            {"op": "update", "path": f"{ROOT}/src/a.py"},
            {"op": "add", "path": "~/.ssh/authorized_keys"},             # `~` is left for the floor, as for Write
            {"op": "delete", "path": f"{ROOT}/relative/old.txt"},         # relative joins the launch directory, as for Write
            {"op": "add", "path": ""},                                    # empty stays empty so the floor denies it
        ])
        dumped = json.dumps(env)
        self.assertNotIn("SECRET_BODY_LINE", dumped)
        self.assertNotIn("KEYMATERIAL", dumped)

    def test_apply_patch_without_headers_is_still_opaque_in_the_envelope(self) -> None:
        for tool_input in ("*** Begin Patch\n*** End Patch\n", "", {}, {"patch": "no headers here"}, None):
            with self.subTest(tool_input=tool_input):
                env = envelope("preToolUse", tool_name="ApplyPatch", tool_input=tool_input)
                self.assertEqual(env["tool_input"]["files"], [])
        # A dict that wraps the patch text is read like the bare string.
        env = envelope("preToolUse", tool_name="ApplyPatch", tool_input={"patch": f"*** Update File: {ROOT}/x.py\n"})
        self.assertEqual(env["tool_input"]["files"], [{"op": "update", "path": f"{ROOT}/x.py"}])

    def test_mcp_on_pre_tool_use_and_before_mcp_execution(self) -> None:
        pre = envelope("preToolUse", tool_name="MCP:list_namespaces", tool_input={}, tool_use_id="m1")
        self.assertEqual(pre["tool_name"], "mcp__unknown__list_namespaces")
        self.assertNotIn("mcp_server", pre)
        before = translate.to_envelope(payload("beforeMCPExecution", tool_name="list_namespaces", tool_input="{}",
                                               tool_use_id="m1", mcp_server_name="Origin",
                                               mcp_server_url="https://api.origin.cursor.com/mcp"), launch_cwd=ROOT)
        self.assertEqual(before.envelope["tool_name"], "mcp__Origin__list_namespaces")
        self.assertEqual(before.envelope["tool_input"], {})
        self.assertEqual(before.envelope["mcp_server"], {"name": "Origin"})
        self.assertEqual(before.mcp_server, "Origin")

    def test_mcp_string_input_with_a_path_reaches_the_floor(self) -> None:
        before = envelope("beforeMCPExecution", tool_name="read_file", tool_input=json.dumps({"path": "/etc/passwd"}),
                          mcp_server_name="fs")
        self.assertEqual(before["tool_input"], {"path": "/etc/passwd"})

    def test_raw_cursor_mcp_tool_names(self) -> None:
        env = envelope("preToolUse", tool_name="CallDynamicTool",
                       tool_input={"namespace": "cursor", "toolName": "Task", "arguments": {"prompt": "x"}})
        self.assertEqual((env["tool_name"], env["tool_input"]), ("mcp__cursor__Task", {"prompt": "x"}))
        env = envelope("preToolUse", tool_name="CallMcpTool",
                       tool_input={"server": "linear", "toolName": "list_issues", "arguments": {}, "description": "d"})
        self.assertEqual(env["tool_name"], "mcp__linear__list_issues")

    def test_passthrough_tools_keep_their_name(self) -> None:
        for tool, tool_input in [("Task", {"description": "d", "prompt": "p", "subagent_type": "explore"}),
                                 ("AwaitShell", {"shell_id": "1", "block_until_ms": 5}), ("TodoWrite", {"todos": []})]:
            env = envelope("preToolUse", tool_name=tool, tool_input=tool_input)
            self.assertEqual((env["tool_name"], env["tool_input"]), (tool, tool_input))

    def test_subagent_calls_are_marked(self) -> None:
        env = envelope("preToolUse", tool_name="Shell", tool_input={"command": "ls"}, parent_tool_call_id="tooluse_x")
        self.assertEqual(env["agent_type"], "subagent")
        self.assertIsNone(envelope("preToolUse", tool_name="Shell", tool_input={"command": "ls"})["agent_type"])


class OutputTranslation(unittest.TestCase):
    def test_shell_output_string_lands_in_the_bash_result_shape(self) -> None:
        t = translate.to_envelope(payload("postToolUse", tool_name="Shell", tool_use_id="t1", duration=3135.1,
                                          tool_input={"command": "echo one", "cwd": "", "timeout": 30000},
                                          tool_output=json.dumps({"output": "one\n", "exitCode": 0})), launch_cwd=ROOT)
        self.assertFalse(t.failed)
        env = t.envelope
        self.assertEqual(env["tool_response"], {"stdout": "one\n", "stderr": "", "interrupted": False})
        self.assertEqual(env["duration_ms"], 3135.1)
        # Same fingerprint as Claude Code's Bash result for the same output.
        claude = {"stdout": "one\n", "stderr": "", "interrupted": False, "isImage": False}
        self.assertEqual(stuck.fingerprint("Bash", env["tool_response"]), stuck.fingerprint("Bash", claude))

    def test_non_zero_exit_takes_the_failure_path(self) -> None:
        t = translate.to_envelope(payload("postToolUse", tool_name="Shell", tool_use_id="t1",
                                          tool_input={"command": "make lint"},
                                          tool_output=json.dumps({"output": "E  assert 1 == 2\n", "exitCode": 1})), launch_cwd=ROOT)
        self.assertTrue(t.failed)
        self.assertEqual(t.envelope["hook_event_name"], "PostToolUseFailure")
        self.assertTrue(t.envelope["error"].startswith("Exit code 1\n"))
        # Identical to Claude Code's failure fingerprint for exit code 1.
        self.assertEqual(stuck.error_fingerprint(t.envelope["error"]), stuck.error_fingerprint("Exit code 1\nE  boom"))

    def test_non_shell_and_non_json_outputs(self) -> None:
        read = translate.to_envelope(payload("postToolUse", tool_name="Read", tool_use_id="t1", tool_input={"file_path": "/a"},
                                             tool_output=json.dumps({"file_path": "/a", "content_length": 213})), launch_cwd=ROOT)
        self.assertEqual(read.envelope["tool_response"], {"file_path": "/a", "content_length": 213})
        raw = translate.to_envelope(payload("postToolUse", tool_name="Read", tool_use_id="t1", tool_input={"file_path": "/a"},
                                            tool_output="not json"), launch_cwd=ROOT)
        self.assertEqual(raw.envelope["tool_response"], "not json")
        shell_dict = translate.translate_output("Shell", {"output": "x", "exitCode": 0})
        self.assertEqual(shell_dict, ({"stdout": "x", "stderr": "", "interrupted": False}, None))

    def test_failure_event(self) -> None:
        t = translate.to_envelope(payload("postToolUseFailure", tool_name="Shell", tool_use_id="t1", duration=0,
                                          tool_input={"command": "ls"}, error_message="Hook blocked with message: x\n\n---\nmore",
                                          failure_type="permission_denied", is_interrupt=False), launch_cwd=ROOT)
        self.assertTrue(t.failed)
        self.assertEqual(t.envelope["error"], "Hook blocked with message: x\n\n---\nmore")
        self.assertFalse(t.envelope["is_interrupt"])

    def test_prompt(self) -> None:
        env = envelope("beforeSubmitPrompt", prompt="fix src/api", attachments=[{"type": "file", "filePath": "/etc/x"}])
        self.assertEqual((env["hook_event_name"], env["prompt"]), ("UserPromptSubmit", "fix src/api"))
        self.assertNotIn("attachments", env)


class ResponseTranslation(unittest.TestCase):
    def test_deny_with_advisory_system_message_stays_deny(self) -> None:
        body = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": "Deletes ~/.ssh."},
                "systemMessage": "Sentinel blocked this action but its hook is not locked."}
        out = translate.to_cursor(body, event="preToolUse")
        self.assertEqual(out["permission"], "deny")
        self.assertIn("Deletes ~/.ssh.", out["user_message"])
        self.assertIn("not locked", out["user_message"])
        self.assertEqual(out["agent_message"], "Deletes ~/.ssh.")

    def test_ask_only_on_the_events_cursor_enforces(self) -> None:
        """Spike C2: `ask` is honoured on `beforeShellExecution` and
        `beforeMCPExecution`; on `preToolUse` Cursor ignores it (ran a Delete,
        rejected a WebFetch), so an ask reaching that event becomes a deny."""
        body = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                       "permissionDecisionReason": "Sentinel: deletes a sibling repo file."}}
        for event in ("beforeShellExecution", "beforeMCPExecution"):
            with self.subTest(event=event):
                self.assertEqual(translate.to_cursor(body, event=event),
                                 {"permission": "ask", "user_message": "Sentinel: deletes a sibling repo file.",
                                  "agent_message": "Sentinel: deletes a sibling repo file."})
        out = translate.to_cursor(body, event="preToolUse")
        self.assertEqual(out["permission"], "deny")
        self.assertIn("deletes a sibling repo file", out["user_message"])
        self.assertIn("Ask the user in chat", out["user_message"])

    def test_before_shell_execution_becomes_the_same_shell_envelope(self) -> None:
        pre = envelope("preToolUse", tool_name="Shell", tool_input={"command": "rm -rf build", "cwd": "", "timeout": 30000},
                       tool_use_id="t1")
        before = envelope("beforeShellExecution", command="rm -rf build", cwd="", sandbox=False, tool_use_id="t1")
        self.assertEqual((before["hook_event_name"], before["tool_name"], before["tool_input"], before["tool_use_id"]),
                         ("PreToolUse", "Bash", {"command": "rm -rf build"}, "t1"))
        self.assertEqual(before["tool_input"], pre["tool_input"])
        sub = envelope("beforeShellExecution", command="ls", cwd="/Users/owen/proj/pkg", tool_use_id="t2",
                       parent_tool_call_id="p1")
        self.assertEqual((sub["cwd"], sub["agent_type"]), ("/Users/owen/proj/pkg", "subagent"))

    def test_ask_capable_depends_on_the_host_shape_not_the_translated_name(self) -> None:
        """Only shapes with a verified second event can hold an ask: `Shell`
        (spike C2) and `MCP:<tool>` (step A1). `CallDynamicTool` also becomes
        `mcp__*` but nothing is known to deliver its ask, so it is not capable
        (review M1): a held confirm that no event delivers is a silent allow."""
        self.assertTrue(translate.ask_capable({"host_tool": "Shell", "tool_name": "Bash"}))
        self.assertTrue(translate.ask_capable({"host_tool": "MCP:read_file", "tool_name": "mcp__unknown__read_file"}))
        self.assertFalse(translate.ask_capable({"host_tool": "CallDynamicTool", "tool_name": "mcp__fs__read_file"}))
        self.assertFalse(translate.ask_capable({"host_tool": "CallMcpTool", "tool_name": "mcp__fs__read_file"}))
        for tool in ("Write", "StrReplace", "Delete", "ApplyPatch", "Read", "WebFetch", ""):
            self.assertFalse(translate.ask_capable({"host_tool": tool, "tool_name": translate.TOOL_NAMES.get(tool, tool)}), tool)
        # An envelope with no host name (built outside the translator): the verified translated shapes only.
        self.assertTrue(translate.ask_capable({"tool_name": "Bash"}))
        self.assertTrue(translate.ask_capable({"tool_name": "mcp__fs__x"}))
        self.assertFalse(translate.ask_capable({"tool_name": "Write"}))

    def test_envelope_records_the_host_tool(self) -> None:
        self.assertEqual(envelope("preToolUse", tool_name="Shell", tool_input={"command": "ls"})["host_tool"], "Shell")
        self.assertEqual(envelope("preToolUse", tool_name="MCP:read_file", tool_input={})["host_tool"], "MCP:read_file")
        self.assertEqual(envelope("preToolUse", tool_name="CallDynamicTool",
                                  tool_input={"namespace": "fs", "toolName": "read_file"})["host_tool"], "CallDynamicTool")
        self.assertEqual(envelope("beforeShellExecution", command="ls", cwd="")["host_tool"], "Shell")
        # On beforeMCPExecution the bare name is given the prefix preToolUse would have used.
        self.assertEqual(envelope("beforeMCPExecution", tool_name="read_file", tool_input="{}",
                                  mcp_server_name="fs")["host_tool"], "MCP:read_file")

    def test_before_mcp_execution_without_a_server_name_is_still_mcp(self) -> None:
        """The event is MCP by definition; a missing server name must not let a
        tool called `Read` borrow the built-in's judgment or pass through."""
        env = envelope("beforeMCPExecution", tool_name="Read", tool_input=json.dumps({"path": "/etc/passwd"}))
        self.assertEqual(env["tool_name"], "mcp__unknown__Read")
        self.assertEqual(env["mcp_server"], {"name": "unknown"})
        env = envelope("beforeMCPExecution", tool_name="list_namespaces", tool_input="{}")
        self.assertEqual(env["tool_name"], "mcp__unknown__list_namespaces")

    def test_allow_shapes_never_say_allow(self) -> None:
        self.assertEqual(translate.to_cursor({}, event="preToolUse"), {})
        out = translate.to_cursor({"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": "nudge"}},
                                  event="preToolUse")
        self.assertEqual(out, {"additional_context": "nudge"})
        # A systemMessage with no decision has no channel on Cursor: dropped, never upgraded.
        out = translate.to_cursor({"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": "nudge"},
                                   "systemMessage": "stuck"}, event="preToolUse")
        self.assertEqual(out, {"additional_context": "nudge"})
        for body in [{}, {"systemMessage": "x"}]:
            self.assertNotIn("permission", translate.to_cursor(body, event="preToolUse"))

    def test_prompt_response_always_continues(self) -> None:
        self.assertEqual(translate.to_cursor({}, event="beforeSubmitPrompt"), {"continue": True})
        out = translate.to_cursor({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": "line"}},
                                  event="beforeSubmitPrompt")
        self.assertEqual(out, {"continue": True, "additional_context": "line"})
        # Even a deny-shaped body (which the service never produces here) cannot stop a prompt.
        bad = {"hookSpecificOutput": {"permissionDecision": "deny", "permissionDecisionReason": "x"}}
        self.assertEqual(translate.to_cursor(bad, event="beforeSubmitPrompt")["continue"], True)

    def test_post_events_return_nothing_or_context(self) -> None:
        self.assertEqual(translate.to_cursor({}, event="postToolUse"), {})
        deny = {"hookSpecificOutput": {"permissionDecision": "deny", "permissionDecisionReason": "x"}}
        self.assertEqual(translate.to_cursor(deny, event="postToolUseFailure"), {})

    def test_response_kind_vocabulary(self) -> None:
        self.assertEqual(translate.response_kind({}), "empty")
        self.assertEqual(translate.response_kind({"additional_context": "x"}), "context")
        self.assertEqual(translate.response_kind({"permission": "deny", "user_message": "x"}), "deny")
        self.assertEqual(translate.response_kind({"permission": "ask", "user_message": "x"}), "ask")


class Schemas(unittest.TestCase):
    def test_strip_sensitive(self) -> None:
        raw = {"hook_event_name": "preToolUse", "user_email": "a@b", "prompt": "p", "tool_output": "o",
               "error_message": "e", "tool_input": {"command": "secret"}, "workspace_roots": ["/r"]}
        out = strip_sensitive(raw)
        for key in ("user_email", "prompt", "tool_output", "error_message", "tool_input"):
            self.assertEqual(out[key], "<stripped>")
        self.assertEqual(out["workspace_roots"], ["/r"])
        self.assertEqual(strip_sensitive("junk"), {"type": "str"})

    def test_payload_is_lenient_and_conversation_falls_back(self) -> None:
        p = CursorHookPayload.model_validate({"hook_event_name": "preToolUse", "conversation_id": "c1", "brand_new": 1})
        self.assertEqual(p.conversation, "c1")
        self.assertIsNone(CursorHookPayload.model_validate({"hook_event_name": "preToolUse"}).conversation)


if __name__ == "__main__":
    unittest.main()
