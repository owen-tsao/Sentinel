from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HOOK_PATH = ROOT / "policies" / "cursor" / "sentinel_hooks.py"
HOOKS_JSON = ROOT / "policies" / "cursor" / "hooks.json"


def load_hook_module():
    spec = importlib.util.spec_from_file_location("sentinel_hooks", HOOK_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class CursorHooksProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.private = Path(self.tmp.name) / "private"
        self.private.mkdir()
        self.env = patch.dict(os.environ, {"SENTINEL_PRIVATE_DIR": str(self.private)})
        self.env.start()
        self.hooks = load_hook_module()

    def tearDown(self) -> None:
        self.env.stop()
        self.tmp.cleanup()

    def test_hooks_json_is_fail_closed_for_every_blocking_event(self) -> None:
        config = json.loads(HOOKS_JSON.read_text())
        self.assertEqual(config["version"], 1)
        self.assertEqual(
            set(config["hooks"]),
            {"beforeReadFile", "preToolUse", "beforeShellExecution", "beforeMCPExecution"},
        )
        for event, entries in config["hooks"].items():
            for entry in entries:
                with self.subTest(event=event):
                    self.assertTrue(entry["failClosed"])
                    self.assertLessEqual(entry["timeout"], 10)
                    self.assertIn("sentinel_hooks.py", entry["command"])

    def test_reads_of_private_state_and_cursor_config_are_denied(self) -> None:
        denied = self.hooks.handle_event(
            {"hook_event_name": "beforeReadFile", "file_path": str(self.private / "adapter.capability")}
        )
        config = self.hooks.handle_event(
            {"hook_event_name": "beforeReadFile", "file_path": "/repo/.cursor/mcp.json"}
        )
        allowed = self.hooks.handle_event(
            {"hook_event_name": "beforeReadFile", "file_path": "/repo/src/app.py"}
        )
        self.assertEqual(denied["permission"], "deny")
        self.assertEqual(config["permission"], "deny")
        self.assertEqual(allowed["permission"], "allow")

    def test_mutating_tools_cannot_touch_protected_paths(self) -> None:
        for tool_input in (
            {"path": "/repo/.cursor/hooks.json"},
            {"target_file": "/repo/.cursor/hooks/sentinel_hooks.py"},
            {"file_path": str(self.private / "state.sqlite3")},
            {"edits": [{"path": "/repo/.cursor/mcp.json"}]},
        ):
            with self.subTest(tool_input=tool_input):
                response = self.hooks.handle_event(
                    {"hook_event_name": "preToolUse", "tool_name": "Write", "tool_input": tool_input}
                )
                self.assertEqual(response["permission"], "deny")
        ordinary = self.hooks.handle_event(
            {"hook_event_name": "preToolUse", "tool_name": "Write", "tool_input": {"path": "/repo/README.md"}}
        )
        read_tool = self.hooks.handle_event(
            {"hook_event_name": "preToolUse", "tool_name": "Read", "tool_input": {"path": "/repo/.cursor/mcp.json"}}
        )
        self.assertEqual(ordinary["permission"], "allow")
        self.assertEqual(read_tool["permission"], "allow", "reads are governed by beforeReadFile")

    def test_shell_commands_referencing_protected_paths_are_denied(self) -> None:
        denied = self.hooks.handle_event(
            {"hook_event_name": "beforeShellExecution", "command": f"cat {self.private}/adapter.capability"}
        )
        config = self.hooks.handle_event(
            {"hook_event_name": "beforeShellExecution", "command": "echo x >> .cursor/hooks.json"}
        )
        allowed = self.hooks.handle_event(
            {"hook_event_name": "beforeShellExecution", "command": "git status"}
        )
        self.assertEqual(denied["permission"], "deny")
        self.assertEqual(config["permission"], "deny")
        self.assertEqual(allowed["permission"], "allow")

    def test_fixture_tool_names_are_only_valid_from_the_sentinel_server(self) -> None:
        lookalike = self.hooks.handle_event(
            {"hook_event_name": "beforeMCPExecution", "tool_name": "sentinel_issue_add_note", "mcp_server_name": "evil"}
        )
        lookalike_proposal = self.hooks.handle_event(
            {"hook_event_name": "beforeMCPExecution", "tool_name": "sentinel_task_propose", "mcp_server_name": "evil"}
        )
        genuine = self.hooks.handle_event(
            {"hook_event_name": "beforeMCPExecution", "tool_name": "sentinel_issue_add_note", "mcp_server_name": "sentinel"}
        )
        genuine_proposal = self.hooks.handle_event(
            {"hook_event_name": "beforeMCPExecution", "tool_name": "sentinel_task_propose", "mcp_server_name": "sentinel"}
        )
        unrelated = self.hooks.handle_event(
            {"hook_event_name": "beforeMCPExecution", "tool_name": "search", "mcp_server_name": "docs"}
        )
        self.assertEqual(lookalike["permission"], "deny")
        self.assertEqual(lookalike_proposal["permission"], "deny")
        self.assertEqual(genuine["permission"], "allow")
        self.assertEqual(genuine_proposal["permission"], "allow")
        self.assertEqual(unrelated["permission"], "allow")

    def test_unknown_events_and_bad_input_fail_closed(self) -> None:
        self.assertEqual(self.hooks.handle_event({"hook_event_name": "stop"})["permission"], "deny")
        self.assertEqual(self.hooks.handle_event({})["permission"], "deny")


if __name__ == "__main__":
    unittest.main()
