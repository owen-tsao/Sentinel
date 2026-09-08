from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


REPO_ROOT = Path(__file__).resolve().parents[1]
HOOK_PATH = REPO_ROOT / ".cursor" / "hooks" / "sentinel_guard.py"


def load_hook() -> ModuleType:
    spec = importlib.util.spec_from_file_location("sentinel_cursor_guard", HOOK_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load Sentinel Cursor hook")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hook = load_hook()


def payload(event: str, **fields: object) -> dict[str, object]:
    return {
        "hook_event_name": event,
        "conversation_id": "conversation-1",
        "generation_id": "generation-1",
        **fields,
    }


class CursorHookPromptTests(unittest.TestCase):
    def test_vague_high_impact_prompt_requires_clarification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            response = hook.handle_before_submit_prompt(
                payload("beforeSubmitPrompt", prompt="Clean up the database."),
                Path(directory),
            )

        self.assertFalse(response["continue"])
        self.assertIn("environment", response["user_message"])
        self.assertIn("exact target", response["user_message"])
        self.assertIn("exact operation", response["user_message"])

    def test_conceptual_security_question_is_not_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            response = hook.handle_before_submit_prompt(
                payload(
                    "beforeSubmitPrompt",
                    prompt="How should production database deletion approvals work?",
                ),
                Path(directory),
            )

        self.assertTrue(response["continue"])

    def test_clear_prompt_records_derived_contract_without_raw_prompt(self) -> None:
        prompt_text = (
            "In staging, preview deleting rows older than 90 days from table "
            "analytics_staging.session_events using a transaction; do not commit. "
            "private-marker-should-not-be-persisted"
        )
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory)
            response = hook.handle_before_submit_prompt(
                payload("beforeSubmitPrompt", prompt=prompt_text),
                state_root,
            )
            stored = next(state_root.glob("*.json")).read_text(encoding="utf-8")

        self.assertTrue(response["continue"])
        self.assertNotIn(prompt_text, stored)
        self.assertNotIn("private-marker-should-not-be-persisted", stored)
        contract = json.loads(stored)
        self.assertEqual(contract["environment"], "staging")
        self.assertTrue(contract["target_specified"])
        self.assertTrue(contract["read_only"])

    def test_question_shaped_imperative_still_requires_clarification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            response = hook.handle_before_submit_prompt(
                payload(
                    "beforeSubmitPrompt",
                    prompt="Would you clean up the production database?",
                ),
                Path(directory),
            )

        self.assertFalse(response["continue"])
        self.assertIn("exact target", response["user_message"])

    def test_reset_imperative_requires_clarification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            response = hook.handle_before_submit_prompt(
                payload(
                    "beforeSubmitPrompt",
                    prompt="Reset the production database.",
                ),
                Path(directory),
            )

        self.assertFalse(response["continue"])
        self.assertIn("exact target", response["user_message"])

    def test_production_irreversible_prompt_requires_rollback_detail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            response = hook.handle_before_submit_prompt(
                payload(
                    "beforeSubmitPrompt",
                    prompt="Delete production database customer_prod.",
                ),
                Path(directory),
            )

        self.assertFalse(response["continue"])
        self.assertIn("rollback", response["user_message"])


class CursorHookActionTests(unittest.TestCase):
    def test_benign_shell_command_is_allowed_without_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            response = hook.handle_before_shell_execution(
                payload("beforeShellExecution", command="pwd"),
                Path(directory),
            )

        self.assertEqual(response, {"permission": "allow"})

    def test_root_deletion_is_denied_without_executing_it(self) -> None:
        dangerous_command = "rm -rf " + "/"
        with tempfile.TemporaryDirectory() as directory:
            response = hook.handle_before_shell_execution(
                payload("beforeShellExecution", command=dangerous_command),
                Path(directory),
            )

        self.assertEqual(response["permission"], "deny")
        self.assertIn("root filesystem", response["user_message"])

    def test_high_impact_shell_without_contract_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            response = hook.handle_before_shell_execution(
                payload(
                    "beforeShellExecution",
                    command="terraform apply -auto-approve",
                ),
                Path(directory),
            )

        self.assertEqual(response["permission"], "deny")
        self.assertIn("confirmation", response["user_message"].lower())

    def test_read_only_prompt_catches_shell_context_overstep(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory)
            hook.handle_before_submit_prompt(
                payload(
                    "beforeSubmitPrompt",
                    prompt=(
                        "In staging, preview terraform changes for cluster payments-stage "
                        "without applying them."
                    ),
                ),
                state_root,
            )
            response = hook.handle_before_shell_execution(
                payload(
                    "beforeShellExecution",
                    command="terraform apply -auto-approve -var-file=staging.tfvars",
                ),
                state_root,
            )

        self.assertEqual(response["permission"], "deny")
        self.assertIn("inspection or preview", response["agent_message"].lower())

    def test_wrapped_root_deletion_is_denied(self) -> None:
        wrapped_command = "bash -c '" + "rm -rf /" + "'"
        with tempfile.TemporaryDirectory() as directory:
            response = hook.handle_before_shell_execution(
                payload("beforeShellExecution", command=wrapped_command),
                Path(directory),
            )

        self.assertEqual(response["permission"], "deny")
        self.assertIn("root filesystem", response["user_message"])

    def test_compound_command_cannot_hide_mutation_after_read_only_prefix(self) -> None:
        command = "git status" + "; chmod 000 /etc/passwd"
        with tempfile.TemporaryDirectory() as directory:
            response = hook.handle_before_shell_execution(
                payload("beforeShellExecution", command=command),
                Path(directory),
            )

        self.assertEqual(response["permission"], "deny")
        self.assertIn("strictly read-only", response["user_message"])

    def test_interpreter_command_is_denied_when_not_explicitly_understood(self) -> None:
        command = 'python3 -c "import shutil; shutil.rmtree(chr(47))"'
        with tempfile.TemporaryDirectory() as directory:
            response = hook.handle_before_shell_execution(
                payload("beforeShellExecution", command=command),
                Path(directory),
            )

        self.assertEqual(response["permission"], "deny")
        self.assertIn("unclassified_shell_command", response["user_message"])

    def test_git_diff_output_and_external_helpers_are_denied(self) -> None:
        for command in (
            "git diff --output=/tmp/change.diff",
            "git diff --ext-diff",
            "git show --textconv HEAD",
        ):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as directory:
                response = hook.handle_before_shell_execution(
                    payload("beforeShellExecution", command=command),
                    Path(directory),
                )

            self.assertEqual(response["permission"], "deny")

    def test_recursive_host_inspection_requires_approval(self) -> None:
        for command in ("ls -R /", "ls -lR /tmp", "du /"):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as directory:
                response = hook.handle_before_shell_execution(
                    payload("beforeShellExecution", command=command),
                    Path(directory),
                )

            self.assertEqual(response["permission"], "deny")
            self.assertIn("strictly read-only", response["user_message"])

    def test_file_write_blocks_unqualified_delete_payload(self) -> None:
        destructive_sql = "DELETE" + " FROM customers;"
        with tempfile.TemporaryDirectory() as directory:
            response = hook.handle_pre_tool_use(
                payload(
                    "preToolUse",
                    tool_name="Write",
                    tool_input={
                        "path": "scripts/reset.py",
                        "contents": f'cursor.execute("{destructive_sql}")',
                    },
                ),
                Path(directory),
            )

        self.assertEqual(response["permission"], "deny")
        self.assertIn("no WHERE clause", response["user_message"])

    def test_file_write_allows_scoped_delete_payload(self) -> None:
        scoped_sql = "DELETE" + " FROM sessions WHERE expires_at < ?;"
        with tempfile.TemporaryDirectory() as directory:
            response = hook.handle_pre_tool_use(
                payload(
                    "preToolUse",
                    tool_name="Write",
                    tool_input={
                        "path": "scripts/cleanup.py",
                        "contents": f'cursor.execute("{scoped_sql}", [cutoff])',
                    },
                ),
                Path(directory),
            )

        self.assertEqual(response, {"permission": "allow"})

    def test_file_delete_tool_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            response = hook.handle_pre_tool_use(
                payload(
                    "preToolUse",
                    tool_name="Delete",
                    tool_input={"path": "src/important.py"},
                ),
                Path(directory),
            )

        self.assertEqual(response["permission"], "deny")
        self.assertIn("file deletion", response["user_message"])

    def test_oversized_file_write_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            response = hook.handle_pre_tool_use(
                payload(
                    "preToolUse",
                    tool_name="Write",
                    tool_input={"contents": "x" * (hook.MAX_INSPECTED_TEXT + 1)},
                ),
                Path(directory),
            )

        self.assertEqual(response["permission"], "deny")
        self.assertIn("too large", response["user_message"])

    def test_hook_configuration_and_guard_code_are_protected(self) -> None:
        tool_inputs = (
            {"path": ".cursor/hooks.json", "contents": "{}"},
            {
                "patch": (
                    "*** Begin Patch\n"
                    "*** Update File: .cursor/hooks/sentinel_guard.py\n"
                    "@@\n-old\n+new\n"
                    "*** End Patch\n"
                )
            },
        )
        for tool_input in tool_inputs:
            with self.subTest(tool_input=tool_input), tempfile.TemporaryDirectory() as directory:
                response = hook.handle_pre_tool_use(
                    payload(
                        "preToolUse",
                        tool_name="ApplyPatch",
                        tool_input=tool_input,
                    ),
                    Path(directory),
                )

            self.assertEqual(response["permission"], "deny")
            self.assertIn("active hook configuration", response["user_message"])

    def test_mcp_mutation_without_contract_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            response = hook.handle_before_mcp_execution(
                payload(
                    "beforeMCPExecution",
                    tool_name="delete_database",
                    tool_input=json.dumps({"database": "customer-prod"}),
                ),
                Path(directory),
            )

        self.assertEqual(response["permission"], "deny")
        self.assertIn("mutate external state", response["user_message"])

    def test_mcp_mutator_name_variants_are_denied(self) -> None:
        for tool_name in ("run_command", "terminate_instances", "write_file", "get_and_reset_database"):
            with self.subTest(tool_name=tool_name), tempfile.TemporaryDirectory() as directory:
                response = hook.handle_before_mcp_execution(
                    payload(
                        "beforeMCPExecution",
                        tool_name=tool_name,
                        tool_input={},
                    ),
                    Path(directory),
                )

            self.assertEqual(response["permission"], "deny")

    def test_explicit_read_only_mcp_tool_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            response = hook.handle_before_mcp_execution(
                payload(
                    "beforeMCPExecution",
                    tool_name="get_issue",
                    tool_input={"id": "ISSUE-1"},
                ),
                Path(directory),
            )

        self.assertEqual(response, {"permission": "allow"})

    def test_production_drop_through_mcp_is_denied(self) -> None:
        drop_statement = "DROP" + " DATABASE customer_prod"
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory)
            hook.handle_before_submit_prompt(
                payload(
                    "beforeSubmitPrompt",
                    prompt=(
                        "In production, preview dropping database customer_prod only after "
                        "verifying snapshot restore; do not execute."
                    ),
                ),
                state_root,
            )
            response = hook.handle_before_mcp_execution(
                payload(
                    "beforeMCPExecution",
                    tool_name="execute_sql",
                    tool_input=json.dumps({"query": drop_statement}),
                ),
                state_root,
            )

        self.assertEqual(response["permission"], "deny")
        self.assertIn("production database", response["user_message"])


class CursorHookAuditTests(unittest.TestCase):
    def test_audit_records_hashes_without_raw_action_text(self) -> None:
        raw_command = "sensitive-command-marker"
        with tempfile.TemporaryDirectory() as directory:
            original_root = hook.STATE_ROOT
            original_path = hook.AUDIT_PATH
            hook.STATE_ROOT = Path(directory)
            hook.AUDIT_PATH = hook.STATE_ROOT / "audit.jsonl"
            try:
                hook._audit_decision(
                    payload("beforeShellExecution", command=raw_command),
                    {"permission": "allow"},
                )
                audit_text = hook.AUDIT_PATH.read_text(encoding="utf-8")
            finally:
                hook.STATE_ROOT = original_root
                hook.AUDIT_PATH = original_path

        self.assertNotIn(raw_command, audit_text)
        record = json.loads(audit_text)
        self.assertEqual(record["event"], "beforeShellExecution")
        self.assertEqual(record["outcome"], "allow")
        self.assertNotIn("subject_hash", record)


if __name__ == "__main__":
    unittest.main()
