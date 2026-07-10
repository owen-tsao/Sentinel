from __future__ import annotations

import sys
import unittest
from pathlib import Path

from pydantic import ValidationError


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.api.schemas import EvaluateRequest, EvaluateResponse, ExecutionResult as ExecutionResultSchema  # noqa: E402
from sentinel.execution import ExecutionResult  # noqa: E402


def request_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "context": "Show repository status.",
        "command": "git status --short",
        "environment": "sandbox",
        "session_id": "session-1",
        "agent_id": "agent-1",
        "user_id": "user-1",
    }
    payload.update(overrides)
    return payload


class ApiSchemaTests(unittest.TestCase):
    def test_evaluate_request_defaults_shell_type_to_unknown(self) -> None:
        request = EvaluateRequest(**request_payload())

        self.assertEqual(request.shell_type, "unknown")

    def test_evaluate_request_accepts_explicit_shell_type(self) -> None:
        request = EvaluateRequest(
            **request_payload(
                context="Run a Python helper.",
                command="python scripts/check.py",
                environment="dev",
                shell_type="python",
            )
        )

        self.assertEqual(request.shell_type, "python")

    def test_evaluate_request_rejects_invalid_environment(self) -> None:
        with self.assertRaises(ValidationError):
            EvaluateRequest(**request_payload(environment="prod"))

    def test_evaluate_request_rejects_invalid_shell_type(self) -> None:
        with self.assertRaises(ValidationError):
            EvaluateRequest(**request_payload(shell_type="ruby"))

    def test_execution_result_schema_accepts_completed_run(self) -> None:
        result = ExecutionResultSchema(
            stdout="hello\n",
            stderr="",
            exit_code=0,
            timed_out=False,
            duration_ms=42,
        )

        self.assertEqual(result.stdout, "hello\n")
        self.assertEqual(result.exit_code, 0)
        self.assertFalse(result.timed_out)
        self.assertFalse(result.stdout_truncated)
        self.assertIsNone(result.error)

    def test_execution_result_schema_rejects_negative_duration(self) -> None:
        with self.assertRaises(ValidationError):
            ExecutionResultSchema(
                stdout="",
                stderr="",
                exit_code=None,
                timed_out=True,
                duration_ms=-1,
            )

    def test_internal_execution_result_can_populate_api_response(self) -> None:
        execution = ExecutionResult(
            stdout="partial output",
            stderr="timed out",
            exit_code=None,
            timed_out=True,
            duration_ms=1_000,
            error="execution timed out",
            stderr_truncated=True,
        )

        response = EvaluateResponse(
            request_id="request-1",
            verdict="allow",
            risk_score=0.05,
            risk_tier="low",
            reasons=["rule:safe_read_only"],
            routing_path="rules",
            agent_message="Allowed.",
            suggested_safe_actions=[],
            confirmation_id=None,
            execution=execution.to_response_payload(),
        )

        self.assertIsNotNone(response.execution)
        assert response.execution is not None
        self.assertEqual(response.execution.stderr, "timed out")
        self.assertTrue(response.execution.timed_out)
        self.assertTrue(response.execution.stderr_truncated)


if __name__ == "__main__":
    unittest.main()

