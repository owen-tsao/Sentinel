from __future__ import annotations

import sys
import unittest
from pathlib import Path

from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.api.schemas import (  # noqa: E402
    ContractEvaluateRequest,
    EvaluateRequest,
    EvaluateResponse,
    ExecutionResult as ExecutionResultSchema,
)
from sentinel.execution import ExecutionResult  # noqa: E402


def contract_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "contract_id": "contract-1",
        "version": 1,
        "session_id": "session-1",
        "agent_id": "agent-1",
        "user_id": "user-1",
        "action": {
            "family": "shell",
            "raw_command": "touch /workspace/build/a.txt",
            "cwd": "/workspace",
        },
    }
    payload.update(overrides)
    return payload


class ApiSchemaTests(unittest.TestCase):
    def test_contract_request_contains_only_raw_shell_proposal(self) -> None:
        request = ContractEvaluateRequest(**contract_payload())
        self.assertEqual(request.action.family, "shell")
        self.assertFalse(hasattr(request.action, "operation"))
        self.assertFalse(hasattr(request.action, "targets"))
        self.assertFalse(hasattr(request, "user_confirmed"))

    def test_contract_request_rejects_caller_canonical_fields(self) -> None:
        action = dict(contract_payload()["action"])  # type: ignore[arg-type]
        action["targets"] = ["/workspace/escaped"]
        with self.assertRaises(ValidationError):
            ContractEvaluateRequest(**contract_payload(action=action))

    def test_contract_request_enforces_string_and_count_limits(self) -> None:
        with self.assertRaises(ValidationError):
            ContractEvaluateRequest(**contract_payload(contract_id="x" * 501))
        with self.assertRaises(ValidationError):
            ContractEvaluateRequest(
                **contract_payload(
                    recent_actions=[
                        {"type": "command", "summary": f"action-{index}"}
                        for index in range(21)
                    ]
                )
            )
        with self.assertRaises(ValidationError):
            ContractEvaluateRequest(**contract_payload(attempt_id=" "))
        with self.assertRaises(ValidationError):
            ContractEvaluateRequest(**contract_payload(attempt_id="x" * 501))

    def test_contract_attempt_id_is_optional_for_evaluation(self) -> None:
        without_attempt = ContractEvaluateRequest(**contract_payload())
        with_attempt = ContractEvaluateRequest(
            **contract_payload(attempt_id="attempt-1")
        )

        self.assertIsNone(without_attempt.attempt_id)
        self.assertEqual(with_attempt.attempt_id, "attempt-1")

    def test_legacy_schema_remains_parseable_but_separate(self) -> None:
        request = EvaluateRequest(
            context="Show the working directory.",
            command="pwd",
            environment="sandbox",
            session_id="session-1",
            agent_id="agent-1",
            user_id="user-1",
        )
        self.assertEqual(request.shell_type, "unknown")

    def test_execution_result_can_populate_response(self) -> None:
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
            execution=execution.to_response_payload(),
        )
        assert response.execution is not None
        self.assertTrue(response.execution.stderr_truncated)

    def test_execution_result_rejects_negative_duration(self) -> None:
        with self.assertRaises(ValidationError):
            ExecutionResultSchema(duration_ms=-1)


if __name__ == "__main__":
    unittest.main()
