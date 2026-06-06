from __future__ import annotations

import sys
import unittest
from pathlib import Path

from pydantic import ValidationError


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.api.schemas import EvaluateRequest  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()

