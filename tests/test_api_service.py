from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel import __version__  # noqa: E402
from sentinel.api.main import _module_ml_enabled, create_app  # noqa: E402
from sentinel.audit import SQLiteAuditStore  # noqa: E402
from sentinel.contracts import SQLiteContractStore  # noqa: E402
from sentinel.execution import ExecutionResult  # noqa: E402
from sentinel.ml.inference import RiskPrediction  # noqa: E402
from sentinel.session import (  # noqa: E402
    ExecutionAttemptBinding,
    SQLiteSessionStore,
)


class FakeExecutor:
    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    def validate_configuration(self) -> None:
        pass

    def validate_operation(self, operation: str) -> None:
        del operation

    def validate_targets(self, targets: list[str]) -> None:
        del targets

    def run(self, *, command: str, shell_type: str) -> ExecutionResult:
        self.calls.append({"command": command, "shell_type": shell_type})
        return ExecutionResult(
            stdout="ok\n",
            stderr="",
            exit_code=0,
            timed_out=False,
            duration_ms=1,
        )


class AllowModel:
    def predict_row(self, row: dict[str, object]) -> RiskPrediction:
        return RiskPrediction(
            risk_probability=0.01,
            model_tier="allow",
            threshold={"warn": 0.2, "confirm_required": 0.4},
            input_names=[],
            provider="test",
            metadata={},
        )


def legacy_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "context": "Show the sandbox working directory.",
        "command": "pwd",
        "environment": "sandbox",
        "shell_type": "bash",
        "session_id": "session-1",
        "agent_id": "agent-1",
        "user_id": "user-1",
    }
    payload.update(overrides)
    return payload


class ApiServiceTests(unittest.TestCase):
    def test_create_app_does_not_load_local_model_without_explicit_opt_in(
        self,
    ) -> None:
        with patch("sentinel.api.main.OnnxRiskModel") as model_factory:
            app = create_app(load_policy=False)

        body = TestClient(app).get("/health").json()
        model_factory.assert_not_called()
        self.assertFalse(body["model_loaded"])
        self.assertEqual(body["model_detail"], "Model loading is disabled.")

    def test_create_app_loads_model_when_explicitly_enabled(self) -> None:
        loaded_model = AllowModel()
        with patch(
            "sentinel.api.main.OnnxRiskModel",
            return_value=loaded_model,
        ) as model_factory:
            app = create_app(load_model=True, load_policy=False)

        model_factory.assert_called_once_with()
        self.assertIs(app.state.risk_model, loaded_model)

    def test_module_ml_environment_requires_exact_boolean(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(_module_ml_enabled())
        with patch.dict(
            os.environ,
            {"SENTINEL_ENABLE_ML": "true"},
            clear=True,
        ):
            self.assertTrue(_module_ml_enabled())
        with patch.dict(
            os.environ,
            {"SENTINEL_ENABLE_ML": "1"},
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "exactly"):
                _module_ml_enabled()

    def test_default_rules_only_app_still_runs_deterministic_policy(self) -> None:
        response = TestClient(create_app()).post(
            "/evaluate",
            json=legacy_payload(),
        )

        self.assertEqual(response.json()["verdict"], "confirm_required")
        self.assertIn("rule:safe_read_only_command", response.json()["reasons"])
        self.assertIn("legacy:non_authorizing_request", response.json()["reasons"])

    def test_openapi_and_package_versions_match(self) -> None:
        app = create_app(load_policy=False)

        self.assertEqual(app.version, "0.1.0")
        self.assertEqual(app.version, __version__)
        self.assertEqual(TestClient(app).get("/openapi.json").json()["info"]["version"], __version__)

    def test_health_reports_model_policy_and_audit_degradation(self) -> None:
        client = TestClient(
            create_app(load_model=False, load_policy=False)
        )
        body = client.get("/health").json()
        self.assertEqual(body["status"], "degraded")
        self.assertFalse(body["model_loaded"])
        self.assertFalse(body["policy_loaded"])
        self.assertEqual(body["audit_status"], "ok")

    def test_owned_sqlite_stores_close_after_each_app_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "sentinel.sqlite3")
            previous = os.environ.get("SENTINEL_STATE_DB")
            os.environ["SENTINEL_STATE_DB"] = database
            try:
                first_app = create_app(load_policy=False)
                binding = ExecutionAttemptBinding(
                    attempt_id="attempt-recovery",
                    session_id="session-1",
                    task_id="task-1",
                    contract_id="contract-1",
                    contract_version=1,
                    authority_epoch=1,
                    action_fingerprint="a" * 64,
                    environment="sandbox",
                )
                with TestClient(first_app):
                    first_app.state.session_store.reserve_attempt(binding)
                    first_app.state.session_store.transition_attempt(
                        binding.attempt_id,
                        expected_state="reserved",
                        new_state="running",
                    )

                second_app = create_app(load_policy=False)
                with TestClient(second_app):
                    recovered = second_app.state.session_store.get_attempt(
                        binding.attempt_id
                    )
                    self.assertIsNotNone(recovered)
                    assert recovered is not None
                    self.assertEqual(recovered.state, "unknown")

                third_app = create_app(load_policy=False)
                with TestClient(third_app):
                    self.assertEqual(
                        third_app.state.session_store.get_attempt(
                            binding.attempt_id
                        ).state,
                        "unknown",
                    )
            finally:
                if previous is None:
                    os.environ.pop("SENTINEL_STATE_DB", None)
                else:
                    os.environ["SENTINEL_STATE_DB"] = previous

    def test_injected_sqlite_stores_are_not_closed_by_app_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "injected.sqlite3"
            contracts = SQLiteContractStore(database)
            sessions = SQLiteSessionStore(database)
            audit = SQLiteAuditStore(database)
            try:
                app = create_app(
                    load_policy=False,
                    contract_store=contracts,
                    session_store=sessions,
                    audit_store=audit,
                )
                with TestClient(app):
                    pass

                self.assertIsNone(contracts.get_active("session-1"))
                self.assertEqual(sessions.get_recent_actions("session-1"), [])
                self.assertEqual(audit.health.status, "ok")
            finally:
                contracts.close()
                sessions.close()
                audit.close()

    def test_confirm_route_does_not_exist(self) -> None:
        client = TestClient(create_app(load_model=False))
        self.assertEqual(
            client.post("/confirm", json={"confirmation_id": "anything"}).status_code,
            404,
        )

    def test_legacy_execute_never_runs_without_contract_authority(self) -> None:
        executor = FakeExecutor()
        client = TestClient(
            create_app(load_model=False, load_policy=False, executor=executor)
        )
        allowed = client.post("/execute", json=legacy_payload())
        ambiguous = client.post(
            "/execute",
            json=legacy_payload(
                context="Run a project helper.",
                command="python scripts/helper.py",
                shell_type="python",
                confirmation_token="ignored",
                user_confirmed=True,
            ),
        )

        self.assertEqual(allowed.json()["verdict"], "confirm_required")
        self.assertIn("legacy:non_authorizing_request", allowed.json()["reasons"])
        self.assertEqual(ambiguous.json()["verdict"], "confirm_required")
        self.assertIn("legacy:non_authorizing_request", ambiguous.json()["reasons"])
        self.assertEqual(executor.calls, [])

    def test_legacy_model_allow_cannot_authorize_execution(self) -> None:
        executor = FakeExecutor()
        client = TestClient(
            create_app(
                model=AllowModel(),
                load_model=False,
                executor=executor,
            )
        )
        response = client.post(
            "/execute",
            json=legacy_payload(
                context="Run helper.",
                command="python scripts/helper.py",
                shell_type="python",
            ),
        )
        self.assertEqual(response.json()["verdict"], "confirm_required")
        self.assertEqual(executor.calls, [])

    def test_legacy_critical_rule_still_blocks(self) -> None:
        executor = FakeExecutor()
        client = TestClient(create_app(load_model=False, executor=executor))
        response = client.post(
            "/execute",
            json=legacy_payload(command="rm -rf /", context="Clean the machine."),
        )
        self.assertEqual(response.json()["verdict"], "block")
        self.assertIn("rule:root_filesystem_deletion", response.json()["reasons"])
        self.assertEqual(executor.calls, [])

    def test_request_body_limit_returns_413(self) -> None:
        client = TestClient(create_app(load_model=False))
        response = client.post(
            "/evaluate",
            content=b'{"padding":"' + (b"x" * 70_000) + b'"}',
            headers={"content-type": "application/json"},
        )
        self.assertEqual(response.status_code, 413)

    def test_chunked_request_body_limit_returns_413(self) -> None:
        client = TestClient(create_app(load_model=False))

        def chunks():
            for _ in range(80):
                yield b"x" * 1_024

        response = client.post(
            "/evaluate",
            content=chunks(),
            headers={
                "content-type": "application/json",
                "transfer-encoding": "chunked",
            },
        )

        self.assertEqual(response.status_code, 413)


if __name__ == "__main__":
    unittest.main()
