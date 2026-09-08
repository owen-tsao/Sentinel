from __future__ import annotations

import sys
import os
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator
from uuid import uuid4

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from approver_harness import ApproverHarness  # noqa: E402
from sentinel.api.main import create_app  # noqa: E402
from sentinel.approval import InMemoryApprovalService  # noqa: E402
from sentinel.audit import AuditEvent, AuditHealth  # noqa: E402
from sentinel.contracts import (  # noqa: E402
    ActionContract,
    InMemoryContractStore,
    InMemoryTrustedEventConsumer,
    TrustedPromptEnvelope,
)
from sentinel.contracts import SQLiteContractStore  # noqa: E402
from sentinel.decision.policy import parse_policy_profile  # noqa: E402
from sentinel.execution import DockerExecutor, ExecutionResult  # noqa: E402
from sentinel.ml.inference import RiskPrediction  # noqa: E402
from sentinel.session import InMemorySessionStore, SessionAction, SQLiteSessionStore  # noqa: E402
from sentinel.audit import SQLiteAuditStore  # noqa: E402


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
            duration_ms=2,
        )


class BlockingExecutor(FakeExecutor):
    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.release = threading.Event()
        self._lock = threading.Lock()

    def run(self, *, command: str, shell_type: str) -> ExecutionResult:
        with self._lock:
            self.calls.append({"command": command, "shell_type": shell_type})
        self.started.set()
        if not self.release.wait(timeout=3):
            raise RuntimeError("test executor release timed out")
        return ExecutionResult(
            stdout="ok\n",
            stderr="",
            exit_code=0,
            timed_out=False,
            duration_ms=2,
        )


class RunOnlyExecutor:
    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    def run(self, *, command: str, shell_type: str) -> ExecutionResult:
        self.calls.append({"command": command, "shell_type": shell_type})
        return ExecutionResult("", "", 0, False, 1)


class ConcurrentExecutor(FakeExecutor):
    def __init__(self) -> None:
        super().__init__()
        self.two_started = threading.Event()
        self.release = threading.Event()
        self._lock = threading.Lock()
        self._active = 0
        self.max_active = 0

    def run(self, *, command: str, shell_type: str) -> ExecutionResult:
        with self._lock:
            self.calls.append({"command": command, "shell_type": shell_type})
            self._active += 1
            self.max_active = max(self.max_active, self._active)
            if self._active == 2:
                self.two_started.set()
        try:
            if not self.release.wait(timeout=3):
                raise RuntimeError("test executor release timed out")
            return ExecutionResult("ok\n", "", 0, False, 2)
        finally:
            with self._lock:
                self._active -= 1


class GloballyGuardedContractStore:
    """Expose two sessions behind one global admission lock."""

    def __init__(
        self,
        stores: dict[str, InMemoryContractStore],
    ) -> None:
        self._stores = stores
        self._guard = threading.Lock()

    def get_active(self, session_id: str, **kwargs: object):
        return self._stores[session_id].get_active(session_id, **kwargs)

    @contextmanager
    def execution_guard(
        self,
        contract_id: str,
        *,
        session_id: str,
        **kwargs: object,
    ) -> Iterator[object]:
        with self._guard:
            with self._stores[session_id].execution_guard(
                contract_id,
                session_id=session_id,
                **kwargs,
            ) as record:
                yield record


class RecordingAuditStore:
    def __init__(self, *, fail: bool = False, fail_after: int | None = None) -> None:
        self.events: list[AuditEvent] = []
        self.fail = fail
        self.fail_after = fail_after

    @property
    def health(self) -> AuditHealth:
        return AuditHealth(
            status="degraded" if self.fail else "ok",
            detail="simulated failure" if self.fail else None,
            fallback_event_count=0,
            fallback_capacity=100,
        )

    def write(self, event: AuditEvent) -> None:
        if self.fail or (
            self.fail_after is not None and len(self.events) >= self.fail_after
        ):
            raise RuntimeError("audit unavailable")
        self.events.append(event)

    def write_required(self, event: AuditEvent) -> None:
        self.write(event)


class FailingCompletionSessionStore(InMemorySessionStore):
    def __init__(self) -> None:
        super().__init__()
        self.failed_completion = False

    def transition_attempt(self, attempt_id: str, **kwargs: object):
        if (
            kwargs.get("new_state") in {"completed", "failed"}
            and not self.failed_completion
        ):
            self.failed_completion = True
            raise RuntimeError("simulated completion persistence failure")
        return super().transition_attempt(attempt_id, **kwargs)  # type: ignore[arg-type]


class CapturingAllowModel:
    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    def predict_row(self, row: dict[str, object]) -> RiskPrediction:
        self.rows.append(row)
        return RiskPrediction(
            risk_probability=0.01,
            model_tier="allow",
            threshold={"warn": 0.2, "confirm_required": 0.4},
            input_names=[],
            provider="test",
            metadata={},
        )


def policy_profile():
    environments = {}
    for environment in ("sandbox", "dev", "staging", "production"):
        environments[environment] = {
            "minimum_model_tier_for_confirmation": "confirm_required",
            "warn_requires_confirmation": False,
            "production_change_requires_confirmation": True,
            "unmatched_requires_confirmation": False,
            "allow_confirmation_for_verdicts": ["confirm_required"],
        }
    return parse_policy_profile(
        {
            "name": "api-test",
            "version": 1,
            "default_environment": "sandbox",
            "environments": environments,
        }
    )


def make_contract(**overrides: object) -> ActionContract:
    values: dict[str, object] = {
        "objective": "Write the two reviewed build outputs.",
        "allowed_operations": {"write"},
        "allowed_tools": {"shell"},
        "exact_targets": [
            "/workspace/build/a.txt",
            "/workspace/build/b.txt",
        ],
        "environment": "sandbox",
        "maximum_scope": "exact",
        "expected_side_effects": ["Write reviewed build output."],
        "allowed_effects": {"write"},
        "forbidden_operations": {"network", "credential_access"},
        "forbidden_effects": ["No network or credential access."],
        "forbidden_effect_codes": {"network", "credential_access"},
        "rollback_plan": "Delete generated output.",
        "dry_run_required": False,
        "authorization_reference": "trusted-test-event",
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    values.update(overrides)
    return ActionContract(**values)


def contract_payload(contract_id: str, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "contract_id": contract_id,
        "version": 1,
        "attempt_id": f"attempt-{uuid4()}",
        "session_id": "session-1",
        "agent_id": "agent-1",
        "user_id": "user-1",
        "action": {
            "family": "shell",
            "raw_command": "touch /workspace/build/a.txt",
            "cwd": "/workspace",
        },
    }
    values.update(overrides)
    return values


def configured_app(
    *,
    contract: ActionContract | None = None,
    model: object | None = None,
    audit_store: object | None = None,
    approval_service: InMemoryApprovalService | None = None,
    executor_override: object | None = None,
    session_store: InMemorySessionStore | None = None,
    session_id: str = "session-1",
):
    now = datetime.now(timezone.utc)
    selected_contract = contract or make_contract()
    consumer = InMemoryTrustedEventConsumer(
        host_id="test-host",
        session_id=session_id,
        channel="test-direct-user",
    )
    contracts = InMemoryContractStore(trusted_event_consumer=consumer)
    sessions = session_store or InMemorySessionStore()
    contract_id = str(uuid4())
    receipt = consumer.consume(
        TrustedPromptEnvelope(
            event_id=f"event-{uuid4()}",
            nonce=f"nonce-{uuid4().hex}",
            host_id="test-host",
            session_id=session_id,
            channel="test-direct-user",
            prompt="Activate the reviewed test contract.",
            purpose="task_transition",
            contract_id=contract_id,
            contract_version=1,
            decision="approve",
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=5),
            authenticated=True,
        ),
        now=now,
    )
    record = contracts.create_active(
        selected_contract,
        session_id=session_id,
        authorization_source="trusted_user",
        created_at=now,
        contract_id=contract_id,
        expected_active_task_id=None,
        trusted_event=receipt,
    )
    executor = executor_override or FakeExecutor()
    selected_model = model if model is not None else CapturingAllowModel()
    selected_audit = audit_store if audit_store is not None else RecordingAuditStore()
    app = create_app(
        model=selected_model,  # type: ignore[arg-type]
        load_model=False,
        policy_profile=policy_profile(),
        load_policy=False,
        contract_store=contracts,
        session_store=sessions,
        approval_service=approval_service,
        audit_store=selected_audit,  # type: ignore[arg-type]
        executor=executor,  # type: ignore[arg-type]
        execution_environment=selected_contract.environment,
        execution_environment_context=selected_contract.environment_context,
    )
    return app, record, contracts, sessions, executor


class ContractApiTests(unittest.TestCase):
    def test_create_app_rejects_executor_and_canonical_cwd_divergence(self) -> None:
        executor = FakeExecutor()
        executor.container_workspace = "/executor-workspace"  # type: ignore[attr-defined]

        with self.assertRaisesRegex(
            ValueError,
            "execution_cwd must match",
        ):
            create_app(
                load_model=False,
                load_policy=False,
                executor=executor,
                execution_cwd="/canonical-workspace",
            )

    def test_create_app_accepts_equivalent_normalized_executor_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            executor = DockerExecutor(
                workspace=Path(workspace),
                container_workspace="/workspace/./build/..",
            )
            app = create_app(
                load_model=False,
                load_policy=False,
                executor=executor,
                execution_cwd="/workspace/",
            )
            docker_command = executor.build_command(
                command="ls",
                shell_type="bash",
                container_name="sentinel-test",
            )

        self.assertEqual(app.state.execution_cwd, "/workspace")
        self.assertEqual(
            docker_command[docker_command.index("--workdir") + 1],
            app.state.execution_cwd,
        )

    def test_execute_requires_attempt_id_before_executor(self) -> None:
        app, record, _, _, executor = configured_app()
        payload = contract_payload(record.contract_id)
        payload.pop("attempt_id")

        response = TestClient(app).post("/execute", json=payload)

        self.assertEqual(response.status_code, 400)
        self.assertIn("attempt_id", response.json()["detail"])
        self.assertEqual(executor.calls, [])

    def test_run_only_executor_fails_closed_before_admission(self) -> None:
        executor = RunOnlyExecutor()
        app, record, _, sessions, _ = configured_app(
            executor_override=executor,
        )

        response = TestClient(app).post(
            "/execute",
            json=contract_payload(
                record.contract_id,
                attempt_id="attempt-run-only",
            ),
        )

        self.assertEqual(response.json()["verdict"], "block")
        self.assertIn(
            "execution:unsupported_executor_capability",
            response.json()["reasons"],
        )
        self.assertEqual(executor.calls, [])
        self.assertIsNone(sessions.get_attempt("attempt-run-only"))

    def test_evaluate_may_omit_attempt_id(self) -> None:
        app, record, _, _, executor = configured_app()
        payload = contract_payload(record.contract_id)
        payload.pop("attempt_id")

        response = TestClient(app).post("/evaluate", json=payload)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["verdict"], "allow")
        self.assertEqual(executor.calls, [])

    def test_default_in_memory_audit_cannot_authorize_execution(self) -> None:
        app, record, _, _, executor = configured_app()
        app.state.audit_store = create_app(
            model=CapturingAllowModel(),
            load_model=False,
            policy_profile=policy_profile(),
            load_policy=False,
        ).state.audit_store

        response = TestClient(app).post(
            "/execute",
            json=contract_payload(record.contract_id),
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(executor.calls, [])

    def test_state_database_environment_uses_persistent_sqlite_stores(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "sentinel.sqlite3")
            previous = os.environ.get("SENTINEL_STATE_DB")
            os.environ["SENTINEL_STATE_DB"] = database
            try:
                app = create_app(
                    model=CapturingAllowModel(),
                    load_model=False,
                    policy_profile=policy_profile(),
                    load_policy=False,
                    executor=FakeExecutor(),
                )
            finally:
                if previous is None:
                    os.environ.pop("SENTINEL_STATE_DB", None)
                else:
                    os.environ["SENTINEL_STATE_DB"] = previous

            try:
                self.assertIsInstance(app.state.contract_store, SQLiteContractStore)
                self.assertIsInstance(app.state.session_store, SQLiteSessionStore)
                self.assertIsInstance(app.state.audit_store, SQLiteAuditStore)
            finally:
                app.state.contract_store.close()
                app.state.session_store.close()
                app.state.audit_store.close()

    def test_persistent_contract_allows_two_actions_and_blocks_third_target(self) -> None:
        app, record, _, sessions, executor = configured_app()
        client = TestClient(app)

        first = client.post(
            "/execute",
            json=contract_payload(record.contract_id),
        )
        second = client.post(
            "/execute",
            json=contract_payload(
                record.contract_id,
                action={
                    "family": "shell",
                    "raw_command": "touch /workspace/build/b.txt",
                    "cwd": "/workspace",
                },
            ),
        )
        third = client.post(
            "/execute",
            json=contract_payload(
                record.contract_id,
                action={
                    "family": "shell",
                    "raw_command": "touch /workspace/build/c.txt",
                    "cwd": "/workspace",
                },
            ),
        )

        self.assertEqual(first.json()["verdict"], "allow")
        self.assertEqual(second.json()["verdict"], "allow")
        self.assertEqual(third.json()["verdict"], "block")
        self.assertIn("contract:target_mismatch", third.json()["reasons"])
        self.assertEqual(len(executor.calls), 2)
        history = sessions.get_recent_actions("session-1")
        self.assertEqual(len(history), 2)
        serialized_history = str(
            [
                {
                    "summary": action.summary,
                    "resources": action.sensitive_resources,
                    "metadata": action.metadata,
                }
                for action in history
            ]
        )
        self.assertNotIn("/workspace/build", serialized_history)
        self.assertNotIn("touch ", serialized_history)

    def test_completed_duplicate_returns_stored_response_without_executor_replay(self) -> None:
        app, record, _, _, executor = configured_app()
        client = TestClient(app)
        payload = contract_payload(record.contract_id, attempt_id="attempt-stable")

        first = client.post("/execute", json=payload)
        duplicate = client.post("/execute", json=payload)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(duplicate.status_code, 200)
        self.assertEqual(duplicate.json(), first.json())
        self.assertEqual(len(executor.calls), 1)

    def test_attempt_id_reuse_with_changed_binding_is_conflict(self) -> None:
        app, record, _, _, executor = configured_app()
        client = TestClient(app)
        first = contract_payload(record.contract_id, attempt_id="attempt-stable")
        changed = contract_payload(
            record.contract_id,
            attempt_id="attempt-stable",
            action={
                "family": "shell",
                "raw_command": "touch /workspace/build/b.txt",
                "cwd": "/workspace",
            },
        )

        self.assertEqual(client.post("/execute", json=first).status_code, 200)
        conflict = client.post("/execute", json=changed)

        self.assertEqual(conflict.status_code, 409)
        self.assertIn("different execution binding", conflict.json()["detail"])
        self.assertEqual(len(executor.calls), 1)

    def test_concurrent_duplicate_executes_once_and_replays_same_response(self) -> None:
        executor = BlockingExecutor()
        app, record, _, _, _ = configured_app(executor_override=executor)
        payload = contract_payload(record.contract_id, attempt_id="attempt-concurrent")

        def execute() -> object:
            return TestClient(app).post("/execute", json=payload)

        with ThreadPoolExecutor(max_workers=2) as pool:
            first_future = pool.submit(execute)
            self.assertTrue(executor.started.wait(timeout=1))
            second_future = pool.submit(execute)
            time.sleep(0.05)
            executor.release.set()
            first = first_future.result(timeout=2)
            second = second_future.result(timeout=2)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.json(), second.json())
        self.assertEqual(len(executor.calls), 1)

    def test_concurrent_distinct_action_sees_first_admitted_history(self) -> None:
        executor = BlockingExecutor()
        model = CapturingAllowModel()
        app, record, _, _, _ = configured_app(
            model=model,
            executor_override=executor,
        )
        first_payload = contract_payload(
            record.contract_id,
            attempt_id="attempt-first",
        )
        second_payload = contract_payload(
            record.contract_id,
            attempt_id="attempt-second",
            action={
                "family": "shell",
                "raw_command": "touch /workspace/build/b.txt",
                "cwd": "/workspace",
            },
        )

        with ThreadPoolExecutor(max_workers=2) as pool:
            first_future = pool.submit(
                lambda: TestClient(app).post("/execute", json=first_payload)
            )
            self.assertTrue(executor.started.wait(timeout=1))
            second_future = pool.submit(
                lambda: TestClient(app).post("/execute", json=second_payload)
            )
            time.sleep(0.05)
            self.assertEqual(len(executor.calls), 1)
            executor.release.set()
            first = first_future.result(timeout=2)
            second = second_future.result(timeout=2)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertGreaterEqual(len(model.rows), 2)
        self.assertIn("shell write", str(model.rows[-1]["recent_actions"]))
        self.assertEqual(len(executor.calls), 2)

    def test_different_sessions_run_concurrently_after_durable_admission(
        self,
    ) -> None:
        _, first_record, first_store, _, _ = configured_app(
            session_id="session-1"
        )
        _, second_record, second_store, _, _ = configured_app(
            session_id="session-2"
        )
        executor = ConcurrentExecutor()
        app = create_app(
            model=CapturingAllowModel(),
            load_model=False,
            policy_profile=policy_profile(),
            load_policy=False,
            contract_store=GloballyGuardedContractStore(
                {
                    "session-1": first_store,
                    "session-2": second_store,
                }
            ),  # type: ignore[arg-type]
            session_store=InMemorySessionStore(),
            audit_store=RecordingAuditStore(),  # type: ignore[arg-type]
            executor=executor,
            execution_environment="sandbox",
        )
        first_payload = contract_payload(
            first_record.contract_id,
            attempt_id="attempt-session-1",
            session_id="session-1",
        )
        second_payload = contract_payload(
            second_record.contract_id,
            attempt_id="attempt-session-2",
            session_id="session-2",
        )

        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                first_future = pool.submit(
                    lambda: TestClient(app).post(
                        "/execute",
                        json=first_payload,
                    )
                )
                second_future = pool.submit(
                    lambda: TestClient(app).post(
                        "/execute",
                        json=second_payload,
                    )
                )
                self.assertTrue(executor.two_started.wait(timeout=1))
                executor.release.set()
                first = first_future.result(timeout=2)
                second = second_future.result(timeout=2)
        finally:
            executor.release.set()

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(executor.max_active, 2)

    def test_revocation_after_admission_does_not_cancel_running_attempt(
        self,
    ) -> None:
        executor = BlockingExecutor()
        app, record, contracts, _, _ = configured_app(
            executor_override=executor,
        )
        payload = contract_payload(
            record.contract_id,
            attempt_id="attempt-admitted-before-revocation",
        )

        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                execution_future = pool.submit(
                    lambda: TestClient(app).post(
                        "/execute",
                        json=payload,
                    )
                )
                self.assertTrue(executor.started.wait(timeout=1))
                suspension_future = pool.submit(
                    lambda: contracts.suspend(
                        record.contract_id,
                        expected_version=record.version,
                        suspended_at=datetime.now(timezone.utc),
                    )
                )
                suspended = suspension_future.result(timeout=1)
                self.assertEqual(suspended.status, "suspended")
                executor.release.set()
                response = execution_future.result(timeout=2)
        finally:
            executor.release.set()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["verdict"], "allow")
        self.assertEqual(len(executor.calls), 1)

    def test_caller_working_directory_cannot_change_authorized_target(self) -> None:
        app, record, _, _, executor = configured_app()
        response = TestClient(app).post(
            "/execute",
            json=contract_payload(
                record.contract_id,
                action={
                    "family": "shell",
                    "raw_command": "touch a.txt",
                    "cwd": "/workspace/build",
                },
            ),
        )

        self.assertEqual(response.json()["verdict"], "block")
        self.assertIn(
            "action:untrusted_working_directory",
            response.json()["reasons"],
        )
        self.assertEqual(executor.calls, [])

    def test_caller_history_is_ignored_in_favor_of_server_history(self) -> None:
        model = CapturingAllowModel()
        app, record, _, sessions, _ = configured_app(
            contract=make_contract(environment="dev"),
            model=model,
        )
        sessions.append_action(
            "session-1",
            SessionAction(
                action_type="file.read",
                summary="server-owned history",
                task_id=record.task_id,
            ),
        )
        client = TestClient(app)

        response = client.post(
            "/evaluate",
            json=contract_payload(
                record.contract_id,
                recent_actions=[
                    {
                        "type": "command",
                        "summary": "caller-forged history",
                    }
                ],
            ),
        )

        self.assertEqual(response.json()["verdict"], "allow")
        self.assertEqual(len(model.rows), 1)
        history = model.rows[0]["recent_actions"]
        self.assertIn("server-owned history", str(history))
        self.assertNotIn("caller-forged history", str(history))

    def test_evaluate_does_not_spend_token_and_execute_spends_it_once(self) -> None:
        approvals = InMemoryApprovalService(
            approval_id_factory=lambda: "approval-1",
            token_factory=lambda: "token-1",
        )
        audit = RecordingAuditStore()
        app, record, _, _, executor = configured_app(
            contract=make_contract(
                allowed_operations={"delete"},
                allowed_effects={"delete"},
                environment="production",
            ),
            approval_service=approvals,
            audit_store=audit,
        )
        client = TestClient(app)
        payload = contract_payload(
            record.contract_id,
            action={
                "family": "shell",
                "raw_command": "rm /workspace/build/a.txt",
                "cwd": "/workspace",
            },
        )
        pending = client.post("/evaluate", json=payload).json()
        token = ApproverHarness(approvals).approve(pending["approval_id"])
        with_token = {**payload, "approval_token": token}

        evaluated = client.post("/evaluate", json=with_token)
        executed = client.post("/execute", json=with_token)
        reused = client.post("/execute", json=with_token)

        self.assertEqual(evaluated.json()["verdict"], "confirm_required")
        self.assertEqual(executed.json()["verdict"], "allow")
        self.assertEqual(executed.json()["routing_path"], "approval")
        self.assertEqual(reused.json(), executed.json())
        self.assertEqual(len(executor.calls), 1)
        approval_events = [
            event for event in audit.events
            if event.event_type == "exact_action_approved"
        ]
        self.assertEqual(len(approval_events), 1)
        self.assertEqual(approval_events[0].user_id, "test-human")
        self.assertEqual(
            approval_events[0].details["approver_channel"],
            "isolated-test-harness",
        )

    def test_approval_token_is_not_spent_when_admission_audit_fails(self) -> None:
        approvals = InMemoryApprovalService(
            approval_id_factory=lambda: "approval-1",
            token_factory=lambda: "token-1",
        )
        audit = RecordingAuditStore()
        app, record, _, _, executor = configured_app(
            contract=make_contract(
                allowed_operations={"delete"},
                allowed_effects={"delete"},
                environment="production",
            ),
            approval_service=approvals,
            audit_store=audit,
        )
        payload = contract_payload(
            record.contract_id,
            action={
                "family": "shell",
                "raw_command": "rm /workspace/build/a.txt",
                "cwd": "/workspace",
            },
        )
        client = TestClient(app)
        pending = client.post("/evaluate", json=payload).json()
        token = ApproverHarness(approvals).approve(pending["approval_id"])
        audit.fail_after = len(audit.events) + 2

        response = client.post(
            "/execute",
            json={**payload, "approval_token": token},
        )

        self.assertEqual(response.status_code, 503)
        self.assertTrue(approvals.has_token(token))
        self.assertEqual(executor.calls, [])

    def test_approval_token_is_not_spent_when_executor_config_is_invalid(self) -> None:
        approvals = InMemoryApprovalService(
            approval_id_factory=lambda: "approval-1",
            token_factory=lambda: "token-1",
        )
        with tempfile.TemporaryDirectory() as workspace:
            executor = DockerExecutor(
                workspace=Path(workspace),
                container_user="0:0",
            )
            app, record, _, _, _ = configured_app(
                contract=make_contract(
                    allowed_operations={"delete"},
                    allowed_effects={"delete"},
                    environment="production",
                ),
                approval_service=approvals,
                executor_override=executor,
            )
            payload = contract_payload(
                record.contract_id,
                action={
                    "family": "shell",
                    "raw_command": "rm /workspace/build/a.txt",
                    "cwd": "/workspace",
                },
            )
            client = TestClient(app)
            pending = client.post("/evaluate", json=payload).json()
            token = ApproverHarness(approvals).approve(pending["approval_id"])

            response = client.post(
                "/execute",
                json={**payload, "approval_token": token},
            )

        self.assertEqual(response.json()["verdict"], "block")
        self.assertIn("execution:unsafe_workspace_target", response.json()["reasons"])
        self.assertTrue(approvals.has_token(token))

    def test_read_only_executor_rejects_mutation_before_spending_authority(self) -> None:
        approvals = InMemoryApprovalService(
            approval_id_factory=lambda: "approval-1",
            token_factory=lambda: "token-1",
        )
        audit = RecordingAuditStore()
        with tempfile.TemporaryDirectory() as workspace:
            executor = DockerExecutor(
                workspace=Path(workspace),
                read_only_workspace=True,
            )
            app, record, _, sessions, _ = configured_app(
                contract=make_contract(
                    allowed_operations={"delete"},
                    allowed_effects={"delete"},
                    environment="production",
                ),
                approval_service=approvals,
                audit_store=audit,
                executor_override=executor,
            )
            payload = contract_payload(
                record.contract_id,
                attempt_id="attempt-read-only-delete",
                action={
                    "family": "shell",
                    "raw_command": "rm /workspace/build/a.txt",
                    "cwd": "/workspace",
                },
            )
            client = TestClient(app)
            pending = client.post("/evaluate", json=payload).json()
            token = ApproverHarness(approvals).approve(pending["approval_id"])

            response = client.post(
                "/execute",
                json={**payload, "approval_token": token},
            )

        self.assertEqual(response.json()["verdict"], "block")
        self.assertIn(
            "execution:unsupported_executor_capability",
            response.json()["reasons"],
        )
        self.assertTrue(approvals.has_token(token))
        self.assertIsNone(sessions.get_attempt("attempt-read-only-delete"))
        self.assertNotIn(
            "execution_admitted",
            [event.event_type for event in audit.events],
        )

    def test_inactive_stale_and_session_mismatches_block(self) -> None:
        app, record, contracts, _, executor = configured_app()
        client = TestClient(app)

        stale = client.post(
            "/execute",
            json=contract_payload(record.contract_id, version=2),
        )
        wrong_session = client.post(
            "/execute",
            json=contract_payload(record.contract_id, session_id="session-2"),
        )
        contracts.suspend(
            record.contract_id,
            expected_version=1,
            suspended_at=datetime.now(timezone.utc),
        )
        inactive = client.post(
            "/execute",
            json=contract_payload(record.contract_id),
        )

        self.assertIn("contract:stale_version", stale.json()["reasons"])
        self.assertIn("contract:not_found", wrong_session.json()["reasons"])
        self.assertIn("contract:not_found", inactive.json()["reasons"])
        self.assertEqual(executor.calls, [])

    def test_audit_precedes_execution_and_post_event_follows(self) -> None:
        audit = RecordingAuditStore()
        app, record, _, _, executor = configured_app(audit_store=audit)
        response = TestClient(app).post(
            "/execute",
            json=contract_payload(record.contract_id),
        )
        self.assertEqual(response.json()["verdict"], "allow")
        self.assertEqual(
            [event.event_type for event in audit.events],
            ["pre_decision", "decision", "execution_admitted", "post_execution"],
        )
        self.assertEqual(audit.events[1].verdict, "allow")
        self.assertEqual(len(executor.calls), 1)

    def test_audit_failure_fails_closed_before_executor(self) -> None:
        audit = RecordingAuditStore(fail=True)
        app, record, _, _, executor = configured_app(audit_store=audit)
        response = TestClient(app).post(
            "/execute",
            json=contract_payload(record.contract_id),
        )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(executor.calls, [])

    def test_admission_audit_failure_prevents_execution(self) -> None:
        audit = RecordingAuditStore(fail_after=2)
        app, record, _, sessions, executor = configured_app(audit_store=audit)
        response = TestClient(app).post(
            "/execute",
            json=contract_payload(record.contract_id),
        )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(executor.calls, [])
        self.assertEqual(sessions.get_recent_actions("session-1"), [])

    def test_post_execution_audit_failure_returns_durable_response_without_replay(self) -> None:
        audit = RecordingAuditStore(fail_after=3)
        app, record, _, sessions, executor = configured_app(audit_store=audit)
        payload = contract_payload(record.contract_id, attempt_id="attempt-post-failure")
        client = TestClient(app)
        response = client.post("/execute", json=payload)
        replay = client.post("/execute", json=payload)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(replay.json(), response.json())
        self.assertEqual(len(executor.calls), 1)
        history = sessions.get_recent_actions("session-1")
        self.assertEqual(len(history), 1)
        self.assertTrue(history[0].metadata["admitted"])

    def test_completion_persistence_failure_marks_unknown_and_prevents_replay(self) -> None:
        sessions = FailingCompletionSessionStore()
        app, record, _, _, executor = configured_app(session_store=sessions)
        payload = contract_payload(
            record.contract_id,
            attempt_id="attempt-completion-failure",
        )
        client = TestClient(app)

        first = client.post("/execute", json=payload)
        replay = client.post("/execute", json=payload)

        self.assertEqual(first.status_code, 409)
        self.assertIn("manual inspection", first.json()["detail"])
        self.assertEqual(replay.status_code, 409)
        self.assertIn("unknown outcome", replay.json()["detail"])
        self.assertEqual(len(executor.calls), 1)

    def test_blocked_action_records_verdict_and_reasons_before_return(self) -> None:
        audit = RecordingAuditStore()
        app, record, _, _, executor = configured_app(audit_store=audit)

        response = TestClient(app).post(
            "/execute",
            json=contract_payload(
                record.contract_id,
                action={
                    "family": "shell",
                    "raw_command": "touch /workspace/build/not-authorized.txt",
                    "cwd": "/workspace",
                },
            ),
        )

        self.assertEqual(response.json()["verdict"], "block")
        self.assertEqual([event.event_type for event in audit.events], ["pre_decision", "decision"])
        self.assertEqual(audit.events[-1].verdict, "block")
        self.assertIn("contract:target_mismatch", audit.events[-1].reason_codes)
        self.assertEqual(executor.calls, [])

    def test_policy_load_failure_blocks_matching_noncritical_action(self) -> None:
        app, record, contracts, sessions, executor = configured_app()
        app.state.policy_profile = None
        app.state.policy_load_error = "invalid policy"
        response = TestClient(app).post(
            "/execute",
            json=contract_payload(record.contract_id),
        )
        self.assertEqual(response.json()["verdict"], "block")
        self.assertIn("policy:unavailable", response.json()["reasons"])
        self.assertEqual(executor.calls, [])
        self.assertIsNotNone(contracts.get_active("session-1"))
        self.assertEqual(sessions.get_recent_actions("session-1"), [])

    def test_critical_rule_short_circuits_model_even_with_contract_mismatch(self) -> None:
        model = CapturingAllowModel()
        app, record, _, _, executor = configured_app(model=model)
        response = TestClient(app).post(
            "/execute",
            json=contract_payload(
                record.contract_id,
                action={
                    "family": "shell",
                    "raw_command": "rm -rf /",
                    "cwd": "/workspace",
                },
            ),
        )
        self.assertEqual(response.json()["verdict"], "block")
        self.assertIn("rule:root_filesystem_deletion", response.json()["reasons"])
        self.assertEqual(model.rows, [])
        self.assertEqual(executor.calls, [])


if __name__ == "__main__":
    unittest.main()
