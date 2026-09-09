from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from itertools import count
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.api.main import create_app  # noqa: E402
from sentinel.approval import InMemoryApprovalService  # noqa: E402
from sentinel.audit import SQLiteAuditStore  # noqa: E402
from sentinel.contracts import (  # noqa: E402
    ActionContract,
    InMemoryContractStore,
    InMemoryTrustedEventConsumer,
    TrustedPromptEnvelope,
)
from sentinel.control import (  # noqa: E402
    ControlConfig,
    SQLiteWorkspaceBindingStore,
    review_workspace,
)
from sentinel.decision.policy import parse_policy_profile  # noqa: E402
from sentinel.execution import DockerExecutor, ExecutionResult  # noqa: E402

API_HOST = "127.0.0.1:8000"
UI_ORIGIN = "http://127.0.0.1:3000"
PAIRING_CAPABILITY = "approval-pairing-" + ("a" * 32)
INTERNAL_TOKEN = "internal-approval-token-" + ("b" * 32)


class RecordingRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(
        self,
        args: list[str],
        **_: Any,
    ) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(args)
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout=b"unexpected",
            stderr=b"",
        )


class FakeExecutor:
    container_workspace = "/workspace"

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.calls: list[dict[str, str]] = []

    def validate_configuration(self) -> None:
        return None

    def validate_operation(self, operation: str) -> None:
        del operation

    def validate_targets(self, targets: list[str]) -> None:
        del targets

    def run(self, *, command: str, shell_type: str) -> ExecutionResult:
        self.calls.append({"command": command, "shell_type": shell_type})
        return ExecutionResult(
            stdout="simulated\n",
            stderr="",
            exit_code=0,
            timed_out=False,
            duration_ms=1,
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
            "name": "control-approval-test",
            "version": 1,
            "default_environment": "sandbox",
            "environments": environments,
        }
    )


def make_contract() -> ActionContract:
    return ActionContract(
        objective="Delete one disposable build marker after confirmation.",
        allowed_operations={"delete"},
        allowed_tools={"shell"},
        exact_targets=["/workspace/build/marker.txt"],
        environment="production",
        maximum_scope="exact",
        expected_side_effects=["Delete the disposable marker."],
        allowed_effects={"delete"},
        forbidden_operations={"network", "credential_access"},
        forbidden_effects=["No network or credential access."],
        forbidden_effect_codes={"network", "credential_access"},
        rollback_plan="Recreate the disposable marker.",
        dry_run_required=False,
        authorization_reference="protected-control-test",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )


@contextmanager
def approval_control_client(
    *,
    use_fake_executor: bool,
) -> Iterator[
    tuple[
        TestClient,
        object,
        InMemoryApprovalService,
        SQLiteAuditStore,
        FakeExecutor | DockerExecutor,
        RecordingRunner | None,
    ]
]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        repository = root / "repository"
        repository.mkdir()
        (repository / ".git").mkdir()
        (repository / "build").mkdir()
        database = root / "sentinel.sqlite3"

        binding_store = SQLiteWorkspaceBindingStore(database)
        supervision = binding_store.bind(review_workspace(repository))
        control_host_id = (
            f"sentinel-control:{supervision.workspace.identity_sha256}"
        )
        now = datetime.now(timezone.utc)
        consumer = InMemoryTrustedEventConsumer(
            host_id=control_host_id,
            session_id=supervision.session_id,
            channel="protected_local_ui",
        )
        contracts = InMemoryContractStore(trusted_event_consumer=consumer)
        contract_id = str(uuid4())
        receipt = consumer.consume(
            TrustedPromptEnvelope(
                event_id=f"event-{uuid4()}",
                nonce=f"nonce-{uuid4().hex}",
                host_id=control_host_id,
                session_id=supervision.session_id,
                channel="protected_local_ui",
                prompt="Activate the fixed approval test contract.",
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
            make_contract(),
            session_id=supervision.session_id,
            authorization_source="protected_local_ui",
            created_at=now,
            contract_id=contract_id,
            expected_active_task_id=None,
            trusted_event=receipt,
        )
        approval_ids = count(1)
        approvals = InMemoryApprovalService(
            approval_id_factory=lambda: f"approval-control-{next(approval_ids)}",
            token_factory=lambda: INTERNAL_TOKEN,
        )
        audit = SQLiteAuditStore(database)
        runner = None if use_fake_executor else RecordingRunner()
        executor: FakeExecutor | DockerExecutor
        if use_fake_executor:
            executor = FakeExecutor(repository)
        else:
            executor = DockerExecutor(
                workspace=repository,
                runner=runner,
            )
        config = ControlConfig(
            workspace=repository,
            pairing_capability=PAIRING_CAPABILITY,
            api_host=API_HOST,
            ui_origin=UI_ORIGIN,
        )
        with patch.dict(
            os.environ,
            {"SENTINEL_STATE_DB": str(database)},
            clear=False,
        ):
            app = create_app(
                load_model=False,
                policy_profile=policy_profile(),
                load_policy=False,
                contract_store=contracts,
                approval_service=approvals,
                audit_store=audit,
                executor=executor,
                execution_environment="production",
                control_config=config,
                control_binding_store=binding_store,
            )
            with TestClient(
                app,
                base_url=f"http://{API_HOST}",
            ) as client:
                yield client, record, approvals, audit, executor, runner
        audit.close()
        binding_store.close()


def pair(client: TestClient) -> None:
    response = client.post(
        "/control/pair/exchange",
        headers={"Origin": UI_ORIGIN},
        json={"capability": PAIRING_CAPABILITY},
    )
    if response.status_code != 200:
        raise AssertionError(response.text)


def execution_payload(record: object) -> dict[str, object]:
    return {
        "contract_id": record.contract_id,
        "version": record.version,
        "attempt_id": "approval-attempt-1",
        "session_id": record.session_id,
        "agent_id": "demo-agent",
        "user_id": "caller-claimed-user",
        "action": {
            "family": "shell",
            "raw_command": "rm /workspace/build/marker.txt",
            "cwd": "/workspace",
        },
        "recent_actions": [],
    }


class ControlApprovalTests(unittest.TestCase):
    def test_unpaired_browser_cannot_list_or_act_on_approvals(self) -> None:
        with approval_control_client(use_fake_executor=False) as (
            client,
            record,
            _,
            _,
            _,
            _,
        ):
            pending = client.post("/execute", json=execution_payload(record)).json()
            approval_id = pending["approval_id"]

            listed = client.get(
                "/control/approvals",
                headers={"Origin": UI_ORIGIN},
            )
            approved = client.post(
                f"/control/approvals/{approval_id}/approve",
                headers={"Origin": UI_ORIGIN},
            )

        self.assertEqual(listed.status_code, 401)
        self.assertEqual(approved.status_code, 401)

    def test_pending_list_exposes_complete_action_but_never_the_token(self) -> None:
        with approval_control_client(use_fake_executor=False) as (
            client,
            record,
            _,
            _,
            _,
            _,
        ):
            pair(client)
            pending = client.post("/execute", json=execution_payload(record))
            listed = client.get(
                "/control/approvals",
                headers={"Origin": UI_ORIGIN},
            )

        self.assertEqual(pending.json()["verdict"], "confirm_required")
        self.assertEqual(listed.status_code, 200)
        item = listed.json()["approvals"][0]
        self.assertEqual(item["attempt_id"], "approval-attempt-1")
        self.assertEqual(item["operation"], "delete")
        self.assertEqual(item["targets"], ["/workspace/build/marker.txt"])
        self.assertEqual(item["task_id"], record.task_id)
        self.assertEqual(item["authority_epoch"], record.authority_epoch)
        self.assertTrue(Path(item["workspace"]).is_absolute())
        self.assertEqual(Path(item["workspace"]).name, "repository")
        self.assertNotIn(INTERNAL_TOKEN, pending.text)
        self.assertNotIn(INTERNAL_TOKEN, listed.text)

    def test_evaluate_does_not_create_an_invisible_control_approval(self) -> None:
        with approval_control_client(use_fake_executor=False) as (
            client,
            record,
            approvals,
            _,
            _,
            _,
        ):
            pair(client)
            evaluated = client.post(
                "/evaluate",
                json=execution_payload(record),
            )
            listed = client.get(
                "/control/approvals",
                headers={"Origin": UI_ORIGIN},
            )

        self.assertEqual(evaluated.json()["verdict"], "confirm_required")
        self.assertIsNone(evaluated.json()["approval_id"])
        self.assertEqual(approvals.list_pending(), [])
        self.assertEqual(listed.json()["approvals"], [])

    def test_unverified_authority_compensation_blocks_control_execution(self) -> None:
        with approval_control_client(use_fake_executor=True) as (
            client,
            record,
            _,
            _,
            executor,
            _,
        ):
            pair(client)
            client.app.state.authority_service._authority_available = False

            blocked = client.post("/execute", json=execution_payload(record))
            active = client.get(
                "/control/authority/active",
                headers={"Origin": UI_ORIGIN},
            )
            status = client.get(
                "/control/status",
                headers={"Origin": UI_ORIGIN},
            )

        self.assertEqual(blocked.json()["verdict"], "block")
        self.assertIn(
            "authority:audit_compensation_unverified",
            blocked.json()["reasons"],
        )
        self.assertEqual(executor.calls, [])
        self.assertIsNone(active.json()["active_contract"])
        self.assertEqual(status.json()["runtime"]["rules"]["status"], "unavailable")

    def test_replacement_authority_invalidates_an_existing_approval(self) -> None:
        with approval_control_client(use_fake_executor=False) as (
            client,
            record,
            approvals,
            _,
            _,
            _,
        ):
            pair(client)
            pending = client.post("/execute", json=execution_payload(record)).json()
            authority = client.app.state.authority_service
            consumer = client.app.state.control_event_consumer
            now = datetime.now(timezone.utc)
            replacement = authority.create_proposed(
                make_contract(),
                session_id=record.session_id,
                authorization_source="protected_local_ui",
                created_at=now,
            )
            receipt = consumer.consume(
                TrustedPromptEnvelope(
                    event_id=f"event-{uuid4()}",
                    nonce=f"nonce-{uuid4().hex}",
                    host_id=consumer.binding[0],
                    session_id=record.session_id,
                    channel="protected_local_ui",
                    prompt="Activate replacement authority.",
                    purpose="task_transition",
                    contract_id=replacement.contract_id,
                    contract_version=replacement.version,
                    decision="approve",
                    issued_at=now - timedelta(seconds=1),
                    expires_at=now + timedelta(minutes=5),
                    authenticated=True,
                ),
                now=now,
            )
            authority.activate_proposed(
                replacement.contract_id,
                expected_version=replacement.version,
                expected_active_task_id=record.task_id,
                trusted_event=receipt,
                activated_at=now,
            )
            pending_after_activation = approvals.list_pending()

            listed = client.get(
                "/control/approvals",
                headers={"Origin": UI_ORIGIN},
            )
            approved = client.post(
                f"/control/approvals/{pending['approval_id']}/approve",
                headers={"Origin": UI_ORIGIN},
                json={"typed_target": "/workspace/build/marker.txt"},
            )

        self.assertEqual(pending_after_activation, [])
        self.assertEqual(listed.json()["approvals"], [])
        self.assertEqual(approved.status_code, 409)
        self.assertEqual(approvals.list_pending(), [])

    def test_distinct_attempts_receive_distinct_exact_approvals(self) -> None:
        with approval_control_client(use_fake_executor=False) as (
            client,
            record,
            _,
            _,
            _,
            _,
        ):
            pair(client)
            first_payload = execution_payload(record)
            second_payload = {
                **first_payload,
                "attempt_id": "approval-attempt-2",
            }
            first = client.post("/execute", json=first_payload).json()
            second = client.post("/execute", json=second_payload).json()
            listed = client.get(
                "/control/approvals",
                headers={"Origin": UI_ORIGIN},
            ).json()["approvals"]

        self.assertNotEqual(first["approval_id"], second["approval_id"])
        self.assertEqual(
            {item["attempt_id"] for item in listed},
            {"approval-attempt-1", "approval-attempt-2"},
        )

    def test_denial_records_evidence_and_launches_nothing(self) -> None:
        with approval_control_client(use_fake_executor=False) as (
            client,
            record,
            _,
            audit,
            _,
            runner,
        ):
            pair(client)
            pending = client.post("/execute", json=execution_payload(record)).json()
            denied = client.post(
                f"/control/approvals/{pending['approval_id']}/deny",
                headers={"Origin": UI_ORIGIN},
            )
            repeated = client.post(
                f"/control/approvals/{pending['approval_id']}/deny",
                headers={"Origin": UI_ORIGIN},
            )
            active = client.app.state.contract_store.get_active(record.session_id)
            events = audit.query()

        self.assertEqual(denied.json()["status"], "denied")
        self.assertIsNone(denied.json()["retry"])
        self.assertEqual(repeated.status_code, 409)
        self.assertEqual(runner.calls, [])
        self.assertEqual(active.contract_id, record.contract_id)
        denial_events = [
            event for event in events if event.event_type == "exact_action_denied"
        ]
        self.assertEqual(len(denial_events), 1)
        self.assertEqual(denial_events[0].task_id, record.task_id)

    def test_approval_retries_once_without_exposing_or_retaining_token(self) -> None:
        with approval_control_client(use_fake_executor=True) as (
            client,
            record,
            approvals,
            audit,
            executor,
            _,
        ):
            pair(client)
            payload = execution_payload(record)
            pending = client.post("/execute", json=payload).json()
            wrong_target = client.post(
                f"/control/approvals/{pending['approval_id']}/approve",
                headers={"Origin": UI_ORIGIN},
                json={"typed_target": "/workspace/build/other.txt"},
            )
            approved = client.post(
                f"/control/approvals/{pending['approval_id']}/approve",
                headers={"Origin": UI_ORIGIN},
                json={"typed_target": "/workspace/build/marker.txt"},
            )
            replay = client.post("/execute", json=payload)
            repeated_approval = client.post(
                f"/control/approvals/{pending['approval_id']}/approve",
                headers={"Origin": UI_ORIGIN},
                json={"typed_target": "/workspace/build/marker.txt"},
            )
            events = audit.query()

        self.assertEqual(wrong_target.status_code, 409)
        self.assertEqual(approved.status_code, 200)
        self.assertEqual(approved.json()["status"], "approved")
        self.assertEqual(approved.json()["retry"]["verdict"], "allow")
        self.assertEqual(replay.json(), approved.json()["retry"])
        self.assertEqual(repeated_approval.status_code, 409)
        self.assertEqual(len(executor.calls), 1)
        self.assertFalse(approvals.has_token(INTERNAL_TOKEN))
        self.assertNotIn(INTERNAL_TOKEN, approved.text)
        self.assertNotIn(INTERNAL_TOKEN, replay.text)
        self.assertNotIn(INTERNAL_TOKEN, repr(events))
        approval_events = [
            event for event in events if event.event_type == "exact_action_approved"
        ]
        self.assertEqual(len(approval_events), 1)
        self.assertEqual(approval_events[0].task_id, record.task_id)
        self.assertEqual(
            len([event for event in events if event.event_type == "execution_admitted"]),
            1,
        )

    def test_read_only_fallback_approves_but_does_not_execute_a_write(self) -> None:
        with approval_control_client(use_fake_executor=False) as (
            client,
            record,
            approvals,
            _,
            _,
            runner,
        ):
            pair(client)
            pending = client.post(
                "/execute",
                json=execution_payload(record),
            ).json()
            approved = client.post(
                f"/control/approvals/{pending['approval_id']}/approve",
                headers={"Origin": UI_ORIGIN},
                json={"typed_target": "/workspace/build/marker.txt"},
            )

        self.assertEqual(approved.status_code, 200)
        self.assertEqual(approved.json()["retry"]["verdict"], "block")
        self.assertIn(
            "execution:unsupported_executor_capability",
            approved.json()["retry"]["reasons"],
        )
        self.assertEqual(runner.calls, [])
        self.assertFalse(approvals.has_token(INTERNAL_TOKEN))

    def test_concurrent_approval_clicks_trigger_only_one_retry(self) -> None:
        with approval_control_client(use_fake_executor=True) as (
            client,
            record,
            _,
            _,
            executor,
            _,
        ):
            pair(client)
            pending = client.post(
                "/execute",
                json=execution_payload(record),
            ).json()
            path = f"/control/approvals/{pending['approval_id']}/approve"

            with ThreadPoolExecutor(max_workers=2) as pool:
                responses = list(
                    pool.map(
                        lambda _: client.post(
                            path,
                            headers={"Origin": UI_ORIGIN},
                            json={
                                "typed_target": "/workspace/build/marker.txt"
                            },
                        ),
                        range(2),
                    )
                )

        self.assertEqual(sorted(response.status_code for response in responses), [200, 409])
        self.assertEqual(len(executor.calls), 1)


if __name__ == "__main__":
    unittest.main()
