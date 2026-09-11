from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from unittest.mock import patch

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.api.main import create_app  # noqa: E402
from sentinel.audit import AuditEvent, AuditHealth, AuditStoreError  # noqa: E402
from sentinel.control import ControlConfig  # noqa: E402
from sentinel.execution import ExecutionResult  # noqa: E402

API_HOST = "127.0.0.1:8000"
UI_ORIGIN = "http://127.0.0.1:3000"
PAIRING_CAPABILITY = "contract-pairing-" + ("c" * 32)


class FakeExecutor:
    container_workspace = "/workspace"

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace

    def validate_configuration(self) -> None:
        return None

    def validate_operation(self, operation: str) -> None:
        del operation

    def validate_targets(self, targets: list[str]) -> None:
        del targets

    def run(self, *, command: str, shell_type: str) -> ExecutionResult:
        del command, shell_type
        raise AssertionError("contract lifecycle tests must not execute commands")


class FailingAuditStore:
    @property
    def health(self) -> AuditHealth:
        return AuditHealth(
            status="degraded",
            detail="forced failure",
            fallback_event_count=0,
            fallback_capacity=0,
        )

    def write(self, event: AuditEvent) -> None:
        del event
        raise AuditStoreError("forced audit failure")

    def write_required(self, event: AuditEvent) -> None:
        self.write(event)

    def query(self, *args: object, **kwargs: object) -> list[AuditEvent]:
        del args, kwargs
        return []


@contextmanager
def configured_control(
    *,
    audit_store: object | None = None,
) -> Iterator[tuple[TestClient, object, Path]]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        repository = root / "repository"
        repository.mkdir()
        (repository / ".git").mkdir()
        database = root / "sentinel.sqlite3"
        with patch.dict(
            os.environ,
            {"SENTINEL_STATE_DB": str(database)},
            clear=False,
        ):
            app = create_app(
                load_model=False,
                load_policy=False,
                executor=FakeExecutor(repository),
                audit_store=audit_store,  # type: ignore[arg-type]
                control_config=ControlConfig(
                    workspace=repository,
                    pairing_capability=PAIRING_CAPABILITY,
                    api_host=API_HOST,
                    ui_origin=UI_ORIGIN,
                ),
            )
            with TestClient(
                app,
                base_url=f"http://{API_HOST}",
            ) as client:
                yield client, app, database


def pair(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/control/pair/exchange",
        headers={"Origin": UI_ORIGIN},
        json={"capability": PAIRING_CAPABILITY},
    )
    if response.status_code != 200:
        raise AssertionError(response.text)
    return {"Origin": UI_ORIGIN}


def accepted_contract(
    *,
    target: str = "/workspace/build/result.txt",
) -> dict[str, object]:
    return {
        "operation": "write",
        "exact_targets": [target],
        "environment": "sandbox",
        "expected_side_effects": [f"Create exactly {target}."],
        "allowed_effects": ["write"],
        "forbidden_operations": ["credential_access", "network"],
        "forbidden_effects": ["No credential access or network communication."],
        "forbidden_effect_codes": ["credential_access", "network"],
        "rollback_plan": f"Delete {target}.",
        "dry_run_required": False,
        "expires_in_minutes": 60,
    }


def state_file_bytes(database: Path) -> bytes:
    payload = b""
    for candidate in database.parent.glob(f"{database.name}*"):
        if candidate.is_file():
            payload += candidate.read_bytes()
    return payload


class ControlContractTests(unittest.TestCase):
    def test_target_suggestions_list_workspace_paths_as_container_paths(self) -> None:
        with configured_control() as (client, app, _):
            workspace = Path(app.state.supervision_binding.workspace.path)
            (workspace / "api.py").write_text("print('hi')\n")
            (workspace / "build").mkdir()
            (workspace / "build" / "result.txt").write_text("x")
            (workspace / "node_modules").mkdir()
            (workspace / "node_modules" / "junk.js").write_text("x")
            (workspace / ".env").write_text("SECRET=1")

            unpaired = client.get("/control/targets", headers={"Origin": UI_ORIGIN})
            headers = pair(client)
            response = client.get("/control/targets", headers=headers)

        self.assertEqual(unpaired.status_code, 401)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["workspace_root"], "/workspace")
        self.assertFalse(body["truncated"])
        paths = {item["path"]: item["kind"] for item in body["paths"]}
        self.assertEqual(paths["/workspace/api.py"], "file")
        self.assertEqual(paths["/workspace/build"], "directory")
        self.assertEqual(paths["/workspace/build/result.txt"], "file")
        # Hidden entries and dependency folders are noise in a target picker.
        self.assertNotIn("/workspace/.env", paths)
        self.assertNotIn("/workspace/.git", paths)
        self.assertFalse(any(path.startswith("/workspace/node_modules") for path in paths))

    def test_unpaired_browser_cannot_draft_activate_or_query_audit(self) -> None:
        with configured_control() as (client, _, _):
            draft = client.post(
                "/control/contracts/draft",
                headers={"Origin": UI_ORIGIN},
                json={"raw_prompt": "Read /workspace/README.md in sandbox."},
            )
            activate = client.post(
                "/control/contracts/activate",
                headers={"Origin": UI_ORIGIN},
                json={
                    "contract_id": "contract-1",
                    "expected_version": 1,
                },
            )
            audit = client.get(
                "/control/audit",
                headers={"Origin": UI_ORIGIN},
            )

        self.assertEqual(draft.status_code, 401)
        self.assertEqual(activate.status_code, 401)
        self.assertEqual(audit.status_code, 401)

    def test_draft_is_deterministic_and_cannot_activate_itself(self) -> None:
        marker = "RAW-PROMPT-ONLY-7f3dff4d"
        raw_prompt = (
            "Write /workspace/build/result.txt in sandbox. "
            f"Private note {marker}."
        )
        with configured_control() as (client, _, database):
            origin = pair(client)
            response = client.post(
                "/control/contracts/draft",
                headers=origin,
                json={"raw_prompt": raw_prompt},
            )
            active = client.get(
                "/control/authority/active",
                headers=origin,
            )
            persisted = state_file_bytes(database)

        body = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            body["prompt_sha256"],
            hashlib.sha256(raw_prompt.encode("utf-8")).hexdigest(),
        )
        self.assertIsNone(body["proposed_contract"])
        self.assertEqual(active.json()["active_contract"], None)
        self.assertTrue(
            all(item["requires_review"] for item in body["suggestions"])
        )
        self.assertIn(
            "rollback_plan",
            [question["field"] for question in body["questions"]],
        )
        self.assertNotIn(marker.encode("utf-8"), persisted)

    def test_accepted_draft_persists_hash_then_requires_explicit_activation(
        self,
    ) -> None:
        marker = "RAW-PROMPT-ONLY-c52737bd"
        raw_prompt = (
            "Write /workspace/build/result.txt in sandbox. "
            f"Transient note {marker}."
        )
        with configured_control() as (client, _, database):
            origin = pair(client)
            drafted = client.post(
                "/control/contracts/draft",
                headers=origin,
                json={
                    "raw_prompt": raw_prompt,
                    "accepted_contract": accepted_contract(),
                },
            )
            proposed = drafted.json()["proposed_contract"]
            before = client.get(
                "/control/authority/active",
                headers=origin,
            )
            activated = client.post(
                "/control/contracts/activate",
                headers=origin,
                json={
                    "contract_id": proposed["contract_id"],
                    "expected_version": proposed["version"],
                    "expected_active_task_id": None,
                },
            )
            after = client.get(
                "/control/authority/active",
                headers=origin,
            )
            repeated = client.post(
                "/control/contracts/activate",
                headers=origin,
                json={
                    "contract_id": proposed["contract_id"],
                    "expected_version": proposed["version"],
                    "expected_active_task_id": None,
                },
            )
            persisted = state_file_bytes(database)

        prompt_hash = hashlib.sha256(raw_prompt.encode("utf-8")).hexdigest()
        self.assertEqual(drafted.status_code, 200)
        self.assertEqual(proposed["status"], "proposed")
        self.assertEqual(
            proposed["contract"]["source_prompt_sha256"],
            prompt_hash,
        )
        self.assertIsNone(proposed["contract"]["approved_payload_sha256"])
        self.assertNotIn(marker, proposed["contract"]["objective"])
        self.assertIsNone(before.json()["active_contract"])
        self.assertEqual(activated.status_code, 200)
        self.assertEqual(
            activated.json()["active_contract"]["status"],
            "active",
        )
        self.assertEqual(
            after.json()["active_contract"]["contract_id"],
            proposed["contract_id"],
        )
        self.assertEqual(repeated.status_code, 409)
        self.assertNotIn(marker.encode("utf-8"), persisted)
        self.assertIn(prompt_hash.encode("ascii"), persisted)

    def test_activation_compare_and_swap_prevents_silent_task_replacement(
        self,
    ) -> None:
        with configured_control() as (client, _, _):
            origin = pair(client)
            first = client.post(
                "/control/contracts/draft",
                headers=origin,
                json={
                    "raw_prompt": "Write /workspace/build/one.txt in sandbox.",
                    "accepted_contract": accepted_contract(
                        target="/workspace/build/one.txt"
                    ),
                },
            ).json()["proposed_contract"]
            first_active = client.post(
                "/control/contracts/activate",
                headers=origin,
                json={
                    "contract_id": first["contract_id"],
                    "expected_version": 1,
                    "expected_active_task_id": None,
                },
            ).json()["active_contract"]
            second = client.post(
                "/control/contracts/draft",
                headers=origin,
                json={
                    "raw_prompt": "Write /workspace/build/two.txt in sandbox.",
                    "accepted_contract": accepted_contract(
                        target="/workspace/build/two.txt"
                    ),
                },
            ).json()["proposed_contract"]
            stale = client.post(
                "/control/contracts/activate",
                headers=origin,
                json={
                    "contract_id": second["contract_id"],
                    "expected_version": 1,
                    "expected_active_task_id": None,
                },
            )
            current = client.get(
                "/control/authority/active",
                headers=origin,
            )

        self.assertEqual(stale.status_code, 409)
        self.assertEqual(
            current.json()["active_contract"]["task_id"],
            first_active["task_id"],
        )

    def test_validation_errors_do_not_reflect_raw_prompt(self) -> None:
        marker = "RAW-VALIDATION-MARKER-e31626a9"
        with configured_control() as (client, _, _):
            origin = pair(client)
            response = client.post(
                "/control/contracts/draft",
                headers=origin,
                json={
                    "raw_prompt": marker,
                    "accepted_contract": {
                        **accepted_contract(),
                        "unexpected": marker,
                    },
                },
            )

        self.assertEqual(response.status_code, 422)
        self.assertNotIn(marker, response.text)
        self.assertTrue(
            all(
                "input" not in error
                for error in response.json()["detail"]
            )
        )

    def test_audit_failure_does_not_persist_or_reflect_raw_prompt(self) -> None:
        marker = "RAW-AUDIT-FAILURE-MARKER-a52c8d7e"
        raw_prompt = (
            "Write /workspace/build/result.txt in sandbox. "
            f"Transient note {marker}."
        )
        with configured_control(audit_store=FailingAuditStore()) as (
            client,
            _,
            database,
        ):
            origin = pair(client)
            response = client.post(
                "/control/contracts/draft",
                headers=origin,
                json={
                    "raw_prompt": raw_prompt,
                    "accepted_contract": accepted_contract(),
                },
            )
            persisted = state_file_bytes(database)

        self.assertEqual(response.status_code, 409)
        self.assertNotIn(marker, response.text)
        self.assertNotIn(marker.encode("utf-8"), persisted)

    def test_audit_route_is_implicitly_scoped_to_supervision_session(self) -> None:
        with configured_control() as (client, app, _):
            origin = pair(client)
            session_id = app.state.supervision_binding.session_id
            app.state.audit_store.write(
                AuditEvent(
                    event_type="visible-event",
                    session_id=session_id,
                    task_id="task-visible",
                )
            )
            app.state.audit_store.write(
                AuditEvent(
                    event_type="hidden-event",
                    session_id="other-session",
                    task_id="task-hidden",
                )
            )
            all_events = client.get(
                "/control/audit",
                headers=origin,
            )
            task_events = client.get(
                "/control/audit",
                headers=origin,
                params={"task_id": "task-visible"},
            )

        self.assertIn(
            "visible-event",
            [event["event_type"] for event in all_events.json()["events"]],
        )
        self.assertNotIn(
            "hidden-event",
            [event["event_type"] for event in all_events.json()["events"]],
        )
        self.assertEqual(
            [event["event_type"] for event in task_events.json()["events"]],
            ["visible-event"],
        )


if __name__ == "__main__":
    unittest.main()
