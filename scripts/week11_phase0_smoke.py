#!/usr/bin/env python3
"""Prove the Week 11 pairing, approval retry, and scoped Docker write path."""

from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fastapi.testclient import TestClient  # noqa: E402

from sentinel.api.main import create_app  # noqa: E402
from sentinel.approval import InMemoryApprovalService  # noqa: E402
from sentinel.audit import SQLiteAuditStore  # noqa: E402
from sentinel.contracts import (  # noqa: E402
    ActionContract,
    InMemoryTrustedEventConsumer,
    SQLiteContractStore,
    TrustedPromptEnvelope,
)
from sentinel.control import (  # noqa: E402
    ControlConfig,
    SQLiteWorkspaceBindingStore,
    generate_pairing_capability,
    review_workspace,
)
from sentinel.decision.policy import parse_policy_profile  # noqa: E402
from sentinel.execution import DockerExecutor  # noqa: E402
from sentinel.session import SQLiteSessionStore  # noqa: E402

API_HOST = "127.0.0.1:8000"
UI_ORIGIN = "http://127.0.0.1:3000"
MARKER_TARGET = "/workspace/build/approved-marker.txt"


def _policy_profile():
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
            "name": "week11-phase0-smoke",
            "version": 1,
            "default_environment": "sandbox",
            "environments": environments,
        }
    )


def _contract() -> ActionContract:
    return ActionContract(
        objective="Create one marker in Sentinel's disposable build directory.",
        allowed_operations={"write"},
        allowed_tools={"shell"},
        exact_targets=[MARKER_TARGET],
        environment="production",
        maximum_scope="exact",
        expected_side_effects=["Create one disposable marker file."],
        allowed_effects={"write"},
        forbidden_operations={"delete", "network", "credential_access"},
        forbidden_effects=["No deletion, network, or credential access."],
        forbidden_effect_codes={"delete", "network", "credential_access"},
        rollback_plan="Delete the disposable repository.",
        dry_run_required=False,
        authorization_reference="week11-phase0-smoke",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )


def _activate_contract(
    contracts: SQLiteContractStore,
    consumer: InMemoryTrustedEventConsumer,
    session_id: str,
):
    now = datetime.now(timezone.utc)
    contract_id = str(uuid4())
    receipt = consumer.consume(
        TrustedPromptEnvelope(
            event_id=f"event-{uuid4()}",
            nonce=f"nonce-{uuid4().hex}",
            host_id=consumer.binding[0],
            session_id=session_id,
            channel="protected_local_ui",
            prompt="Activate the fixed Phase 0 smoke contract.",
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
    return contracts.create_active(
        _contract(),
        session_id=session_id,
        authorization_source="protected_local_ui",
        created_at=now,
        contract_id=contract_id,
        expected_active_task_id=None,
        trusted_event=receipt,
    )


def _payload(record, attempt_id: str) -> dict[str, object]:
    return {
        "contract_id": record.contract_id,
        "version": record.version,
        "attempt_id": attempt_id,
        "session_id": record.session_id,
        "agent_id": "week11-demo-runner",
        "user_id": "server-owned-demo",
        "action": {
            "family": "shell",
            "raw_command": f"touch {MARKER_TARGET}",
            "cwd": "/workspace",
        },
        "recent_actions": [],
    }


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _check_raw_mount_confinement(
    executor: DockerExecutor,
    repository: Path,
    build: Path,
) -> None:
    marker = executor.run(
        command="touch /workspace/build/mount-probe.txt",
        shell_type="bash",
    )
    _require(
        marker.exit_code == 0 and (build / "mount-probe.txt").is_file(),
        f"nested marker write failed: {marker.stderr or marker.error}",
    )
    (build / "mount-probe.txt").unlink()

    sibling_write = executor.run(
        command="touch /workspace/blocked-sibling.txt",
        shell_type="bash",
    )
    _require(
        sibling_write.exit_code not in {None, 0}
        and not (repository / "blocked-sibling.txt").exists(),
        "read-only sibling write unexpectedly succeeded",
    )
    traversal = executor.run(
        command="touch /workspace/build/../blocked-traversal.txt",
        shell_type="bash",
    )
    _require(
        traversal.exit_code not in {None, 0}
        and not (repository / "blocked-traversal.txt").exists(),
        "parent traversal write unexpectedly succeeded",
    )

    sibling = repository / "sibling.txt"
    sibling.write_text("original", encoding="utf-8")
    runtime_symlink = executor.run(
        command=(
            "ln -s ../sibling.txt /workspace/build/runtime-link.txt "
            "&& printf hacked > /workspace/build/runtime-link.txt"
        ),
        shell_type="bash",
    )
    _require(
        runtime_symlink.exit_code not in {None, 0}
        and sibling.read_text(encoding="utf-8") == "original",
        "runtime symlink escaped the writable subtree",
    )
    (build / "runtime-link.txt").unlink(missing_ok=True)

    runtime_hardlink = executor.run(
        command=(
            "ln /workspace/sibling.txt /workspace/build/runtime-hardlink.txt "
            "&& printf hacked > /workspace/build/runtime-hardlink.txt"
        ),
        shell_type="bash",
    )
    _require(
        runtime_hardlink.exit_code not in {None, 0}
        and sibling.read_text(encoding="utf-8") == "original",
        "runtime hardlink escaped the writable subtree",
    )
    (build / "runtime-hardlink.txt").unlink(missing_ok=True)

    prelinked = build / "prelinked.txt"
    os.link(sibling, prelinked)
    try:
        try:
            executor.validate_configuration()
        except ValueError as exc:
            _require("hard-linked" in str(exc), "hardlink failed for wrong reason")
        else:
            raise RuntimeError("preexisting hardlink was not rejected")
    finally:
        prelinked.unlink()


def run() -> None:
    with tempfile.TemporaryDirectory(prefix="sentinel-week11-phase0-") as directory:
        root = Path(directory)
        repository = root / "sample-repository"
        build = repository / "build"
        repository.mkdir(mode=0o755)
        (repository / ".git").mkdir()
        build.mkdir(mode=0o700)
        build.chmod(0o700)
        database = root / "sentinel.sqlite3"
        internal_tokens = iter(("internal-approved-" + ("a" * 32),))
        approval_ids = iter(("approval-denied", "approval-approved"))

        binding_store = SQLiteWorkspaceBindingStore(database)
        supervision = binding_store.bind(review_workspace(repository))
        control_host_id = (
            f"sentinel-control:{supervision.workspace.identity_sha256}"
        )
        consumer = InMemoryTrustedEventConsumer(
            host_id=control_host_id,
            session_id=supervision.session_id,
            channel="protected_local_ui",
        )
        contracts = SQLiteContractStore(
            database,
            trusted_event_consumer=consumer,
        )
        sessions = SQLiteSessionStore(database)
        audit = SQLiteAuditStore(database)
        approvals = InMemoryApprovalService(
            approval_id_factory=lambda: next(approval_ids),
            token_factory=lambda: next(internal_tokens),
        )
        executor = DockerExecutor(
            workspace=repository,
            writable_subdirectory="build",
            container_user=f"{os.getuid()}:{os.getgid()}",
        )
        try:
            _check_raw_mount_confinement(executor, repository, build)
            record = _activate_contract(
                contracts,
                consumer,
                supervision.session_id,
            )
            pairing_capability = generate_pairing_capability()
            app = create_app(
                load_model=False,
                policy_profile=_policy_profile(),
                load_policy=False,
                contract_store=contracts,
                session_store=sessions,
                approval_service=approvals,
                audit_store=audit,
                executor=executor,
                execution_environment="production",
                control_config=ControlConfig(
                    workspace=repository,
                    pairing_capability=pairing_capability,
                    api_host=API_HOST,
                    ui_origin=UI_ORIGIN,
                ),
                control_binding_store=binding_store,
            )
            with TestClient(
                app,
                base_url=f"http://{API_HOST}",
            ) as client:
                origin = {"Origin": UI_ORIGIN}
                paired = client.post(
                    "/control/pair/exchange",
                    headers=origin,
                    json={"capability": pairing_capability},
                )
                _require(paired.status_code == 200, "browser pairing failed")

                denied_request = client.post(
                    "/execute",
                    json=_payload(record, "attempt-denied"),
                )
                denied_id = denied_request.json().get("approval_id")
                _require(
                    denied_request.json().get("verdict") == "confirm_required"
                    and denied_id == "approval-denied",
                    "denial candidate was not queued",
                )
                denied = client.post(
                    f"/control/approvals/{denied_id}/deny",
                    headers=origin,
                )
                _require(
                    denied.status_code == 200
                    and not (build / "approved-marker.txt").exists(),
                    "denial launched an execution",
                )

                approved_payload = _payload(record, "attempt-approved")
                approval_request = client.post(
                    "/execute",
                    json=approved_payload,
                )
                approval_id = approval_request.json().get("approval_id")
                _require(
                    approval_request.json().get("verdict") == "confirm_required"
                    and approval_id == "approval-approved",
                    "approval candidate was not queued",
                )
                approved = client.post(
                    f"/control/approvals/{approval_id}/approve",
                    headers=origin,
                    json={"typed_target": MARKER_TARGET},
                )
                approved_body = approved.json()
                marker = build / "approved-marker.txt"
                _require(
                    approved.status_code == 200
                    and approved_body.get("retry", {}).get("verdict") == "allow"
                    and marker.is_file(),
                    "approved marker was not executed exactly once",
                )
                marker_mtime = marker.stat().st_mtime_ns
                replay = client.post("/execute", json=approved_payload)
                _require(
                    replay.json() == approved_body["retry"]
                    and marker.stat().st_mtime_ns == marker_mtime,
                    "terminal replay relaunched the executor",
                )
                changed = dict(approved_payload)
                changed["action"] = {
                    "family": "shell",
                    "raw_command": "touch /workspace/build/changed.txt",
                    "cwd": "/workspace",
                }
                conflict = client.post("/execute", json=changed)
                _require(
                    conflict.status_code == 409
                    and not (build / "changed.txt").exists(),
                    "changed action reused an admitted attempt",
                )
                _require(
                    "internal-approved-" not in approved.text
                    and "internal-approved-" not in replay.text,
                    "internal approval authority reached an HTTP response",
                )

            events = audit.query()
            event_types = [event.event_type for event in events]
            denied_index = event_types.index("exact_action_denied")
            approved_index = event_types.index("exact_action_approved")
            admitted_index = event_types.index("execution_admitted")
            completed_index = event_types.index("post_execution")
            _require(
                denied_index < approved_index < admitted_index < completed_index,
                "approval audit sequence is out of order",
            )
            _require(
                len(
                    [
                        event
                        for event in events
                        if event.event_type == "execution_admitted"
                    ]
                )
                == 1,
                "more than one execution was admitted",
            )
            _require(
                "internal-approved-" not in repr(events),
                "internal approval authority reached audit evidence",
            )
        finally:
            audit.close()
            sessions.close()
            contracts.close()
            binding_store.close()

    print(
        "Week 11 Phase 0 smoke passed: pairing, denial, internal approval retry, "
        "single marker write, replay rejection, mount confinement, and ordered audit."
    )


if __name__ == "__main__":
    run()
