#!/usr/bin/env python3
"""Run local Docker smoke checks for the Sentinel API and executor images."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = ROOT / "docker-compose.yml"
CONFIG_TIMEOUT_SECONDS = 30
BUILD_TIMEOUT_SECONDS = 600
COMPOSE_LIFECYCLE_TIMEOUT_SECONDS = 120
COMPOSE_EXEC_TIMEOUT_SECONDS = 30


def run_command(
    command: list[str],
    *,
    env: dict[str, str],
    timeout_seconds: float,
    cwd: Path = ROOT,
) -> None:
    print(f"+ {' '.join(command)}")
    subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=True,
        timeout=timeout_seconds,
    )


def read_json(url: str, *, timeout: float) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{url} returned non-object JSON")
    return payload


def post_json(url: str, payload: dict[str, Any], *, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read().decode("utf-8"))
    if not isinstance(body, dict):
        raise ValueError(f"{url} returned non-object JSON")
    return body


def wait_for_health(base_url: str, *, timeout_seconds: float, interval_seconds: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None

    while time.monotonic() < deadline:
        try:
            health = read_json(f"{base_url}/health", timeout=3)
            status = health.get("status")
            if status in {"ok", "degraded"}:
                return health
            last_error = ValueError(f"unexpected health status: {status!r}")
        except (OSError, ValueError, urllib.error.URLError) as exc:
            last_error = exc
        time.sleep(interval_seconds)

    if last_error is not None:
        raise TimeoutError(f"API health check did not pass: {last_error}")
    raise TimeoutError("API health check did not pass")


def check_evaluate(base_url: str) -> dict[str, Any]:
    response = post_json(
        f"{base_url}/evaluate",
        {
            "context": "Show git status for this repository.",
            "command": "git status --short",
            "recent_actions": [],
            "environment": "sandbox",
            "shell_type": "bash",
            "session_id": "docker-smoke-session",
            "agent_id": "docker-smoke-agent",
            "user_id": "docker-smoke-user",
        },
        timeout=5,
    )
    verdict = response.get("verdict")
    if verdict not in {"allow", "warn", "confirm_required", "block"}:
        raise ValueError(f"unexpected evaluate verdict: {verdict!r}")
    if not response.get("request_id"):
        raise ValueError("evaluate response did not include request_id")
    return response


def check_execute_gating(base_url: str) -> dict[str, Any]:
    """A clearly dangerous command must be blocked and must never reach the sandbox."""
    response = post_json(
        f"{base_url}/execute",
        {
            "context": "Clean up the machine.",
            "command": "rm -rf / --no-preserve-root",
            "recent_actions": [],
            "environment": "production",
            "shell_type": "bash",
            "session_id": "docker-smoke-session",
            "agent_id": "docker-smoke-agent",
            "user_id": "docker-smoke-user",
        },
        timeout=10,
    )
    if response.get("verdict") != "block":
        raise ValueError(f"expected block verdict for destructive command, got {response.get('verdict')!r}")
    if response.get("execution") is not None:
        raise ValueError("blocked command must not include an execution result")
    return response


def check_legacy_execute_gating(base_url: str) -> dict[str, Any]:
    """Legacy requests carry no authority and must never reach an executor."""
    response = post_json(
        f"{base_url}/execute",
        {
            "context": "Show git status for this repository.",
            "command": "git status --short",
            "recent_actions": [],
            "environment": "sandbox",
            "shell_type": "bash",
            "session_id": "docker-smoke-session",
            "agent_id": "docker-smoke-agent",
            "user_id": "docker-smoke-user",
        },
        timeout=30,
    )
    verdict = response.get("verdict")
    execution = response.get("execution")
    if verdict == "allow":
        raise ValueError("legacy /execute request unexpectedly gained authority")
    if execution is not None:
        raise ValueError(
            f"non-allow verdict {verdict!r} must not include an execution result"
        )
    return response


def check_direct_executor() -> dict[str, Any]:
    """Verify the built sandbox image actually runs a command via DockerExecutor on the host."""
    sys.path.insert(0, str(ROOT / "src"))
    from sentinel.execution import DockerExecutor  # noqa: PLC0415

    executor = DockerExecutor(workspace=ROOT, read_only_workspace=True, timeout_seconds=15)
    result = executor.run(command="echo sentinel-sandbox-ok && whoami", shell_type="bash")
    if result.error is not None:
        raise ValueError(f"direct executor run failed: {result.error}")
    if result.exit_code != 0 or "sentinel-sandbox-ok" not in result.stdout:
        raise ValueError(f"unexpected executor output: exit={result.exit_code} stdout={result.stdout!r}")
    if "root" in result.stdout.splitlines():
        raise ValueError("sandbox command ran as root; executor image must stay non-root")
    return {
        "exit_code": result.exit_code,
        "duration_ms": result.duration_ms,
        "user": result.stdout.splitlines()[-1] if result.stdout else None,
    }


def check_contract_executor_audit() -> dict[str, Any]:
    """Run trusted authority through the API, real executor, and SQLite audit."""

    sys.path.insert(0, str(ROOT / "src"))
    from fastapi.testclient import TestClient  # noqa: PLC0415
    from sentinel.api.main import create_app  # noqa: PLC0415
    from sentinel.audit import SQLiteAuditStore  # noqa: PLC0415
    from sentinel.authority import ContractAuthorityService  # noqa: PLC0415
    from sentinel.contracts import (  # noqa: PLC0415
        ActionContract,
        InMemoryContractStore,
        InMemoryTrustedEventConsumer,
        TrustedPromptEnvelope,
    )
    from sentinel.execution import DockerExecutor  # noqa: PLC0415
    from sentinel.ml.inference import RiskPrediction  # noqa: PLC0415
    from sentinel.session import InMemorySessionStore  # noqa: PLC0415

    class SmokeAllowModel:
        def predict_row(self, row: dict[str, object]) -> RiskPrediction:
            del row
            return RiskPrediction(
                risk_probability=0.01,
                model_tier="allow",
                threshold={"warn": 0.2, "confirm_required": 0.4},
                input_names=[],
                provider="docker-smoke",
                metadata={},
            )

    now = datetime.now(timezone.utc)
    session_id = "docker-contract-smoke"
    contract_id = str(uuid4())
    consumer = InMemoryTrustedEventConsumer(
        host_id="sentinel-smoke-host",
        session_id=session_id,
        channel="protected-smoke",
    )
    contracts = InMemoryContractStore(trusted_event_consumer=consumer)
    sessions = InMemorySessionStore()
    contract = ActionContract(
        objective="Read the Sentinel README inside the sandbox.",
        allowed_operations={"read"},
        allowed_tools={"shell"},
        exact_targets=["/workspace/README.md"],
        environment="sandbox",
        maximum_scope="exact",
        expected_side_effects=["Read one reviewed file."],
        allowed_effects={"read"},
        forbidden_operations={"network", "credential_access"},
        forbidden_effects=["No network or credential access."],
        forbidden_effect_codes={"network", "credential_access"},
        rollback_plan="No mutation occurs.",
        dry_run_required=False,
        authorization_reference="docker-smoke-trusted-event",
        expires_at=now + timedelta(minutes=10),
    )
    with tempfile.TemporaryDirectory() as directory:
        audit = SQLiteAuditStore(Path(directory) / "audit.sqlite3")
        try:
            authority = ContractAuthorityService(contracts, audit)
            proposed = authority.create_proposed(
                contract,
                session_id=session_id,
                authorization_source="trusted_user",
                created_at=now,
                contract_id=contract_id,
            )
            receipt = consumer.consume(
                TrustedPromptEnvelope(
                    event_id=f"event-{uuid4()}",
                    nonce=f"nonce-{uuid4().hex}",
                    host_id="sentinel-smoke-host",
                    session_id=session_id,
                    channel="protected-smoke",
                    prompt="Approve reading README for Docker smoke.",
                    purpose="task_transition",
                    contract_id=contract_id,
                    contract_version=proposed.version,
                    decision="approve",
                    issued_at=now - timedelta(seconds=1),
                    expires_at=now + timedelta(minutes=5),
                    authenticated=True,
                ),
                now=now,
            )
            active = authority.activate_proposed(
                contract_id,
                expected_version=proposed.version,
                expected_active_task_id=None,
                trusted_event=receipt,
                activated_at=now,
            )
            app = create_app(
                model=SmokeAllowModel(),
                load_model=False,
                load_policy=True,
                contract_store=contracts,
                session_store=sessions,
                audit_store=audit,
                executor=DockerExecutor(
                    workspace=ROOT,
                    read_only_workspace=True,
                    timeout_seconds=15,
                ),
                execution_environment="sandbox",
            )
            response = TestClient(app).post(
                "/execute",
                json={
                    "contract_id": contract_id,
                    "version": active.version,
                    "attempt_id": f"docker-smoke-attempt-{uuid4().hex}",
                    "session_id": session_id,
                    "agent_id": "docker-smoke-agent",
                    "user_id": "docker-smoke-user",
                    "action": {
                        "family": "shell",
                        "raw_command": "cat /workspace/README.md",
                        "cwd": "/workspace",
                    },
                },
            )
            body = response.json()
            execution = body.get("execution") or {}
            if (
                response.status_code != 200
                or body.get("verdict") != "allow"
                or execution.get("exit_code") != 0
                or execution.get("error") is not None
            ):
                raise ValueError(
                    "contract-aware Docker execution did not complete successfully"
                )
            event_types = [
                event.event_type for event in audit.query(contract_id=contract_id)
            ]
            required_order = [
                "authority_transition_prepared",
                "authority_transition_completed",
                "authority_transition_prepared",
                "authority_transition_completed",
                "pre_decision",
                "decision",
                "execution_admitted",
                "post_execution",
            ]
            cursor = 0
            for event_type in event_types:
                if (
                    cursor < len(required_order)
                    and event_type == required_order[cursor]
                ):
                    cursor += 1
            if cursor != len(required_order):
                raise ValueError(
                    f"contract-aware audit order was incomplete: {event_types}"
                )
            return {
                "verdict": body["verdict"],
                "exit_code": execution["exit_code"],
                "audit_event_types": event_types,
            }
        finally:
            audit.close()


def compose_command(args: argparse.Namespace, *parts: str) -> list[str]:
    return [
        "docker",
        "compose",
        "-p",
        args.project_name,
        "-f",
        str(args.compose_file),
        *parts,
    ]


def check_api_socket_absent(args: argparse.Namespace, *, env: dict[str, str]) -> None:
    """Confirm the containerized API cannot access the host Docker daemon."""

    run_command(
        compose_command(
            args,
            "exec",
            "-T",
            "api",
            "python",
            "-c",
            (
                "from pathlib import Path; "
                "raise SystemExit(1 if Path('/var/run/docker.sock').exists() else 0)"
            ),
        ),
        env=env,
        timeout_seconds=COMPOSE_EXEC_TIMEOUT_SECONDS,
    )


def smoke_check(args: argparse.Namespace) -> dict[str, Any]:
    if shutil.which("docker") is None:
        raise RuntimeError("Docker CLI is not installed or is not on PATH")

    env = os.environ.copy()
    env["SENTINEL_API_PORT"] = str(args.port)

    run_command(
        compose_command(args, "config", "--quiet"),
        env=env,
        timeout_seconds=CONFIG_TIMEOUT_SECONDS,
    )
    if not args.skip_build:
        run_command(
            compose_command(args, "build", "api", "executor"),
            env=env,
            timeout_seconds=BUILD_TIMEOUT_SECONDS,
        )

    executor_report = check_direct_executor()
    contract_report = check_contract_executor_audit()

    try:
        run_command(
            compose_command(args, "up", "-d", "api"),
            env=env,
            timeout_seconds=COMPOSE_LIFECYCLE_TIMEOUT_SECONDS,
        )
        base_url = f"http://127.0.0.1:{args.port}"
        health = wait_for_health(base_url, timeout_seconds=args.timeout, interval_seconds=args.interval)
        check_api_socket_absent(args, env=env)
        evaluation = check_evaluate(base_url)
        execute_block = check_execute_gating(base_url)
        legacy_execute = check_legacy_execute_gating(base_url)
        return {
            "health": health,
            "executor_direct": executor_report,
            "contract_executor_audit": contract_report,
            "api_docker_socket_present": False,
            "evaluate": {
                "verdict": evaluation["verdict"],
                "risk_tier": evaluation["risk_tier"],
                "routing_path": evaluation["routing_path"],
            },
            "execute_blocked": {
                "verdict": execute_block["verdict"],
                "execution": execute_block["execution"],
            },
            "legacy_execute_gating": {
                "verdict": legacy_execute["verdict"],
                "execution": legacy_execute["execution"],
            },
        }
    finally:
        if not args.keep_running:
            run_command(
                compose_command(args, "down", "--remove-orphans"),
                env=env,
                timeout_seconds=COMPOSE_LIFECYCLE_TIMEOUT_SECONDS,
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-file", type=Path, default=COMPOSE_FILE)
    parser.add_argument("--project-name", default="sentinel-smoke")
    parser.add_argument("--port", type=int, default=8000, help="Host port mapped to the API container.")
    parser.add_argument("--timeout", type=float, default=60.0, help="Seconds to wait for /health.")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between health probes.")
    parser.add_argument("--skip-build", action="store_true", help="Reuse existing local images.")
    parser.add_argument("--keep-running", action="store_true", help="Leave the API container running after checks pass.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report = smoke_check(args)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
