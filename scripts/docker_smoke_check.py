#!/usr/bin/env python3
"""Run local Docker smoke checks for the Sentinel API and executor images."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = ROOT / "docker-compose.yml"


def run_command(command: list[str], *, env: dict[str, str], cwd: Path = ROOT) -> None:
    print(f"+ {' '.join(command)}")
    subprocess.run(command, cwd=cwd, env=env, check=True)


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


def check_execute_fail_closed(base_url: str) -> dict[str, Any]:
    """Inside compose the API has no Docker socket, so allowed commands must fail closed, not run on the host."""
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
        if not isinstance(execution, dict):
            raise ValueError("allowed /execute response must include an execution payload")
        # The containerized API has no Docker socket, so the ONLY acceptable
        # outcome is a structured sandbox error with no completed process.
        # A real exit code would mean the command executed somewhere (host
        # fallback or an accidentally mounted Docker socket) - a regression.
        if execution.get("error") is None:
            raise ValueError("expected a structured sandbox error from /execute inside compose; command may have executed")
        if execution.get("exit_code") is not None:
            raise ValueError("compose API returned an exit code; command must not execute without Docker access")
    elif execution is not None:
        raise ValueError(f"non-allow verdict {verdict!r} must not include an execution result")
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


def smoke_check(args: argparse.Namespace) -> dict[str, Any]:
    if shutil.which("docker") is None:
        raise RuntimeError("Docker CLI is not installed or is not on PATH")

    env = os.environ.copy()
    env["SENTINEL_API_PORT"] = str(args.port)

    run_command(compose_command(args, "config", "--quiet"), env=env)
    if not args.skip_build:
        run_command(compose_command(args, "build", "api", "executor"), env=env)

    executor_report = check_direct_executor()

    try:
        run_command(compose_command(args, "up", "-d", "api"), env=env)
        base_url = f"http://127.0.0.1:{args.port}"
        health = wait_for_health(base_url, timeout_seconds=args.timeout, interval_seconds=args.interval)
        evaluation = check_evaluate(base_url)
        execute_block = check_execute_gating(base_url)
        execute_fail_closed = check_execute_fail_closed(base_url)
        return {
            "health": health,
            "executor_direct": executor_report,
            "evaluate": {
                "verdict": evaluation["verdict"],
                "risk_tier": evaluation["risk_tier"],
                "routing_path": evaluation["routing_path"],
            },
            "execute_blocked": {
                "verdict": execute_block["verdict"],
                "execution": execute_block["execution"],
            },
            "execute_fail_closed": {
                "verdict": execute_fail_closed["verdict"],
                "execution_error": (execute_fail_closed.get("execution") or {}).get("error"),
            },
        }
    finally:
        if not args.keep_running:
            run_command(compose_command(args, "down", "--remove-orphans"), env=env)


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
