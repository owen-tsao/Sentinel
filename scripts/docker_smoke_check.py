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

    try:
        run_command(compose_command(args, "up", "-d", "api"), env=env)
        base_url = f"http://127.0.0.1:{args.port}"
        health = wait_for_health(base_url, timeout_seconds=args.timeout, interval_seconds=args.interval)
        evaluation = check_evaluate(base_url)
        return {
            "health": health,
            "evaluate": {
                "verdict": evaluation["verdict"],
                "risk_tier": evaluation["risk_tier"],
                "routing_path": evaluation["routing_path"],
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
