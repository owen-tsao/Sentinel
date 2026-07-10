# Project Sentinel

Enterprise guardrail engine for AI-agent actions: evaluate commands with deterministic policy and sequence-aware ML, run approved actions in a local Docker executor, expose developer workflows through a CLI, and audit decisions to a local SQLite store.

## Docs

- [docs/Weekly Structure.md](./docs/Weekly%20Structure.md) — enterprise roadmap and 12-week Engine & CLI MVP
- [docs/Final Plan.md](./docs/Final%20Plan.md) — architecture and component specs
- [docs/week1_threat_model.md](./docs/week1_threat_model.md) — initial threat model and risk categories
- [docs/data_strategy.md](./docs/data_strategy.md) — dataset strategy and labeling guidance

## Status

Week 9 sandboxed execution. Sentinel can evaluate proposed commands through a local API using deterministic rules first, local environment policy profiles, ONNX model scoring when a local model artifact is available, and exact-request confirmation tokens for high-risk but potentially legitimate actions. Commands with a final `allow` verdict can now run in an ephemeral, restricted Docker sandbox through `POST /execute`.

## Stack

- PyTorch (training) + ONNX Runtime (inference)
- FastAPI
- Docker
- SQLite (audit logs, with JSONL export)

## Local API

Use a Python 3.11+ environment, then install the local package with API and test dependencies:

```bash
python3 -m pip install -e ".[test]"
```

Start the evaluation service:

```bash
PYTHONPATH=src uvicorn sentinel.api.main:app --reload
```

Check service health:

```bash
curl http://127.0.0.1:8000/health
```

If the ONNX model artifact is not present, health returns `status: "degraded"`. That is expected during local development: deterministic rules still run, and gray-area requests fall back to `confirm_required` instead of being allowed blindly.

Evaluate a command without executing it:

```bash
curl -X POST http://127.0.0.1:8000/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "context": "Show git status for this repository.",
    "command": "git status --short",
    "recent_actions": [],
    "environment": "sandbox",
    "shell_type": "bash",
    "session_id": "local-session",
    "agent_id": "local-agent",
    "user_id": "local-user"
  }'
```

`POST /evaluate` never executes commands. It returns a structured verdict with a request ID, risk score, risk tier, reason codes, routing path, agent-facing message, suggested safer actions, and an optional `confirmation_id`.

## Sandboxed Execution

`POST /execute` accepts the same request body as `/evaluate`. It evaluates first, and only runs the command if the final verdict is `allow` (including confirmation-token approvals). `warn`, `confirm_required`, and `block` verdicts return `execution: null` and never touch the sandbox.

Build the sandbox image once, then start the API on the host (the host needs Docker access to spawn sandbox containers):

```bash
docker compose --profile executor build executor
PYTHONPATH=src uvicorn sentinel.api.main:app --reload
```

Execute a safe command:

```bash
curl -X POST http://127.0.0.1:8000/execute \
  -H "Content-Type: application/json" \
  -d '{
    "context": "List repository files.",
    "command": "ls -la",
    "recent_actions": [],
    "environment": "sandbox",
    "shell_type": "bash",
    "session_id": "local-session",
    "agent_id": "local-agent",
    "user_id": "local-user"
  }'
```

Allowed commands run in an ephemeral `docker run --rm` container with no network, CPU/memory/pids limits, a read-only root filesystem, dropped capabilities, `no-new-privileges`, a strict timeout, and a single bind mount scoped to the configured workspace. The response includes an `execution` object with `stdout`, `stderr`, `exit_code`, `timed_out`, `duration_ms`, and truncation flags.

Executor settings can be tuned with environment variables before starting the API:

- `SENTINEL_EXECUTOR_IMAGE` — sandbox image (default `sentinel-executor:local`)
- `SENTINEL_EXECUTOR_WORKSPACE` — host directory mounted at `/workspace` (default: API process working directory)
- `SENTINEL_EXECUTOR_TIMEOUT_SECONDS` — per-command timeout (default 10; malformed or non-positive values fall back to the default)
- `SENTINEL_EXECUTOR_READONLY_WORKSPACE` — set to `true` to make the workspace mount read-only
- `SENTINEL_MAX_CONCURRENT_EXECUTIONS` — cap on simultaneous sandbox runs (default 8; excess requests get HTTP 429)

If Docker is unavailable, the image is missing, or the sandbox cannot start, Sentinel fails closed: the response reports a structured `execution.error` and the command is never run on the host.

## Docker Usage

Build and run the local API container with Docker Compose:

```bash
docker compose up --build api
```

Then check the containerized service:

```bash
curl http://127.0.0.1:8000/health
```

The API container mounts `policies/` and `models/` read-only. If `models/sentinel-distilbert-onnx/model.onnx` is present, `/health` should report `status: "ok"` with `model_loaded: true`. If the ONNX artifact is absent, `/health` reports `status: "degraded"`; deterministic rules and policy still run, and gray-area requests require confirmation rather than being allowed by default.

If port `8000` is busy, choose a different host port:

```bash
SENTINEL_API_PORT=8010 docker compose up --build api
```

The executor image is the sandbox that `POST /execute` uses for approved commands. It is not started by default and never runs as a long-lived service; the API spawns one ephemeral container per command. Build it explicitly:

```bash
docker compose --profile executor build executor
```

Note that the containerized API cannot reach the Docker daemon (no socket mount, by design), so `POST /execute` fails closed inside Compose. For local sandboxed execution, run the API on the host as shown above.

For a full local container smoke check, run:

```bash
python3 scripts/docker_smoke_check.py
```

That script validates Compose config, builds both images, runs one command directly through the Docker executor to verify the sandbox works and stays non-root, starts only the API service, checks `/health`, sends one safe `/evaluate` request, verifies `/execute` blocks destructive commands, verifies the containerized API fails closed instead of executing on the host, and tears the Compose project down.

## Policy Profiles

Sentinel loads the default local policy profile from `policies/default.json`. The profile controls environment-specific escalation after deterministic rules run:

- `sandbox` and `dev` are less strict for low-risk and warning-level model outcomes.
- `staging` and `production` escalate warned or unmatched ambiguous actions more aggressively.
- Rule-based `block` decisions are final. Policy can escalate a non-block decision to `confirm_required`, but it cannot downgrade a block.

The response `routing_path` explains which layer made the decisive call:

- `rules`: deterministic rules decided the result.
- `policy`: the active policy profile escalated or finalized the result.
- `model`: the ONNX model decided a gray-area request.
- `combined`: rules and model both contributed.
- `confirmation`: a valid one-use confirmation token approved the exact request.

## Local Confirmation Flow

When Sentinel returns `verdict: "confirm_required"`, confirmable requests include a `confirmation_id`. A human or local tool can approve that pending request through `POST /confirm`, which returns a one-use `confirmation_token`.

Request confirmation:

```bash
curl -X POST http://127.0.0.1:8000/confirm \
  -H "Content-Type: application/json" \
  -d '{
    "confirmation_id": "paste-confirmation-id-here"
  }'
```

Then retry the same `POST /evaluate` request with the returned token:

```json
{
  "context": "Run an unfamiliar project helper.",
  "command": "python scripts/custom_cleanup.py",
  "recent_actions": [],
  "environment": "dev",
  "shell_type": "python",
  "session_id": "local-session",
  "agent_id": "local-agent",
  "user_id": "local-user",
  "confirmation_token": "paste-confirmation-token-here"
}
```

The token is checked against a SHA-256 fingerprint of the exact request fields: `context`, `command`, `environment`, `shell_type`, `recent_actions`, `session_id`, `agent_id`, and `user_id`. If any field changes, the token is rejected and Sentinel returns `confirm_required` again. Tokens are one-use, and `user_confirmed: true` is not trusted unless a valid token is also supplied.

`block` verdicts are not confirmable. Sentinel does not create confirmation IDs for critical blocks such as root deletion, credential theft, exfiltration, broad production deletion, or defense evasion.

## Local-Only Limitations

The Week 9 local runtime is intentionally limited:

- Pending confirmations and tokens disappear when the API process restarts.
- Tokens are random local secrets, not signed JWTs.
- There is no Slack, email, browser approval queue, or CLI approval workflow yet.
- There is no audit persistence for confirmations or executions yet (SQLite audit logging is Week 10 scope).
- Docker reduces local blast radius for development, but it shares the host kernel and is not a production-grade sandbox. A hostile workload could attempt kernel-level escapes that VMs would contain.
- The sandbox workspace mount is read-write by default, so approved commands can modify files inside that directory (and nothing outside it). Set `SENTINEL_EXECUTOR_READONLY_WORKSPACE=true` when write access is not needed.
- Command output is fully buffered in API memory before the 64KB cap is applied, so a command that floods stdout within the timeout can spike API memory. Concurrency is capped, and incremental capped streaming is a planned hardening step.
- The execution timeout covers the whole `docker run` lifetime, including container startup. Commands finishing right at the deadline may be reported as timed out even though their side effects completed.
- `warn` verdicts do not execute. This is a deliberate fail-safe default that may become configurable later.

### Isolation migration path (post-summer)

The `CommandExecutor` protocol keeps the sandbox swappable. The intended hardening sequence, in increasing isolation strength, is:

1. Current: ephemeral `docker run` with no network, dropped capabilities, resource limits, and a scoped mount.
2. Add gVisor (`runsc`) or a seccomp/AppArmor profile for syscall filtering on the same Docker flow.
3. Move to microVMs (Firecracker or Kata Containers) or managed per-job isolation (e.g. cloud-run jobs) so each execution gets its own kernel.

Run the focused API and decision checks:

```bash
PYTHONPATH=src python3 -m unittest tests.test_confirmation tests.test_policy tests.test_decision_engine tests.test_api_service tests.test_executor
```
