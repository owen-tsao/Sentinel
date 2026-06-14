# Project Sentinel

Enterprise guardrail engine for AI-agent actions: evaluate commands with deterministic policy and sequence-aware ML, run approved actions in a local Docker executor, expose developer workflows through a CLI, and audit decisions to AWS DynamoDB.

## Docs

- [docs/Weekly Structure.md](./docs/Weekly%20Structure.md) — enterprise roadmap and 12-week Engine & CLI MVP
- [docs/Final Plan.md](./docs/Final%20Plan.md) — architecture and component specs
- [docs/week1_threat_model.md](./docs/week1_threat_model.md) — initial threat model and risk categories
- [docs/data_strategy.md](./docs/data_strategy.md) — dataset strategy and labeling guidance

## Status

Week 8 Docker foundation. Sentinel can evaluate proposed commands through a local API using deterministic rules first, local environment policy profiles, ONNX model scoring when a local model artifact is available, and exact-request confirmation tokens for high-risk but potentially legitimate actions. The API and future executor boundary now have separate local Docker images.

## Stack

- PyTorch (training) + ONNX Runtime (inference)
- FastAPI
- Docker
- AWS DynamoDB (audit logs)

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

`POST /evaluate` never executes commands in Week 8. It returns a structured verdict with a request ID, risk score, risk tier, reason codes, routing path, agent-facing message, suggested safer actions, and an optional `confirmation_id`.

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

The executor image is intentionally separate from the API image and is not started by default. Build or run its placeholder command explicitly:

```bash
docker compose --profile executor build executor
docker compose --profile executor run --rm executor
```

For a full local container smoke check, run:

```bash
python3 scripts/docker_smoke_check.py
```

That script validates Compose config, builds both images, starts only the API service, checks `/health`, sends one safe `/evaluate` request, and tears the Compose project down.

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

The Week 8 local runtime is intentionally limited:

- Pending confirmations and tokens disappear when the API process restarts.
- Tokens are random local secrets, not signed JWTs.
- There is no Slack, email, browser approval queue, or CLI approval workflow yet.
- There is no `POST /execute` endpoint yet, so Sentinel still evaluates only and does not run commands.
- There is no DynamoDB or JSONL audit persistence for confirmations yet.
- Docker reduces local blast radius for development, but this is not a production sandbox yet.
- The executor container does not mount the Docker socket, does not run privileged, has no network in Compose, and currently only prints a readiness message.

Run the focused API and decision checks:

```bash
PYTHONPATH=src python3 -m unittest tests.test_confirmation tests.test_policy tests.test_decision_engine tests.test_api_service
```
