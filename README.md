# Project Sentinel

Sentinel is a local-first task-authorization backend for AI agents. It keeps accepted task authority on the server, turns proposed shell commands into canonical actions, checks those actions against the active contract and deterministic policy, and records the decision before any sandboxed execution.

This repository is a production-grade foundation: its trust boundaries, persistence, replay controls, audit admission, and fail-closed behavior are tested. It is not yet a production-ready product. There is no human approval/control UI, no protected runtime authority API, no mandatory agent integration, and no production-grade execution isolation.

## Current status

Week 10 is implemented on `feature/week-10-task-authority` and is ready for clean commits.

- Versioned contracts, one active task per session, server-owned history, canonical multi-target shell actions, exact-action test approvals, SQLite state, and at-most-once execution attempts are implemented.
- A clean Python 3.11 container run passes all 477 tests, and the Docker authority/execution smoke passes.
- The current API exposes only `GET /health`, `POST /evaluate`, and `POST /execute`.
- Authority changes and approval issuance are internal/test-only until Week 11 adds a protected provenance and human-control interface.
- Shell execution is read-only for Week 10. Write and delete operations are rejected before execution admission.
- Cursor and legacy OpenClaw integrations are advisory. They do not prove complete interception or trusted direct-user provenance.
- ML serving is disabled. There is no independent calibration set, and calibration/export/serving fail closed.

The frozen 90-row reviewed regression corpus has SHA-256 `8488862b2da4744bf08f33ee413982f290181feea8c81e7d42f8f1034c62feec`. The non-promoting v5 regression result is 98.8889% expected accuracy, 100% overstep recall, 100% insufficient-contract detection, 5.8824% compliant false interruption, zero critical misses, and eight missing reason expectations. It is regression evidence, not blind promotion evidence.

## Architecture

```text
Untrusted agent request
        |
        v
FastAPI: resolve active contract and session history from server state
        |
        v
Canonicalize raw shell command -> contract matcher -> deterministic policy
        |
        +--> allow / warn / confirm_required / block
        |
        v (allow on POST /execute only)
Durable admission audit + at-most-once attempt reservation
        |
        v
Ephemeral read-only Docker executor
        |
        v
Stored response and ordered audit evidence
```

`SENTINEL_STATE_DB` enables SQLite persistence for contracts, session history, execution attempts, and audit evidence. Without it, the in-memory stores support evaluation and tests, but the default in-memory audit store cannot authorize real execution.

Deterministic rules and contract policy are the authority. Optional ML may only escalate gray-area risk after it has independent calibration and promotion evidence; it may never create permission.

## Quick start

Use Python 3.11 or newer:

```bash
python3 -m pip install -e ".[test]"
PYTHONPATH=src uvicorn sentinel.api.main:app --reload
curl http://127.0.0.1:8000/health
```

ML loading is opt-in. Module startup loads ONNX only when
`SENTINEL_ENABLE_ML=true` is set exactly; injected applications must pass
`create_app(load_model=True)`. By default, health reports
`model_loaded: false` and `model_detail: "Model loading is disabled."` while
deterministic contract and policy enforcement remains active.

ONNX metadata binds the model, checkpoint/tokenizer files, and reviewed serving
thresholds with SHA-256 digests. This detects accidental swaps and inconsistent
local edits in Sentinel's same-user threat model; it is not a cryptographic
signature, because the same local user can replace both an artifact and its
metadata.

## Current API

### `GET /health`

Returns:

```json
{
  "status": "degraded",
  "model_loaded": false,
  "policy_loaded": true,
  "audit_status": "ok",
  "model_path": "models/sentinel-distilbert-onnx/model.onnx",
  "model_detail": "Model loading is disabled.",
  "policy_detail": null,
  "audit_detail": null,
  "detail": "Model loading is disabled."
}
```

Exact detail text and model path can vary with local configuration. `status` is `ok` only when model, policy, and audit health are all ready.

### `POST /evaluate`

Contract-aware requests have this shape:

```json
{
  "contract_id": "contract-uuid",
  "version": 3,
  "session_id": "session-uuid",
  "agent_id": "caller-claimed-agent",
  "user_id": "caller-claimed-user",
  "attempt_id": null,
  "action": {
    "family": "shell",
    "raw_command": "git status --short",
    "cwd": "/workspace"
  },
  "approval_token": null,
  "recent_actions": []
}
```

The server treats `agent_id` and `user_id` as untrusted labels. It ignores caller-provided `recent_actions`, resolves the active contract and recent history from server state, fixes the environment from server configuration, and derives operation, targets, and effects from `raw_command`. Unknown authority-shaped fields are rejected.

`POST /evaluate` never executes. It returns `request_id`, `verdict`, `risk_score`, `risk_tier`, `reasons`, `routing_path`, `agent_message`, `suggested_safe_actions`, optional `approval_id`, and `execution: null`.

The retained legacy `context`/`command` request is compatibility-only. It cannot carry authority, and it cannot authorize execution.

### `POST /execute`

`POST /execute` accepts the same contract request but requires a non-empty `attempt_id`. Execution is admitted only when all of these are true:

- the referenced version is the server-resolved active contract for the session;
- the server-canonicalized action matches that contract and deterministic policy returns `allow`, or a protected exact approval matches;
- the action is a safe read-only shell operation in the configured workspace;
- durable required audit evidence and session attempt state can be committed;
- the Docker executor configuration passes admission checks.

An approval token is bound to the exact contract version, authority epoch, session, environment, and canonical action, and is consumed once. There is no HTTP route that issues approval tokens.

An `attempt_id` is at-most-once. A completed or failed attempt returns its stored response; a reused ID with different bindings is rejected; reserved, running, or unknown attempts return `409` and are never automatically retried.

## Docker roles

Build the executor image and run the API on the host when testing execution:

```bash
docker compose --profile executor build executor
SENTINEL_STATE_DB=.local/sentinel.sqlite3 \
  PYTHONPATH=src uvicorn sentinel.api.main:app --reload
```

The host API can launch one ephemeral executor container per admitted action. The executor runs non-root with no network, a read-only root filesystem, dropped capabilities, resource limits, a timeout, and a read-only workspace mount.

The Compose `api` service is diagnostic and non-executing:

```bash
docker compose up --build api
```

It binds to localhost and has no Docker socket, so it cannot launch executor containers. This is an intentional boundary, not a deployment bug.

Docker reduces local blast radius but shares the host kernel; it is not production-grade isolation.

## Verification

```bash
python3 -m pytest
git diff --check
python3 scripts/evaluate_contracts.py \
  data/evaluation/contract_combined_reviewed.jsonl \
  --minimum-rows-per-category 1 \
  --manifest /tmp/sentinel-known-regression.json
python3 scripts/docker_smoke_check.py
```

The minimum is intentionally `1` because some reviewed categories are sparse.
That makes this a regression-only check; sparse categories remain a blocker
for blind promotion and release claims.

The Docker smoke requires Docker Desktop, builds both images, validates the non-root executor and API socket isolation, and exercises the trusted contract-to-audit path. See [scripts/README.md](./scripts/README.md) for the complete command index.

## Known limitations

- No usable human approval, contract-authoring, lifecycle, or audit-control UI exists yet.
- No runtime lifecycle or approval route exists; authority mutation remains internal/test-only.
- Week 10 execution supports read-only workspace actions only.
- Slack's basic internal-channel metadata path passed once. Slack Connect, guests, private channels, scheduled sends, Google Workspace, and provider enforcement remain unproven.
- Fixture-backed contextual regression checks do not prove live evidence producers or atomic provider-side limits.
- Current integrations are advisory and may be bypassed by their hosts.
- The API has no authenticated multi-user identity boundary. Keep it on one trusted local machine.

## Documentation

- [Product Architecture](./docs/Product%20Architecture.md) — current Week 10 boundary and Week 11 targets
- [Roadmap](./docs/Roadmap.md) — sequencing and release gates
- [Data strategy](./docs/data_strategy.md) — dataset evidence and promotion rules
- [Evaluation data](./data/evaluation/README.md) — reviewed artifacts and regression history
- [Threat model](./docs/week1_threat_model.md) — initial risks and policy categories
