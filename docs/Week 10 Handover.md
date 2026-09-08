# Week 10 Handover

Status: complete and merged into `main` on September 8, 2026.

This handover is the factual starting point for a new Week 11 chat. The detailed
implementation plan is [Week 11 Plan](./Week%2011%20Plan.md).

## What Sentinel is now

Sentinel is a local-first task-authorization backend for AI agents. The server
owns the active task contract and recent action history. It canonicalizes each
proposed action, applies deterministic contract and safety policy, records the
decision, and only then admits supported execution to Docker.

The product is not yet a finished application. Week 10 delivered the security
foundation; Week 11 adds the protected local human-control experience.

## Week 10 result

- Immutable, versioned `ActionContract` records and audited lifecycle
  transitions.
- One server-resolved active task per session.
- One-use trusted events for authority creation, activation, amendment, and
  reactivation.
- Strict shell canonicalization with complete target/effect modeling.
- Deterministic contract matching and policy verdicts:
  `allow`, `warn`, `confirm_required`, and `block`.
- Exact-action approvals bound to contract version, authority epoch, session,
  environment, and canonical action.
- Durable, at-most-once execution attempts with replay and concurrency checks.
- SQLite contract, session, attempt, and ordered audit persistence.
- Non-root, network-disabled, resource-limited Docker execution.
- Read-only workspace execution; write and delete execution remain disabled.
- Advisory Cursor and OpenClaw integrations with explicit capability limits.
- Read-only Slack and Google Workspace metadata spike code; only the basic
  internal Slack channel path has been live-validated.
- Frozen 90-row reviewed regression corpus with non-promoting manifests.
- ML serving disabled until independent calibration and blind promotion data
  exist.

## Verified state

- Clean Python 3.11 container run: 477 tests passed.
- Docker smoke: passed.
- Docker smoke covers trusted activation, contract-aware decision, durable
  admission, non-root execution, ordered audit, destructive blocking, API
  Docker-socket isolation, and legacy no-authority gating.
- Independent security and maintainability review: no remaining Week 10
  blocker, high, or medium findings.
- Credential-pattern scan: no repository matches.

The remaining warnings are Pydantic 2 migration debt and dependency-level
deprecations. Pydantic is constrained below version 3 until that migration is
performed.

## Current runtime boundary

The public FastAPI surface is exactly:

- `GET /health`
- `POST /evaluate`
- `POST /execute`

There is no runtime authority lifecycle route, approval route, audit query
route, or human control UI. Authority changes and approval issuance are
internal/test-only.

`POST /execute` only supports server-canonicalized read actions inside the
startup-bound workspace. Durable admission is the authorization commit point.
A later suspension or revocation blocks new attempts but does not cancel a
container that was already admitted.

## Important files

- `README.md` — current product and runtime truth.
- `docs/Product Architecture.md` — trust boundaries and system design.
- `docs/Roadmap.md` — milestone order and release gates.
- `docs/Week 11 Plan.md` — approved next implementation plan.
- `src/sentinel/contracts.py` — contract lifecycle and stores.
- `src/sentinel/authority/service.py` — audited authority transitions.
- `src/sentinel/actions/` — canonical action representation and shell parser.
- `src/sentinel/decision/contract_policy.py` — contract matching.
- `src/sentinel/approval/service.py` — exact-action approval binding.
- `src/sentinel/session/` — history and at-most-once attempts.
- `src/sentinel/audit/` — redaction and SQLite audit evidence.
- `src/sentinel/api/main.py` — current enforcement API.
- `src/sentinel/execution/docker_executor.py` — local Docker containment.
- `data/evaluation/README.md` — reviewed corpus and independence policy.

## Accepted limits that must remain honest

- Cursor and OpenClaw are advisory, not mandatory enforcement boundaries.
- The local API has no protected human-control channel yet.
- A process with arbitrary same-user host access is outside the current threat
  model.
- A coding agent with access to the user's browser profile or paired browser
  session defeats the independence of local browser approval.
- Local Docker shares the host kernel and is not production-grade tenant
  isolation.
- Mid-flight container cancellation is not implemented.
- Provider metadata spikes do not prove provider-side enforcement.
- The reviewed corpus is known regression evidence, not blind promotion
  evidence.

## Start Week 11

1. Confirm `main` is clean and current.
2. Create `feature/week-11-control-center`.
3. Read `docs/Week 11 Plan.md`.
4. Begin with its Phase 0 trust-boundary spike. Do not scaffold the full UI
   before that gate passes.

Suggested new-chat prompt:

> Read `docs/Week 10 Handover.md`, `docs/Week 11 Plan.md`,
> `docs/Product Architecture.md`, and the Week 11 section of
> `docs/Roadmap.md`. Review the Phase 0 assumptions against the current code,
> create `feature/week-11-control-center`, and implement only Phase 0 first.
> Keep FastAPI as the authority, raw prompts draft-only, ML disabled, real
> workspaces read-only, and all external agent integrations advisory.

## Baseline verification commands

```bash
python3 -m pytest
git diff --check
python3 scripts/evaluate_contracts.py \
  data/evaluation/contract_combined_reviewed.jsonl \
  --minimum-rows-per-category 1 \
  --manifest /tmp/sentinel-known-regression.json
PYTHONPATH=src python3 scripts/docker_smoke_check.py
```

The Docker smoke requires Docker Desktop. Do not overwrite committed evaluation
manifests during exploratory runs.
