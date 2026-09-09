# Week 11 Handover

Status: implemented and verified on `feature/week-11-control-center` as of
September 9, 2026. The work is not yet merged. Final verification includes
durable recovery after an unverified authority transition.

This handover is the factual starting point for Week 12. The proposed next
implementation plan is [Week 12 Plan](./Week%2012%20Plan.md).

## What Sentinel is now

Sentinel is a local-first authorization and supervision system for AI-agent
actions. FastAPI owns task authority, evaluates proposed actions, manages
one-time approvals, records ordered audit evidence, and admits supported
execution to Docker.

Week 11 added the first protected human-control experience. A paired browser
can create and activate a task boundary, review one exact high-risk action,
approve or deny it, and inspect what happened afterward. The browser displays
server state but cannot mint approval authority or make policy decisions.

This is a working security proof, not the final daily product workflow. The
current task form asks the user to create a contract manually. Future work
should make that contract mostly invisible: advisory host prompts can prepare
complete drafts, protected confirmation can create authority, and the web app
can focus on agent oversight, connections, approvals, guardrails, and activity.

## Week 11 result

- Added a protected control API beside the existing agent-facing evaluation
  and execution routes.
- Bound each control process to one reviewed Git workspace and one
  server-owned supervision session.
- Added browser pairing that is one-use within one process, with an HttpOnly
  local session, exact loopback Host and Origin checks, and explicit logout.
  Launchers must generate a fresh pairing capability after every restart.
- Kept raw task prompts draft-only. The accepted structured contract and a
  content hash may persist; raw prompt text does not.
- Added deterministic task drafting, field-level review, proposal creation,
  and explicit browser activation.
- Added pending approval listing, denial, exact-action approval, server-owned
  retry, and atomic one-time consumption without sending approval tokens to
  the browser or agent.
- Invalidated stale approvals when task authority changes.
- Added an authority-availability gate that disables authority-dependent
  operations if an activation audit and its compensating suspension cannot be
  verified during the current process lifetime.
- Added ordered audit sequence IDs and newest-first bounded audit querying
  while preserving event order in returned results.
- Added a confined write demonstration: the repository remains read-only and
  only a fresh, privately owned `build/` directory is writable.
- Added a Next.js control center with Overview, Tasks, Approvals, Activity,
  and Settings surfaces.
- Added generated frontend control types, premium accessible controls, a
  collapsible navigation rail, real connection icons, and the Sentinel mark.
- Added a real browser path through Next.js, FastAPI, SQLite, and Docker with
  no mocked Sentinel API calls.
- Kept ML disabled in control mode and rejected control startup when model
  loading is enabled.
- Kept Cursor, OpenClaw, MCP, and provider integrations explicitly advisory.

## Verified end-to-end behavior

The real browser path proves:

```text
one-use browser pairing
  -> deterministic task draft
  -> explicit contract activation
  -> exact action submitted
  -> denial with zero execution
  -> new exact action submitted
  -> human approval
  -> one unchanged server-owned retry
  -> one confined Docker write
  -> replay rejection
  -> ordered audit evidence
```

The browser never receives an approval token. Approval is bound to the exact
action, task, contract version, authority epoch, environment, workspace, and
intended execution attempt.

## Verification evidence

- Python 3.11 container suite: 543 tests passed.
- Playwright: 14 tests passed.
- Frontend type check, ESLint, generated-type check, and production build:
  passed.
- Real Playwright path through FastAPI, SQLite, and Docker: passed.
- Phase 0 pairing/workspace smoke: passed.
- Docker executor and nested writable-mount smoke: passed.
- Desktop semantic structure, keyboard navigation, visible focus, reduced
  motion, and WCAG AA text contrast checks: passed.
- Independent correctness and security reviews: completed; their confirmed
  implementation findings were addressed before the final regression. The
  later handover review identified the authority restart-recovery gap, which is
  now fixed and covered by process-reconstruction tests.
- Patch formatting with `git diff --check`: passed.
- Six real-flow screenshots were regenerated under
  `docs/screenshots/week11/`.

The Python run still emits Pydantic migration and dependency deprecation
warnings. They are existing maintenance debt, not failed behavior.

## Current HTTP boundary

The agent-facing API remains:

- `GET /health`
- `POST /evaluate`
- `POST /execute`

When an embedding process supplies a reviewed `ControlConfig`, the protected
local API additionally exposes:

- `POST /control/pair/exchange`
- `GET /control/status`
- `POST /control/contracts/draft`
- `POST /control/contracts/activate`
- `GET /control/authority/active`
- `GET /control/approvals`
- `POST /control/approvals/{approval_id}/approve`
- `POST /control/approvals/{approval_id}/deny`
- `GET /control/audit`
- `POST /control/logout`

Pairing exchange is the only route that does not require an existing control
session. It still requires the exact configured loopback Host and UI Origin.
Control requests cannot select another workspace or supervision session.

## Current trust and execution boundary

- FastAPI is the authority. Next.js is an untrusted human-control client.
- The active contract, recent action history, environment, workspace, and
  approval token are resolved or owned by the server.
- Caller-provided agent identity, user identity, history, and context do not
  grant authority.
- The agent-facing `session_id` is also an untrusted selector. Week 11 control
  mode supports only one server-owned supervision session; multiple sessions
  require authenticated adapter-to-session mapping.
- Shell input is canonicalized into complete targets and effects before
  contract matching.
- Deterministic rules and environment policy decide clear cases before any
  optional model path.
- ML is disabled in the Week 11 control process.
- Real execution requires durable audit admission and an at-most-once
  `attempt_id`.
- Real workspaces remain read-only. Only the disposable demo's reviewed
  nested `build/` directory can be writable.
- Docker runs with no network by default, resource limits, a timeout,
  restricted mounts, and no Docker socket inside the API container.
- Local Docker reduces blast radius but is not a production tenant-isolation
  boundary.

## Important implementation files

Backend control boundary:

- `src/sentinel/control/config.py` — fixed local control configuration.
- `src/sentinel/control/workspace.py` — canonical workspace review and durable
  supervision binding.
- `src/sentinel/control/pairing.py` — one-use pairing and local control
  sessions.
- `src/sentinel/control/drafts.py` — deterministic draft compilation and raw
  prompt handling.
- `src/sentinel/control/approvals.py` — browser-safe approval coordination.
- `src/sentinel/api/control_schemas.py` — strict control request and response
  models.
- `src/sentinel/api/control_routes.py` — protected browser routes.
- `src/sentinel/api/main.py` — enforcement and control-service wiring.
- `src/sentinel/authority/service.py` — audited transitions and the
  authority-availability gate.
- `src/sentinel/approval/service.py` — exact approval binding and
  invalidation.
- `src/sentinel/audit/sqlite_store.py` — ordered persistent audit evidence.
- `src/sentinel/execution/docker_executor.py` — read-only repository with
  optional confined nested write access.

Control center:

- `web/src/components/control-provider.tsx` — pairing, shared control state,
  and refresh behavior.
- `web/src/components/app-shell.tsx` — navigation and truthful global
  enforcement status.
- `web/src/app/page.tsx` — current workspace and attention overview.
- `web/src/app/tasks/page.tsx` — manual draft, review, and activation proof.
- `web/src/app/approvals/page.tsx` — complete exact-action review.
- `web/src/app/audit/page.tsx` — filtered activity and event detail.
- `web/src/app/settings/page.tsx` — current settings and planned connections.
- `web/src/lib/control-api.ts` — browser API client.
- `web/src/lib/control-types.ts` — generated control contracts.

Proof and verification:

- `scripts/week11_phase0_smoke.py`
- `scripts/week11_control_demo.py`
- `scripts/week11_playwright_server.py`
- `scripts/generate_control_types.py`
- `tests/test_control_*.py`
- `web/tests/e2e/real-control-flow.spec.ts`
- `web/tests/e2e/phase4-screens.spec.ts`
- `web/tests/e2e/control-shell.spec.ts`

## Accepted limits that must remain honest

- No external agent is mandatorily connected. The verified enforcement claim
  ends at actions routed through the Sentinel API.
- Current Cursor documentation describes blocking hooks for several tool
  families, but no live Sentinel adapter has proved complete coverage,
  trustworthy direct-user provenance, tamper resistance, or redirected
  execution.
- The manual task form proves contract review; it is too much friction for the
  intended everyday product.
- The Week 11 demo proves one Sentinel-owned shell write path, not general
  write access to a real repository.
- Pairing consumption, pending approvals and tokens, retry envelopes, and
  browser sessions are process-local.
- Protected lifecycle transitions persist a quarantine marker before mutation.
  If completion audit and compensation both fail, restart recovery suspends the
  matching uncertain contract version and audits reconciliation before
  reopening authority. Failed recovery keeps authority closed.
- A process with arbitrary access to the developer's operating-system account
  or paired browser profile remains outside the local threat model.
- Browser approval is not independent if the guarded agent can control the
  paired browser.
- Mid-flight Docker cancellation is not implemented.
- Provider metadata fixtures are synthetic and sanitized. Only one narrow,
  read-only internal Slack metadata path has been live-validated.
- The 90-case reviewed evaluation corpus is known regression evidence, not a
  blind ML promotion set.
- ML serving remains disabled until independent training, calibration, and
  blind evaluation requirements are met.
- Multi-user identity, hosted tenancy, production credential brokering, and
  production-grade execution isolation remain future work.

## Product direction beginning with Week 12

The next product should not require a user to open Sentinel and fill out a
contract before every ordinary task.

The intended normal flow is:

```text
one-time connection and guardrail setup
  -> user works in an agent
  -> prompt prepares a task boundary
  -> protected compact confirmation when provenance is advisory
  -> ordinary in-scope actions continue
  -> unclear or sensitive changes request focused review
  -> Sentinel mediates protected tools
  -> control center shows agents, sessions, approvals, coverage, and activity
```

The contract remains necessary security infrastructure, but it should usually
be generated and maintained behind the user experience. The web app becomes
an oversight and exception-management surface. Manual contract editing remains
an advanced fallback. Week 12 first proves one mandatory MCP tool path; Week 13
begins the lower-friction task experience.

## Start Week 12

Do not begin Week 12 implementation on top of an unreviewed working tree.

1. Review and commit Week 11 only when explicitly requested.
2. Merge Week 11 through the repository's normal protected-branch process.
3. Review and explicitly approve the redesigned Week 12 plan.
4. Create `feature/week-12-mcp-mediation`.
5. Read `docs/Week 12 Plan.md`.
6. Run the plan's Phase 0 mediation spike before adding an MCP dependency,
   redesigning the UI, or integrating a provider.
7. Keep every unsupported action family labeled advisory.

Suggested new-chat prompt:

> Read `docs/Week 11 Handover.md`, `docs/Week 12 Plan.md`,
> `docs/Product Architecture.md`, and the Week 12 section of
> `docs/Roadmap.md`. Confirm that the redesigned Week 12 direction is approved,
> verify the Phase 0 assumptions against current Cursor and MCP behavior, and
> implement only the smallest disposable mediation spike. Do not add
> dependencies without approval. Keep FastAPI authoritative, ML disabled, real
> provider credentials out of scope, and unsupported agent actions explicitly
> advisory.

## Baseline verification commands

From the repository root:

```bash
python3 -m pytest -q
git diff --check
PYTHONPATH=src python3 scripts/docker_smoke_check.py
PYTHONPATH=src python3 scripts/week11_phase0_smoke.py
```

From `web/`:

```bash
npm run typecheck
npm run lint
npm run types:check
npm run build
npm run test:e2e
```

Run the Docker smoke first because it builds the API and executor images used
by later smoke and browser checks. Docker Desktop must be running, and ports
3000 and 8000 must be free before the corresponding UI and API flows.
Exploratory evaluation must write to a temporary manifest rather than
overwriting committed historical evidence.
