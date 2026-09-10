# Week 12 Handover

Status: implemented and verified in the working tree on September 9, 2026.
The work is not yet committed. Independent correctness and security reviews
were run against the full Week 12 change and every confirmed finding was
fixed; see "Review findings".

This handover is the factual starting point for Week 13. The plan it closes
is [Week 12 Plan](./Week%2012%20Plan.md); the spike that de-risked it is
[Week 12 Phase 0 Spike](./Week%2012%20Phase%200%20Spike.md).

## What Sentinel is now

Sentinel is a local-first authorization and supervision system for AI-agent
actions. FastAPI owns task authority, evaluates proposed actions, manages
one-time approvals, records ordered audit evidence, and admits supported
execution to Docker.

Week 12 added the first path where an external agent's tool *cannot* act
around Sentinel. Cursor sees two ordinary MCP tools for a local issue tracker.
Every call to those tools travels through a Sentinel checkpoint that checks a
fixed startup ceiling, the active task contract, and the approval state before
anything happens. If Sentinel is stopped, the tools fail closed and report
"nothing was performed". The human still approves in the Week 11 browser
control center, which never exposes approval tokens to the agent.

The honest claim this earns, in the tested configuration:

> With Cursor's agent sandbox enabled and the Sentinel hooks installed, every
> effect on the local issue fixture passed through Sentinel's policy and
> approval path, and Sentinel stopping prevented the effect. The agent's shell
> could read but not alter Sentinel state. Other Cursor action families
> (shell, file edits, browser) remain advisory.

## Week 12 result

- Added an immutable `SupervisionPolicy` startup ceiling: allowed tool
  family, issue-ID scope, ordinary vs confirm-required vs forbidden
  operations, and process lifetime. Fixed at startup, content-bound, stored
  durably, never widened by a contract.
- Added an adapter session registry that identifies the Cursor MCP shim with a
  hashed bearer capability (constant-time comparison, rotation on reissue) and
  binds every call to the single supervision session. The bearer identifies
  the adapter kind; it is not task authority and is not secret from a
  same-user agent.
- Added an isolated SQLite issue fixture owned by Sentinel with durable
  operation states (`prepared`, `succeeded`, `failed`) keyed by `attempt_id`,
  giving at-most-once writes across retries, replays, and crashes.
- Added the `McpMediator` and `POST /integration/mcp/call`. It reuses the
  existing contract matcher, approval service, authority service, and audit
  store rather than adding a second policy engine.
- Added a stdio MCP shim (`src/sentinel/mcp/server.py`) so Cursor discovers
  the tools normally. The shim holds no policy; it forwards and fails closed.
- Extended the approval envelope so a pending MCP write shows the exact tool
  and arguments in the browser, and the server performs the approved write
  itself at approval time.
- Extended the task form so a task can target fixture issues, validated
  against the startup ceiling at draft time.
- Added truthful control-center status: MCP connection, per-family coverage
  (mandatory / advisory / unsupported) with basis and known limits, and hook
  and sandbox state. This lives under Settings → Connections; the Overview
  keeps only the one-line connection status in the header so it stays focused
  on the current task and pending attention.
- Added Cursor project hooks (`policies/cursor/`) that fail closed on reads or
  commands touching Sentinel private state or Cursor configuration.
- Added a launcher (`scripts/week12_control_demo.py`) that starts Sentinel
  with a disposable workspace, fixture, and adapter capability, prints the
  `mcp.json` block, and can report fixture state after shutdown.

## Verified live Cursor run

Run on September 9, 2026 with Cursor's agent sandbox on, Sentinel hooks
active, Sentinel started from the user's own terminal, and the human acting
in the paired browser.

```text
task activated in the browser (write, fixture issues, SPIKE-1, sandbox)
  -> 3 matching reads              allow      mcp:matching_read
  -> note write A                  held       approval created, nothing written
  -> human denied A in browser
  -> retry of A                    block      mcp:attempt_failed
  -> note write B                  held       approval created, nothing written
  -> human approved B in browser   server applied the note once
  -> retry of B (same attempt id)  allow      mcp:already_applied, note_added=false
  -> identical replay of B         allow      duplicate_suppressed=true
  -> changed body, same attempt id block      fixture:attempt_binding_mismatch
  -> Sentinel stopped (Ctrl-C)
  -> fixture state                 notes: 1 (note B), operations: 3 reads ok,
                                   A failed, B succeeded
```

Two extra findings came out of the live run, both fixed the same day:

- The first read was blocked with `contract:dry_run_required` because the
  task had "Test first" set to yes. Fixture tools have no dry-run mode, so
  Sentinel correctly refused every call. Drafting such a task now returns a
  clear 422 and the form says which setting to change. This was fail-closed
  behaving correctly against an unsatisfiable task.
- After approving write B, the Approvals page showed a red "execution failed"
  banner even though the server returned 200 and the note landed exactly once.
  The page judged MCP outcomes by shell rules (exit code). It now reads the
  MCP reasons instead, with a Playwright test for the exact case.

Two independent layers also fired during the run and are worth recording:
Cursor's own auto-review paused each agent write before it reached Sentinel
(a discretionary per-chat gate), and the Sentinel shell hook blocked the agent
from listing the run directory (a fail-closed configured gate). Neither
replaces the other.

## Measurements

Environment: macOS, Python 3.11 in-process FastAPI `TestClient`, SQLite on
local disk, Cursor 2026-09 with sandbox on for the live run.

| Measure | Result |
|---|---|
| Fixture family mediation observed | 100% of effects passed through Sentinel (live run + harness) |
| Tested fixture bypasses (sandbox on) | 0 successful; raw byte read of fixture file is allowed (information only, no effect) |
| Effects while Sentinel unavailable | 0 (Phase 0 harness: gateway down → "nothing was performed"; live run: 1 note after shutdown, unchanged) |
| Changed-action or replay acceptance | 0 (live run and tests) |
| Duplicate notes | 0 |
| Adapter or approval capability exposure | Adapter bearer is readable by a same-user agent by design and grants no authority; approval tokens never leave the server |
| Decision latency, read allow (n=200) | p50 2.7 ms, p95 8.4 ms |
| Decision latency, write → confirm_required (n=100) | p50 1.9 ms, p95 2.4 ms |
| Decision latency, out-of-scope block (n=100) | p50 1.5 ms, p95 2.2 ms |
| Coverage labels | fixture tools `mandatory`; shell `advisory`; browser `unsupported` |

Latency is the in-process API path and excludes Cursor's stdio hop. These are
bounded local results, not production guarantees.

## Verification evidence

- Full Python suite: 592 tests passed.
- Playwright mocked-state suite (port 3100 config): 18 passed, including five
  Week 12 tests for coverage display on Settings, an Overview free of MCP
  detail, MCP approval cards, and the approval outcome banner.
- Frontend type check, ESLint, generated-type check, and production build:
  passed.
- `git diff --check`: passed.
- Credential-pattern scan of the Week 12 paths: no hits. The only repository
  hits are pre-existing Slack token *prefixes* used as detection fixtures.
- Real Cursor MCP run: passed as recorded above.
- Independent correctness review (Bugbot) and security review: run against
  the full uncommitted change. Findings and their disposition are listed in
  "Review findings" below.

Not re-run this week: the Week 11 real Playwright path through Docker
(`real-control-flow.spec.ts`) and the Docker smoke. The Docker executor code
did not change; the shell approval path is covered by the unchanged backend
tests.

## Review findings

**Security review** (independent, full uncommitted diff): no medium, high,
or critical findings. Verified: bearer stored only as SHA-256 and compared in
constant time; capability file written 0600 in a 0700 directory with only the
path printed; the integration route rejects wrong `Host` and any
browser-originated request; the request model forbids extra fields and the
canonicalizer requires the exact argument key set, so no caller-supplied
verdict, contract, session, or history can reach a decision; approval binding
covers attempt, payload hash, targets, effects, contract version, epoch, and
ceiling hash; audit, fixture, and Sentinel-down failures all fail closed.

Two low-severity robustness notes were raised and fixed the same day:

- If the adapter capability was rotated between the agent's request and the
  human's approve click, the approved retry consumed the token and then hit a
  fixture binding mismatch, surfacing as a 500 with the operation stuck in
  `admitted`. The retry now compares the stored operation binding before
  consuming the token, fails the operation, and returns a clean
  `approval:binding_mismatch` block. Covered by
  `test_adapter_rotation_between_request_and_approval_blocks_cleanly`.
- The approved retry always returned `allow`, and the `post_execution` audit
  row always carried `verdict="allow"`, even if the fixture ended in a
  non-succeeded state. Both now follow the actual terminal state
  (`mcp:approved_write_not_applied` on anything but `succeeded`).

Confirmed as accepted, documented limits rather than findings: a same-user
agent can read the adapter capability and call the route directly (identical
policy applies; approval still needs the HttpOnly browser session); the hooks
match strings and paths and are a second layer behind Cursor's sandbox; the
pairing link is opened through the browser as in Week 11.

**Correctness review (Bugbot)**: the first run was rejected by the model
provider's content classifier because of the security vocabulary in the
brief, not because of anything in the code. The rerun with neutral wording
produced five findings; all were fixed the same day.

- *Medium — fixture tasks accepted unsatisfiable safeguards.* The dry-run fix
  from the live run had three siblings: `rollback_required`,
  `transaction_required`, and `backup_required` were passed straight into the
  contract, and the MCP action never sets the matching facts, so any such task
  would block every call. Drafting a fixture task with any of the four now
  returns one 422 naming them; the form hides the safeguard checkboxes for
  fixture tasks and clears them when switching target kind. Tested for all
  four flags.
- *Medium — an operation stuck in `applying` caused 500s and duplicate
  admission evidence.* If the effect crashed in-process after `applying`
  became durable, later retries were treated as fresh, wrote another
  `execution_admitted` audit row, and then failed inside the fixture. The
  mediator now treats `applying` like `unknown` (block,
  `mcp:outcome_unknown`), `_admit` checks the fixture state before writing
  audit, and both the direct and approved-retry paths convert admission
  failures into clean blocks instead of 500s. Tested: one admission row,
  zero notes, verdict block.
- *Low — Activity described a failed MCP write as finished.* The
  `post_execution` description now follows the verdict, and the audit
  details include the target so the "on SPIKE-1" suffix renders.
- *Low — machine-specific `.cursor/mcp.json` would be committed.* It holds an
  absolute path to a per-run capability file and goes stale on every launch.
  Added to `.gitignore`; the reusable profile stays in `policies/cursor/`.
- *Low — untested branches.* Added tests for ceiling expiry (block plus
  status flip to unavailable), admission audit failure (block, operation
  stays `prepared`, later retry succeeds), and the stuck-`applying` path.

## Current HTTP boundary

Agent-facing routes are unchanged: `GET /health`, `POST /evaluate`,
`POST /execute`.

When a `SupervisionPolicy` is supplied at startup, the process additionally
exposes one adapter-facing route:

- `POST /integration/mcp/call` — requires `Authorization: Bearer <adapter
  capability>`; body is `{tool, arguments, attempt_id}`; response is the
  verdict, reason code, coverage status, operation state, and result. The
  caller cannot supply a verdict, contract, session, or history.

The protected browser routes from Week 11 are unchanged in shape.
`GET /control/status` now includes `integration` (connection, coverage,
ceiling, hooks/sandbox) and `GET /control/approvals` entries include
`family`, `tool`, and `arguments`.

## Current trust and execution boundary

- FastAPI is the authority. Next.js is an untrusted human-control client. The
  MCP shim is an untrusted forwarder.
- The startup ceiling is fixed for the process lifetime. Contracts can only
  narrow within it.
- The adapter bearer binds calls to the one supervision session and
  identifies the adapter kind. It is not proof the call came through Cursor's
  tool path, and any holder is subject to identical policy, approval,
  admission, and audit.
- Every MCP write is prepared under its `attempt_id` before any decision, and
  the same `attempt_id` with different arguments is rejected forever.
- Approved writes are performed by the server during approval; the agent's
  later retry only observes the outcome.
- Cursor's sandbox is the write boundary around Sentinel state and Cursor
  configuration; Sentinel hooks are a second fail-closed layer. Sentinel shows
  their status but cannot enforce the user's sandbox setting.
- Reads of Sentinel files by a same-user agent are possible and are treated as
  information exposure, not an effect.

## Important implementation files

Mediation path:

- `src/sentinel/supervision/policy.py` — immutable startup ceiling and store.
- `src/sentinel/integrations/registry.py` — adapter sessions and capability
  hashing.
- `src/sentinel/integrations/models.py` — adapter session, connection, and
  coverage records.
- `src/sentinel/integrations/hooks.py` — inspects Cursor `hooks.json` for the
  fail-closed profile.
- `src/sentinel/mcp/fixture.py` — isolated SQLite issue fixture with durable
  operation states.
- `src/sentinel/mcp/mediation.py` — server-side canonicalization and decision.
- `src/sentinel/mcp/gateway.py` — `McpMediator`: authenticate, ceiling,
  contract, approval, audit, apply.
- `src/sentinel/mcp/server.py` — stdio MCP shim for Cursor.
- `src/sentinel/api/integration_routes.py`, `integration_schemas.py` — the
  adapter-facing route.
- `src/sentinel/api/main.py` — wiring, MCP-aware approval retry, fixture task
  validation.

Control center:

- `web/src/components/agent-coverage.tsx` — connection, hook/sandbox, and
  per-family coverage block.
- `web/src/app/settings/page.tsx` — Connections shows the live Cursor MCP
  status and hosts the coverage block.
- `web/src/app/page.tsx` — Overview no longer shows MCP detail.
- `web/src/app/approvals/page.tsx` — MCP approval cards and family-aware
  outcome.
- `web/src/app/tasks/page.tsx` — target kind selector for fixture tasks;
  review ticks only on authority-granting fields; dry-run hidden for fixture
  tasks.
- `web/src/app/audit/page.tsx` — MCP tool and target in event descriptions.

Configuration and proof:

- `policies/cursor/hooks.json`, `policies/cursor/sentinel_hooks.py` — the
  fail-closed hook profile to install as `.cursor/hooks`.
- `scripts/week12_control_demo.py` — live-run launcher and state inspector.
- `scripts/week12_spike/` — Phase 0 disposable spike (kept as evidence).
- `tests/test_supervision_policy.py`, `tests/test_integrations_registry.py`,
  `tests/test_mcp_fixture.py`, `tests/test_mcp_mediation_api.py`,
  `tests/test_cursor_hooks_profile.py`.
- `web/tests/e2e/week12-integration.spec.ts`,
  `web/playwright.mocked.config.ts`.

## Accepted limits that must remain honest

- Only the disposable fixture tool family is mandatory. Cursor shell, file,
  browser, and subagent actions remain advisory or unsupported, and the UI
  says so per family.
- The boundary depends on the user keeping Cursor's sandbox on and the hooks
  installed. Approving an "outside the sandbox" escalation for Sentinel paths
  defeats it. Sentinel displays this; it cannot prevent it.
- A same-user agent can read the adapter capability and fixture bytes. This
  grants no authority and produces no effect, but it is information exposure.
- The fixture is a stand-in for a real tracker. No provider credentials, no
  Linear/Jira/GitHub write path.
- Adapter sessions, pending approvals, and retry envelopes are process-local.
  Restarting Sentinel requires a fresh pairing and a fresh `mcp.json` block.
- The task still has to be created by hand in the browser before the agent
  can act. The form now requires explicit confirmation of only the five
  settings that grant authority (operation, targets, environment, allowed
  changes, expiry); descriptive and narrowing suggestions are accepted unless
  changed. This is still the friction Week 13 is meant to remove.
- Contracts are scoped per workspace, not per agent. One Sentinel process has
  one supervision session and one active contract, so two agents working in
  the same workspace share a boundary and one can be blocked by the other's
  task. Per-agent session isolation is scheduled for Week 16 (roadmap order
  kept by decision on September 9, 2026).
- Sandbox behavior on Linux and Windows, hook behavior inside subagents, and
  whether the browser tool can reach the paired approval session are
  unverified.
- Latency was measured in-process and excludes the stdio hop.

## Start Week 13

1. Review and commit Week 12 only when explicitly requested, after the review
   findings section is filled in.
2. Merge through the normal protected-branch process.
3. Read the Week 13 section of `docs/Roadmap.md` (automatic task preparation)
   and confirm direction before writing a plan.
4. Riskiest assumption to spike first: whether a Cursor prompt event can
   prepare a complete, correct fixture-task draft that the human confirms in
   one compact step, without the prompt being treated as authority.
5. Keep every non-fixture action family labeled advisory.

## Baseline verification commands

From the repository root:

```bash
python3 -m pytest -q
git diff --check
python3 scripts/generate_control_types.py --check
```

From `web/`:

```bash
npm run typecheck
npm run lint
npm run build
npx playwright test -c playwright.mocked.config.ts
```

For the live run, see the docstring at the top of
`scripts/week12_control_demo.py`. Start Sentinel from your own terminal (not
from the agent), keep Cursor's sandbox on, and paste the printed block into
`.cursor/mcp.json`. When creating the fixture task, set "Test first" to No.
After stopping Sentinel, run
`python3 scripts/week12_control_demo.py state <run directory>` and expect
exactly the notes you approved.
