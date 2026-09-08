# Week 11 Plan: Local Control Center

Status: final and reviewed on September 8, 2026.

This plan narrows the broader roadmap into one polished, protected vertical
slice. It is the implementation authority for Week 11 when it conflicts with
older aspirational Week 11 wording.

## Goal

Ship a desktop-first local web control center for one developer supervising a
coding agent in one repository:

```text
Create task
  -> review deterministic questions and contract
  -> explicitly activate authority
  -> inspect active authority
  -> agent proposes an exact action
  -> approve or deny
  -> approved action retries once and consumes approval
  -> inspect ordered audit evidence
```

FastAPI remains the security authority. Next.js is a human-control client, not
a second policy engine.

## Fixed product decisions

- Primary user: one developer supervising one coding agent in one repository.
- Workspace: one reviewed local repository, resolved and fixed at process
  startup. An optional Git remote is display-only after credentials, query
  strings, and fragments are removed; Sentinel never fetches from it.
- Authority: the server creates one supervision session at startup and binds
  both the paired browser and demo runner to it. Control requests cannot choose
  a `session_id`. The UI labels that session's authority with the fixed
  workspace name; the workspace itself does not own authority.
- Restart binding: persist the supervision-session ID with a canonical
  workspace identity in the same state database. Restarting against the same
  workspace may resume it; a workspace identity mismatch must fail startup or
  require a new empty state database. Authority must never carry from one
  repository to another.
- Contract input: natural-language task first, deterministic extraction,
  focused questions, then an editable structured contract.
- Activation: every new contract requires an explicit browser action.
- Raw prompt: may exist transiently in browser memory and in one bounded
  FastAPI request while deterministic compilation runs. Persist the SHA-256 of
  its exact UTF-8 bytes without normalization and the accepted structured
  contract, never the raw text.
- Contract presentation: plain-language summary first, exact boundaries below,
  raw JSON inside an Advanced disclosure.
- Navigation: Overview, Tasks, Approvals, Audit.
- Global context: active authority remains visible from every page.
- Approval: normal confirmation uses Approve/Deny. Destructive or production
  actions require typing the exact target.
- Denial: record it, preserve current task authority, and offer either
  a safer suggested action or a fresh task draft. Amendment controls are
  deferred.
- Approval completion: the token remains server-side. The demo runner
  retries the same exact action binding and `attempt_id`; the internal token is
  the only added material, and atomic admission consumes it.
- Onboarding: three short checks followed by an optional, skippable demo.
- Integration honesty: show "No mandatory agent connected." Cursor, OpenClaw,
  MCP, and other host surfaces remain advisory.
- Demo: Sentinel may create a disposable sample repository before backend
  startup and launch a dedicated process bound to it. Runtime workspace
  selection is forbidden, and the user's real repository is never modified.
- Device target: desktop-first.
- ML: disabled and out of scope.

## Visual direction

Use a premium light developer-tool interface:

- white page canvas;
- baby-blue raised surfaces and primary actions;
- neutral ink, compact Inter typography, and restrained density;
- red only for blocked/destructive outcomes;
- green only for successful/allowed outcomes;
- thin borders, subtle card shadows, 8–12px radii;
- Lucide icons only where they improve recognition;
- no gradients, decorative dashboards, card-in-card nesting, or icon-heavy
  generated-looking layouts;
- visible keyboard focus, WCAG AA body contrast, and reduced-motion support.

The baby-blue primary treatment is an explicit Sentinel product decision and
overrides the usual monochrome-primary default. Color must still communicate
hierarchy rather than decorate every element.

## Scope

### Must ship

- Startup workspace review and fixed canonical binding.
- One-use browser pairing and protected control session.
- Deterministic task draft plus focused clarification questions.
- Editable contract review and explicit activation.
- Workspace-visible active authority summary.
- Pending exact-action approval list.
- Approve and deny flows.
- Server-owned automatic retry for one truthful demo action.
- Atomic approval consumption and replay rejection.
- Compact operational audit summary with the exact event list immediately
  below it.
- Optional disposable sample repository.
- One Playwright critical path using real FastAPI control and enforcement APIs.

### Explicitly deferred

- Reusable task templates.
- Custom rules UI.
- Research, personal-assistant, and operations presets.
- Multi-workspace switching.
- GitHub OAuth.
- Marketing site.
- Mandatory Cursor, Codex, OpenClaw, or MCP enforcement.
- Slack or Google production enforcement.
- ML training, calibration, or serving.
- Hosted accounts, multi-tenancy, billing, and organization RBAC.
- General write access to the user's real workspace.
- Mid-flight Docker cancellation.

## Threat model

### In scope

- Unpaired callers invoking protected local routes.
- The guarded agent attempting to mint, activate, expand, approve, or revoke
  authority.
- Pairing-token replay or leakage through URLs, logs, audit, or responses.
- Cross-site requests from a malicious webpage.
- Approval replay, changed-action reuse, and concurrent retries.
- Workspace path traversal, symlink escape, and runtime workspace switching.
- Raw prompt leakage into SQLite, audit events, logs, or error responses.

### Out of scope

- Arbitrary compromise of the developer's operating-system account.
- A process that can read Sentinel server memory or browser cookies/profile.
- An attacker controlling the developer's browser.
- A coding agent intentionally granted browser automation or paired-profile
  access.

If the agent can control the paired browser, browser approval is not an
independent human channel and Sentinel must say so.

## Phase 0: Prove the load-bearing boundary

Do this before scaffolding the full UI.

### Riskiest assumption

Sentinel can provide a browser-only human control channel and demonstrate one
real `confirm_required -> approve -> retry -> execute` action without exposing
approval authority to the agent or weakening the Week 10 fail-closed boundary.

### Spike

1. Create any disposable sample repository before backend startup. Resolve the
   chosen workspace with `realpath` at startup and reject runtime changes,
   parent traversal, and symlink escape.
2. Persist the server-owned supervision-session ID with the canonical workspace
   identity. Prove a restart with the same state database and a different
   workspace fails closed.
3. Generate a cryptographically random, short-lived, one-use pairing
   capability. Store only its hash and compare it in constant time.
4. Bind both services to loopback, choose one canonical hostname, and accept
   credentialed browser requests only from the exact local UI origin. Reject
   `Origin: null`, unexpected Host values, and wildcard CORS.
5. Deliver the capability to the UI in the URL fragment. Remove it with
   `history.replaceState` before exchanging it for an HttpOnly, host-only,
   SameSite=Strict control session, then invalidate it.
6. Apply Host/Origin checks to pairing exchange as well. Every other
   `/control/*` route additionally requires the paired session. Define session
   inactivity/absolute expiry and explicit logout.
7. Prove unpaired `/evaluate` and `/execute` callers cannot access control
   routes or receive approval tokens.
8. Freeze one demo contract, one allowed read, one confirmable action, one
   blocked action, and the expected audit sequence.

### Truthful confirmation demo

Create the Sentinel-owned disposable repository before the dedicated demo
server starts. Keep its repository mount read-only and expose only a fresh,
Sentinel-owned `build/` subdirectory as writable. The Docker spike must prove
that parent/sibling paths, traversal, symlinks, hardlinks, and mount-source
substitution cannot escape that subdirectory; cleanup must remove it. The
proposed action creates exactly one marker file there. It is a real state
change, requires exact-action confirmation, and cannot modify the user's
repository.

If a nested writable mount cannot be represented and validated without making
the full workspace writable, do not fake the demonstration. Fall back to an
approval-only proof and defer executed writes.

### Kill conditions

Stop and narrow Week 11 if any is true:

- An unpaired caller can invoke an authority or approval control.
- The pairing capability appears in logs, audit, normal responses, or retained
  browser history.
- Raw prompt text reaches persistent state, logs, audit, errors, retries, or
  telemetry.
- Workspace confinement can be escaped or changed without restart.
- Existing authority can be loaded with a different startup workspace.
- No real action can complete confirmation, server-owned retry, and atomic
  execution without weakening a deterministic block.
- Approval can authorize changed action details or more than one launch.
- The critical browser flow requires OAuth, ML, templates, custom rules, or a
  mandatory external agent.

### Exit gate

Focused backend tests prove the pairing, workspace, raw-prompt, approval,
retry, replay, and concurrency guarantees. Only then begin the full interface.

## Phase 1: Protected control backend

Add a separate control package instead of expanding the agent request schemas:

```text
src/sentinel/control/
  pairing.py
  workspace.py
  drafts.py
  approvals.py
src/sentinel/api/
  control_routes.py
  control_schemas.py
```

Wire existing services rather than reimplementing them:

- `ContractAuthorityService` for lifecycle changes.
- `InMemoryTrustedEventConsumer` for one-use trusted UI events.
- `InMemoryApprovalService` initially, adding query/denial behavior without
  exposing `issue()` to agent routes.
- `SQLiteContractStore`, `SQLiteSessionStore`, and `SQLiteAuditStore` as the
  server-owned state.

Minimum protected routes:

```text
POST /control/pair/exchange
GET  /control/status
POST /control/contracts/draft
POST /control/contracts/activate
GET  /control/authority/active
GET  /control/approvals
POST /control/approvals/{id}/approve
POST /control/approvals/{id}/deny
GET  /control/audit
```

Rules:

- Pairing exchange is the only unpaired control route.
- Pairing exchange still requires the exact loopback Host and UI Origin.
- Control schemas reject unknown fields.
- The server-owned supervision session is implicit; control requests cannot
  select another authority session.
- Agent routes remain `GET /health`, `POST /evaluate`, and `POST /execute`.
- Approval tokens never appear in browser network traffic, normal responses,
  logs, audit events, or errors.
- Contract activation uses a fresh trusted UI event and compare-and-swap
  lifecycle checks.
- Draft compilation is deterministic and never guesses a target, environment,
  effect, or rollback fact.
- Draft requests are size-bounded, never logged, and failure-injection tests
  prove raw text is absent from every persistent/error path.
- `/control/status` treats intentionally disabled ML as disabled, not unhealthy.
- Audit queries add server-owned session/task filters required by the UI.
- A restart expires pending approvals, pairing/control sessions, and
  process-local retry envelopes fail closed.

## Phase 2: Approval and demo-runner loop

Implement a small server-owned demo coordinator:

1. Submit the initial action to `/execute` with a stable `attempt_id`.
2. Confirm that `confirm_required` does not reserve an execution attempt,
   matching current Week 10 behavior.
3. Store a bounded server-owned execution envelope containing the raw command
   needed for execution plus its canonical binding, contract/version/epoch,
   supervision session, environment, workspace, approval ID, and intended
   `attempt_id`. Never store the task's raw natural-language prompt.
4. Show the complete operation, targets, effects, workspace, contract version,
   authority epoch, reason, and expiry in Approvals.
5. Bind the pending approval to the coordinator envelope and intended
   `attempt_id`.
6. On denial, write audit evidence, delete the envelope, and launch nothing.
7. On approval, issue the token internally, add it only to the server's retry
   call, and signal the coordinator. The browser and guarded agent never
   receive it.
8. Retry with the same `attempt_id` and exact action binding. The internal token
   is the only added authorization material.
9. Consume approval only inside durable execution admission.
10. Return the stored completed/failed result on safe terminal replay;
    reserved, running, conflicting, or unknown attempts never relaunch.

Add focused tests for changed target, operation, effect, environment, version,
epoch, expired approval, double click, concurrent retry, audit failure, and
executor failure.

## Phase 3: Web foundation

Create `web/` with:

- Next.js App Router;
- React and TypeScript;
- Tailwind CSS;
- selected shadcn/Radix primitives;
- Lucide icons;
- Playwright.

These technologies are architectural intent, not authorization to edit package
manifests or install packages. Before Phase 3 implementation, present the exact
dependency list and wait for explicit user approval. After approval, use the
package manager to add current supported releases rather than inventing
versions manually. Keep frontend types generated from or checked against
FastAPI schemas rather than duplicating security decisions in TypeScript.

Application shell:

- left navigation: Overview, Tasks, Approvals, Audit;
- persistent top authority bar;
- connection state that says whether the flow is Sentinel-owned or advisory;
- deterministic loading, empty, error, expired-session, and disconnected
  states.

## Phase 4: Core screens

### Overview

- Three startup checks: backend, reviewed workspace, Docker.
- Rules-only health shown as healthy when all enabled components are ready.
- If the current process was launched in demo mode, identify its pre-created
  sample repository. Otherwise offer instructions to relaunch a dedicated demo
  process; never switch the running workspace.
- Active authority and pending approval summary.
- No decorative chart wall.

### Tasks

- Single-page split view.
- Left: task prompt and only the focused missing-field questions.
- Right: live plain-language contract summary and exact boundaries.
- Every inferred field carries a source label and requires review.
- Raw JSON is collapsed under Advanced.
- Activation is a distinct final action.

### Approvals

- Complete action-versus-contract diff.
- Approve/Deny for normal confirmation.
- Exact-target typing for destructive/production actions.
- Denial recovery choices.
- Clear pending, approved, denied, expired, consumed, and failed states.

### Audit

- Compact counts, outcome trend, pending approvals, and recent high-risk events.
- Exact event table immediately below.
- Filters for task, event type, verdict, and time.
- Ordered detail for activation, request, decision, consumption, admission, and
  result.
- No raw prompts, secrets, or unbounded command output.

## Phase 5: End-to-end verification

One Playwright path must use the real local APIs:

1. Create a disposable repository and writable demo build directory.
2. Start a dedicated backend already bound to that repository.
3. Pair the browser.
4. Pass the three startup checks.
5. Enter a task.
6. Answer a focused question and edit one inferred boundary.
7. Activate explicitly.
8. Confirm the authority bar updates.
9. Submit the confirmable demo action.
10. Deny it and verify zero execution.
11. Submit again with a new attempt.
12. Approve it.
13. Verify one automatic retry and exactly one marker write.
14. Inspect the ordered audit trail.

Backend tests remain responsible for concurrency, replay, path escape,
redaction, and failure injection. Playwright must not mock contract activation,
approval, execution, or audit.

## Phase 6: Finish and hand off

- Capture desktop screenshots of all four pages and key states.
- Run accessibility checks and keyboard navigation.
- Run the full Python suite, web type check/lint/tests, Playwright path, Docker
  smoke, and `git diff --check`.
- Update README and architecture claims to match only verified behavior.
- Run independent correctness and security reviews.
- Commit in small dependency order; do not merge until all gates pass.

## Definition of done

Week 11 is complete only when:

- a new user can pair and understand the local boundary;
- one reviewed workspace is fixed at startup;
- raw prompt text is absent from persistence and logs;
- a deterministic draft cannot activate itself;
- explicit activation creates visible task authority;
- unpaired agent callers cannot mutate or approve authority;
- denial launches zero executions;
- approval retries exactly one unchanged action and is consumed once;
- conflicting or concurrent reuse cannot launch twice;
- the audit view proves the complete sequence;
- one real Playwright path and the full backend/Docker checks pass;
- the UI clearly says no mandatory external agent is connected.

## Recommended commits

1. `Add protected local pairing and workspace binding`
2. `Add control routes for task authority`
3. `Add server-owned approval retry flow`
4. `Build the local control center shell`
5. `Add task review and activation`
6. `Add approval and audit workflows`
7. `Add the protected browser regression path`
8. `Document the verified Week 11 boundary`
