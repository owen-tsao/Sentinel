# Project Sentinel: Roadmap

This document is the source of truth for sequencing, milestones, dependencies, and outcomes. Stable product/security behavior belongs in `docs/Product Architecture.md`; implementation-level checklists belong only in the active week plan.

Project Sentinel is a local-first authorization and supervision layer for AI
agents. Users should work where their agents already run while Sentinel derives
bounded task authority, mediates supported tools, interrupts unclear or
sensitive changes, and records what happened. The web app is an agent command
center for setup, oversight, approvals, coverage, and activity; manual contract
editing is an advanced fallback.

This roadmap separates the work into two phases:

- **Part 1: Local Product Proof (Weeks 1-17)** builds the guardrail engine,
  persistent task authority, local execution and audit, protected human review,
  one mandatory MCP fixture path, low-friction task preparation, persistent
  guardrails, a local agent command center, one conditional real-provider
  validation, and a measured release-candidate decision.
- **Part 2: Hosted/Hybrid Expansion** adds organizations, enterprise identity,
  production credential brokering, regional or customer-hosted enforcement,
  observability integrations, and managed execution after the local product is
  useful and enforceable.

## Product Thesis

AI agents are becoming powerful enough to run shell commands, modify infrastructure, send external communications, and trigger production workflows. Enterprises will need a middleware layer that treats every agent action as untrusted until it is evaluated, policy-checked, scoped, and logged.

Sentinel's near-term wedge is not enterprise-wide agent discovery or a general
prompt-writing assistant. The local product should prove that quiet supervision
and mandatory enforcement work together:

- receive task instructions where the user already works;
- prepare a bounded `ActionContract` from explicit facts without silently
  changing user intent;
- let an advisory but complete draft reach protected compact confirmation;
  clarify or reject missing and ambiguous authority-bearing facts first;
- keep one accepted task contract active across many compliant commands and tool calls,
- let an authenticated host-attested direct-user event narrow, replace, or
  clearly extend the current task without repeated approval; advisory host
  prompts remain drafts until protected confirmation,
- require separate approval only when a task adds sensitive authority such as production access, credentials, deployment, external sending, or broad deletion,
- mediate only explicitly supported action families through a host adapter,
  MCP gateway, or Sentinel-owned proxy and label every coverage gap;
- deterministically compare each proposed action with the accepted contract,
- use a PyTorch/ONNX model only for ambiguity or contract-overstep gray areas after evaluation is trustworthy,
- apply deterministic policy rules and risk tiers,
- require confirmation for high-risk but possibly legitimate actions,
- run approved commands in a restricted Docker sandbox,
- write audit logs to a local SQLite store,
- expose the system through FastAPI and a protected local command center for
  connections, agents, active work, guardrails, approval, audit, and health;
- use host and MCP surfaces for task intake, protected tool mediation, compact
  status, and links to exceptional review;
- defer public marketing until the measured local workflow is ready to explain
  honestly.

## Core Product Principles

- **Context matters:** decisions depend on `context`, `command`, and `environment`, not command text alone.
- **Prompt text is not authorization:** vague natural language must be clarified before it can authorize a high-impact action.
- **Supervision should be quiet:** complete ordinary prompts should not require
  users to fill out contracts. Sentinel should prepare the boundary, show the
  smallest necessary review, and keep exact editing available on demand.
- **Authority lasts for a task, not one command:** an active contract covers
  multiple matching actions until a trusted authority event switches tasks, or
  it is suspended, superseded, expired, or revoked.
- **Only trusted authority events can expand authority:** authenticated
  host-attested direct-user events and protected local authority actions may
  grant permission. Agent suggestions and content read from tools, webpages,
  messages, or files cannot.
- **The contract is the boundary:** task identity, operation, exact target, environment, maximum scope, constraints, rollback requirements, authorization source, lifecycle, and approval state must be machine-checkable.
- **Exact-action approval is exceptional:** one-time approval is reserved for sensitive actions and must not turn every ordinary command into a permission prompt.
- **Learn convenience, never permission:** future saved templates and personalization may suggest familiar targets and safety steps, but only a fresh trusted instruction or protected approval can activate authority.
- **Temporal context matters:** decisions should consider the recent action window for the agent session, not only the current command.
- **Malicious is different from destructive:** authorized destructive work may be allowed or require confirmation; malicious or agent-gone-haywire actions should block.
- **Deterministic policy comes first:** critical allow/block rules and environment policy short-circuit before ML inference whenever possible.
- **ML handles gray areas conservatively:** ONNX inference is reserved for ambiguity and contract-overstep signals and may deny/escalate, never independently approve high-impact work.
- **ML cannot broaden permission:** a model score can never downgrade a contract mismatch, environment restriction, deterministic block, missing trusted authority, or incomplete enforcement path.
- **MCP alone is not enforcement:** an MCP tool is advisory unless the host or a proxy guarantees complete mediation of protected actions.
- **Docker is not a production security boundary:** local Docker is acceptable
  for the local product proof; enterprise execution requires stronger
  isolation such as managed orchestration, microVMs, or hardened Kubernetes
  controls.
- **Audit everything:** allowed, blocked, warned, and confirmation-required requests must all be logged.
- **Local-first security:** teams should be able to test policies and commands locally before using hosted infrastructure.
- **Web app is the command center:** connections, agents, sessions, guardrails,
  approvals, enforcement coverage, and mediated activity belong in the local
  control center. It should not become a required form before every task.
- **Integrate where work happens:** Cursor, Codex, MCP, and similar surfaces
  should provide task intake and compact status. Mandatory tool calls run
  through Sentinel; exceptional review routes to the protected web app.
- **Scale without replacing the core:** a future hosted control plane may manage organizations, identity, policy, and audit indexing while enforcement remains local, regional, or customer-hosted.

## Part 1: Local Product Proof (Weeks 1-17)

### Local Product Definition of Done

The local product proof is complete when Sentinel can:

- Accept command-evaluation requests through a FastAPI service.
- Prepare an ordinary task from a supported agent prompt without manual
  contract field entry.
- Activate an advisory but complete task draft through protected compact
  confirmation; clarify or reject missing and ambiguous authority-bearing
  facts first.
- Keep an accepted task contract active across multiple compliant canonical actions.
- Version, replace, narrow, expire, and revoke task authority while preserving its trusted source.
- Let authenticated host-attested direct-user events move to a different
  ordinary task without stale-contract blocks; advisory prompts require
  protected confirmation, and sensitive capability expansion always requires
  review.
- Bind one-use exact-action approvals to a specific contract version and canonical action.
- Evaluate requests using deterministic contract/rule enforcement, with ONNX scoring only if it proves value beyond the rules-only baseline.
- Return structured verdicts: `allow`, `warn`, `confirm_required`, or `block`.
- Run approved commands in a restricted local Docker executor.
- Record audit events in a local SQLite store with a JSONL export/debug format.
- Mandatorily mediate at least one useful local MCP tool family and honestly
  measure every tested bypass.
- Manage local agent sessions, task status, tool/data access, coverage gaps,
  approvals, and activity in one command center.
- Validate one narrow real-provider path only after credential and metadata
  assumptions pass a disposable spike.
- Keep LLM suggestions out of the release path until a later shadow evaluation;
  evaluation may enable draft assistance but never authority.
- Make a release-candidate decision only after the supervision workflow is
  measured and reviewable.
- Keep any CLI limited to non-blocking health, fixture evaluation, and CI diagnostics.
- Produce system metrics: contract-overstep recall, compliant-action false
  interruption rate, enforcement coverage, approval bypass rate, p50/p95
  decision latency, model inference latency only when a model is enabled,
  sandbox latency, and audit logging success rate.

### Local Product Architecture

```text
Agent host / automation
        |
        | task prompt + proposed protected tool calls
        v
Measured host adapter / Sentinel MCP gateway -- authenticated session
                                                    +
Local web command center ----------------------- protected human control
                                                    |
                                                    v
FastAPI control service + SQLite
        |
        | active authority + startup guardrails + measured adapter coverage
        v
Decision engine
        |
        |-- active ActionContract boundary
        |-- deterministic rules and environment policy
        |-- server-owned recent action history
        |-- optional ONNX gray-area score
        |-- protected exact-action approval
        v
Verdict: allow / warn / confirm_required / block
        |
        | if allowed
        v
Action router
        |
        |-- shell command -> local Docker executor
        |-- file/MCP/DB/cloud/provider action -> mandatory adapter/proxy
        |-- no mediated path -> reject
        |
        v
Response + audit event
        |
        |-- agent command center
        |-- compact host/MCP status and review links
        |-- SQLite audit + JSONL export

Public marketing site -> installation and product education only
```

## Phase 1: Product Foundations and Data Contract

### Week 1: Enterprise Threat Model and Data Standard

**Goal:** Define Sentinel's enforcement scope, risk categories, and data contract for a security product.

**Tasks:**

- Refine the threat model around enterprise agent execution:
  - destructive local commands,
  - cloud resource deletion,
  - credential access,
  - data exfiltration,
  - outbound communication mistakes,
  - defense evasion,
  - suspicious install scripts.
- Define initial environments: `sandbox`, `dev`, `staging`, and `production`.
- Define verdicts: `allow`, `warn`, `confirm_required`, and `block`.
- Define the session context contract for recent agent actions, such as the last 3-5 commands, tool calls, files touched, network targets, and sensitive resources accessed.
- Keep the seed dataset as the product's label policy and expand only where it clarifies ambiguous enterprise cases.
- Document the JSONL schema for training/evaluation examples and the audit log schema.

**Deliverable:** Threat model, seed examples, and data schema that clearly distinguish malicious actions from authorized destructive actions.

### Week 2: Dataset Pipeline and Benchmark Ingestion

**Goal:** Build a reproducible data pipeline that can merge curated seed data, benchmark data, and generated edge cases.

**Tasks:**

- Implement `scripts/data_pipeline.py`.
- Load examples from `data/examples/`.
- Validate required fields:
  - `id`
  - `context`
  - `command`
  - `recent_actions`
  - `environment`
  - `label`
  - `risk_category`
  - `source`
  - `expected_verdict`
- Deduplicate exact `(context, command, environment)` examples.
- Add support for sequence-aware examples where the same command has different risk depending on the previous actions in the session.
- Normalize older seed examples without history to `recent_actions: []` so existing curated data remains usable.
- Research CUAHarm and OS-Harm for extractable command/tool traces.
- Create a small benchmark-derived pilot set before scaling ingestion.
- Split processed data into train, validation, and evaluation outputs.

**Deliverable:** Reproducible processed datasets with label/category counts and validation errors surfaced clearly.

### Week 3: Rules Baseline and Policy Specification

**Goal:** Establish deterministic security behavior before training the ML model.

**Tasks:**

- Implement a rules baseline for critical patterns:
  - root deletion,
  - credential file access,
  - secret upload,
  - suspicious `curl | sh`,
  - broad cloud deletion,
  - audit-log deletion,
  - privilege escalation,
  - unsafe mass external communication.
- Define environment-specific policy overrides.
- Define which rules always block versus which rules require confirmation.
- Implement deterministic short-circuit behavior:
  - critical block rules return immediately without model inference,
  - explicit low-risk allow rules can skip model inference in trusted sandbox contexts,
  - only ambiguous gray-area requests continue to the ONNX model.
- Evaluate rules against the seed and processed evaluation set.
- Record baseline recall, false positive rate, and per-category misses.

**Deliverable:** A policy/rules module with baseline metrics and explainable reason codes.

## Phase 2: ML Guardrail Engine

### Week 4: First PyTorch Classifier

**Goal:** Train the first command-risk classifier using the established data contract.

**Tasks:**

- Fine-tune a lightweight text classifier such as DistilBERT.
- Train on `(context, recent_actions, command, environment)` rather than command text alone.
- Encode a rolling window of the last 3-5 agent actions so the model can detect suspicious sequences, such as reading secrets before a network upload.
- Track dangerous recall, false positive rate, precision, and confusion matrix by risk category.
- Compare model behavior against the rules baseline.
- Document failure cases that need more data or policy handling.

**Deliverable:** First working PyTorch model with measurable performance and clear failure modes.

### Week 5: Model Hardening and ONNX Serving

**Goal:** Prepare the model for production-style inference inside the guardrail service.

**Tasks:**

- Improve weak categories from Week 4, especially:
  - context-dependent destructive commands,
  - sequence-dependent suspicious behavior,
  - legitimate high-risk operations,
  - obfuscated exfiltration,
  - cloud deletion,
  - external communication mistakes.
- Calibrate thresholds using validation data.
- Export the trained model to ONNX.
- Build an inference wrapper around ONNX Runtime.
- Measure CPU p50/p99 inference latency.
- Add regression examples for previously missed cases.

**Deliverable:** ONNX model artifact and inference wrapper ready for service integration.

## Phase 3: FastAPI Guardrail Service

### Week 6: Evaluation API

**Goal:** Expose the decision engine as a structured API.

**Tasks:**

- Build a FastAPI service with `POST /evaluate`.
- Accept request fields:
  - `context`
  - `command`
  - `recent_actions`
  - `environment`
  - `session_id`
  - `agent_id`
  - `user_id`
  - optional confirmation token.
- Return structured verdicts with:
  - request ID,
  - risk score,
  - risk tier,
  - reason codes,
  - agent-facing message,
  - suggested safer alternatives.
- Add `GET /health`.
- Add API tests for malformed requests, allowed commands, blocked commands, and confirmation-required commands.

**Deliverable:** Local API service that can evaluate commands without executing them.

### Week 7: Risk Tiers, Confirmation, and Policy Files

**Goal:** Make the API behave like a real enterprise policy engine, not a binary classifier.

**Tasks:**

- Implement risk tiers:
  - `allow`,
  - `warn`,
  - `confirm_required`,
  - `block`.
- Add policy-file support for local development, such as YAML or JSON policy profiles.
- Implement deterministic routing so rules and policy can return immediately before ONNX inference.
- Track whether each decision was made by `rules`, `policy`, `model`, or `combined` routing for auditability and latency analysis.
- Implement exact-request confirmation tokens for high-risk actions.
- Ensure confirmation cannot be reused for a different command/context/environment.
- Add tests for environment-specific policy behavior.

**Deliverable:** Decision engine that supports local policy profiles and confirmation-safe high-risk execution.

## Phase 4: Local Execution Sandbox

### Week 8: Dockerized Service and Executor Image

**Goal:** Package Sentinel and define the local proof-of-concept execution boundary.

**Tasks:**

- Write a Dockerfile for the FastAPI guardrail service.
- Build a separate minimal executor image for approved commands.
- Run both as non-root users.
- Add local development configuration through Docker Compose.
- Keep serving image lightweight by using ONNX Runtime rather than full PyTorch.
- Explicitly document that Docker reduces blast radius for the local proof but
  is not treated as a production-grade security boundary.

**Deliverable:** Sentinel service and executor images build locally and run from Docker Compose.

### Week 9: Sandboxed Command Execution

**Goal:** Add controlled local execution for approved commands while preserving clear security limitations.

**Tasks:**

- Implement `POST /execute` or an execution mode that evaluates first, then runs only if allowed.
- Run approved commands in the Docker executor with:
  - no network by default,
  - CPU and memory limits,
  - strict timeout,
  - restricted mounted workspace,
  - no Docker socket mount,
  - cleanup after each run.
- Capture stdout, stderr, exit code, timeout status, and execution duration.
- Ensure blocked and confirmation-required commands never execute.
- Add executor tests for timeout, blocked host access, and restricted mounts.
- Document the later migration path from local Docker to stronger managed
  isolation.

**Deliverable:** End-to-end local enforcement: evaluate, decide, execute in sandbox if allowed, and return structured output.

## Phase 5: Task Authorization and Audit Evidence

### Week 10: Trustworthy Task-Authority Foundation

**Goal:** Replace the legacy context/command trust model with a tested, server-owned task-authority boundary.

**Entry gate:** Before broad implementation, prove one Cursor action path can be mandatorily intercepted, distinguish a direct user event from agent/tool content, reject a replayed trusted event, and publish a supported-action coverage matrix. If user provenance cannot be proven, authority changes must use the protected local interface. If an action path can bypass Sentinel, that path remains advisory.

**Gate result:** Cursor does not provide authenticated direct-user provenance in `beforeSubmitPrompt`, and `beforeShellExecution` cannot redirect the original host command into Sentinel's Docker executor. The Cursor adapter is therefore explicitly advisory/unsupported by action family, prompt-based authority updates are disabled, and Week 10 proves the mandatory boundary only through the Sentinel-owned contract API → Docker release path. Promoting Cursor requires the protected local authority interface plus a host-owned proxy or another execution path Sentinel actually controls.

**Outcomes:**

- Close release-blocking rule, approval, API resource-limit, executor, model-input, and data-split safety debt.
- Implement persistent `ActionContract` lifecycle, one active task per session, canonical multi-target matching, server-owned history, and atomic exact-action approval.
- Implement SQLite audit evidence for every authority, decision, approval, and execution transition.
- Keep template save/reuse out of Week 10; define only the audit event shapes
  needed by the protected Week 11 core flow.
- Rebuild evaluation around human-reviewed contract compliance and compare ML with the rules-only baseline.

**Done when:** the insecure agent-callable approval path is disabled; persistent contract lifecycle/store/API/matcher tests pass; one Sentinel-owned shell path completes active contract → canonical action → decision → Docker release → ordered audit end to end; the Cursor capability matrix makes its advisory status explicit; exact approval is tested only through an isolated test harness until Week 11 provides the protected human interface; bypass/replay/concurrency/redaction tests pass; and a human-reviewed golden evaluation either justifies optional ML or records a rules-only release decision.

**Current result:** the Week 10 foundation is complete and merged into `main`.

- Authority: immutable contract versions, one active task per session, trusted-event replay rejection, authority epochs, audited transitions, and server-side active-contract resolution are implemented. Runtime mutation remains internal/test-only until Week 11 provides protected provenance and controls.
- Decisions: raw shell input is canonicalized on the server into complete targets/effects, checked against the active contract, and evaluated with server-owned recent history. Caller identity and caller history do not grant authority.
- Replay and execution: contract-aware `/execute` requires an `attempt_id`, durable admission evidence, matching active authority, a safe read-only action, and exact approval when required. Each attempt is at-most-once; completed/failed responses are replayed from storage, while conflicting, in-flight, or unknown attempts never auto-run.
- Persistence and audit: `SENTINEL_STATE_DB` supplies SQLite contract, session, attempt, and audit state. The default in-memory audit store cannot authorize execution.
- Executor: Week 10 supports read-only workspace execution only. Write/delete actions are rejected before admission. The Compose API has no Docker socket and is diagnostic; the host-run API owns executor-container launch.
- Integrations: Cursor and legacy OpenClaw remain advisory. One live read-only Slack run proved the basic internal public-channel metadata path; Slack Connect, guests, private channels, scheduled sending, Google Workspace, and provider enforcement remain unproven.
- Data: the reviewed 60-row core, 30-row communications, and frozen combined corpus remain committed. Candidate JSONL and generated review Markdown were removed and are regenerated on demand. The combined SHA-256 remains `8488862b2da4744bf08f33ee413982f290181feea8c81e7d42f8f1034c62feec`.
- Evaluation: known-regression v5 reports 90 rows, 98.8889% expected accuracy, 100% contract-overstep recall, 100% insufficient-contract detection, 5.8824% compliant false interruption, zero critical misses, and eight missing reason expectations. It is explicitly non-promoting; v4 and the original baseline manifests remain historical evidence.
- Verification: a clean Python 3.11 container run passes all 477 tests. The Docker smoke also passes the trusted activation → durable admission → read-only non-root execution → ordered audit path, destructive blocking, API socket isolation, and legacy no-authority gating.
- ML: serving is disabled. Without an independent reviewed calibration set, calibration, export, and serving fail closed.

**Week 10 local summary:** implementation, review, verification, clean commits,
and the local merge are complete. The durable handover is
[Week 10 Handover](./Week%2010%20Handover.md).

**ML promotion gate (not a Week 10 commit blocker):** before any model can be promoted, create a fresh preregistered, group-disjoint blind set; prove training, validation, calibration, and blind-evaluation independence; review and content-bind the calibration data; and pass the documented metrics without inspecting failures first. If those conditions are not met, Sentinel ships rules-only and keeps model serving disabled.

**Domain expansion gate:** do not add every domain to one model or dataset at once. First complete the live communications matrix and confirm that official provider metadata can resolve the policy facts without unsafe guesses. Then evaluate customer-support/CRM, code/deployment, financial operations, and cloud/identity in that order. Each domain must independently pass the same entry gate: authoritative read-only metadata spike, documented unknowns and kill condition, small human-reviewed evaluation pack, and rules-only baseline before any ML training examples are added.

Week 10's contract references, server-owned history, canonical actions, and trusted prompt envelopes supersede the earlier Week 2/4/6 context-command schemas.

### Week 11: Protected Local Control-Center Core

**Goal:** Prove one polished, protected local control-center flow for a developer supervising a coding agent in one repository.

The reviewed implementation checklist is
[Week 11 Plan](./Week%2011%20Plan.md). That plan supersedes the broader
aspirational scope that previously appeared here.

**Implementation order:**

1. Prove one-use browser pairing, fixed workspace binding, raw-prompt
   non-persistence, and one truthful confirmation/retry action.
2. Add protected control routes around the existing authority, approval, and
   audit services while leaving agent routes unchanged.
3. Add server-owned denial, approval, automatic retry, and atomic consumption.
4. Build the Next.js shell with Overview, Tasks, Approvals, and Audit.
5. Complete one real Playwright path through FastAPI and Docker.
6. Run full security, correctness, accessibility, and release verification.

**Deliverable:** From the local web app, a paired human can create and edit a
task contract, explicitly activate it, inspect workspace authority, deny or
approve one exact action, observe one server-owned retry, and inspect the
ordered audit evidence. The UI must clearly state that no mandatory external
agent is connected.

**Current result:** Implemented on `feature/week-11-control-center`. The real
browser path uses FastAPI, SQLite, and Docker without mocked Sentinel APIs and
proves denial with zero execution, one approved confined write, replay safety,
and ordered audit evidence. The Python suite passes 535 tests in a Python 3.11
container; 14 Playwright tests, frontend type/lint/generated-type/build checks,
Docker smoke paths, and desktop semantic/keyboard/contrast checks pass. The
branch still requires explicit commits and merge review.

**Restart-recovery result:** Resolved on the Week 11 branch. Sentinel now
persists quarantine before protected lifecycle mutations, suspends matching
uncertain authority during startup recovery, and keeps authority closed when
reconciliation or its audit cannot be verified.

**Deferred from Week 11:** templates, custom rules, broad task presets,
multi-workspace management, GitHub OAuth, marketing, ML, production provider
enforcement, and mandatory external-agent integration.

### Planning discipline for Weeks 12-17

- Each active week plan must name one load-bearing assumption, validate it
  before broad implementation, and stop when its kill condition fires.
- Preregister workflow packs, denominators, and pass/fail thresholds before
  inspecting final results.
- Treat authority bypass, cross-session access, approval replay, changed-action
  reuse, protected credential exposure, and effects during Sentinel failure as
  zero-tolerance failures.
- Keep optional UI, provider, model, and marketing work behind the week's
  security and usefulness gate.
- When evidence is inconclusive, retain the narrower verified behavior and
  document the unknown instead of expanding the claim.

## Phase 6: Automatic Supervision and the Local Agent Product

### Week 12: First Mandatory MCP Tool Path

**Goal:** Prove that one disposable local MCP tool family cannot act around
Sentinel in the tested Cursor configuration.

The reviewed implementation checklist is
[Week 12 Plan](./Week%2012%20Plan.md). It becomes implementation authority only
after explicit approval.

**Entry gate:** The Week 11 authority restart-recovery blocker is closed and
must remain covered by regression. Next, run a live Cursor/MCP spike before
adding dependencies or shared integration models.

**Phase 0 cutoff:** Complete the mediation evidence and dependency decision by
the end of the second working day. If either remains unresolved, Week 12 ends
as a documented spike and later milestones shift; do not compress the
remaining build into the week.

**Planned outcome:**

- Measure actual Cursor prompt, MCP, shell, file, browser, and subagent
  behavior rather than relying on documentation.
- Keep Cursor prompt events advisory and all task activation in the existing
  protected browser flow.
- Add an immutable startup guardrail ceiling for one disposable tool family.
- Authenticate one MCP adapter session without treating it as task authority.
- Mediate a local issue fixture with repeated reads and one
  confirm-required note write.
- Keep fixture state, adapter material, and MCP configuration outside guarded
  workspace mounts and normal agent-readable paths.
- Require one real Cursor MCP run for release evidence; use a faithful harness
  only for repeatable CI regression.
- Prove block and shutdown with zero effect, exact approval with one effect,
  replay and changed-payload rejection, and an honest capability matrix.

**Kill condition:** If the fixture effect can bypass Sentinel, if the guarded
agent can reach its state or adapter material, if Sentinel failure permits the
effect, or if Cursor cannot complete the real MCP run, end Week 12 as a
documented spike.

**Deliverable:** One honestly bounded mandatory local MCP fixture path and
measured Cursor capability matrix. Automatic task preparation and UI redesign
remain Week 13 work.

**Result (September 9, 2026):** Delivered. A real Cursor run with the sandbox
on completed three mediated reads, one denied write with zero effect, one
approved write with exactly one effect, and rejection of replay and of a
changed payload under the approved attempt; the fixture held exactly one note
after Sentinel was stopped. The startup ceiling, hashed adapter session,
durable fixture operation states, and truthful per-family coverage shipped as
planned. Two live-run findings were fixed the same day: fixture tasks can no
longer require a dry run they cannot perform, and the Approvals page no longer
misreports a successful MCP write as a shell failure. The adapter capability is
readable by a same-user agent by design and grants no authority; Linux/Windows
sandbox behavior and subagent hook behavior remain unverified. Details in
[Week 12 Handover](./Week%2012%20Handover.md).

### Week 13: Automatic Task Preparation

**Goal:** Remove manual contract entry from the Week 12 MCP workflow without
pretending an advisory Cursor prompt is trusted authority.

The implementation checklist is [Week 13 Plan](./Week%2013%20Plan.md).

**Riskiest assumption:** The agent can hand Sentinel a complete, structured
task proposal through a channel Sentinel already controls, and one compact
protected confirmation can show exactly what will be granted.

**Reconciliation (September 9, 2026):** Earlier drafts of this section
described the intake as a "prompt grammar" parsed from Cursor text. The plan
and the implementation use a structured MCP tool instead
(`sentinel_task_propose(operation, issue_ids, minutes)`), because it reuses
every Week 12 control (adapter bearer, startup ceiling, canonicalization,
audit, fail-closed hooks) and needs no parser. The hook-based prompt channel
is not built; it stays a fallback only if live trials show the agent will not
propose on its own.

**Planned outcome:**

- Accept one structured proposal from the agent as advisory input.
- Prepare a complete non-authorizing task draft from explicit validated facts.
- Reject missing or ambiguous facts rather than guessing or starting a
  clarification system this week.
- Show every authority-bearing field in one compact browser confirmation with
  no manual field entry for the supported proposal.
- Keep the previous task active while a replacement remains a draft; activating
  the replacement suspends the previous task atomically.
- Let the confirmed task cover at least three matching MCP reads without
  repeated task review.
- Measure proposal success, compact-review time, manual edits, repeated reviews,
  false interruptions, and raw-text retention.

**Kill condition:** If the supported proposal still requires manual field
entry, if the draft can change explicit facts between proposal and activation,
if an unconfirmed proposal changes authority, or if the agent will not use the
tool without hand-holding, keep the Week 11 manual flow. Also retain the old
flow as default if preregistered review-time or manual-edit thresholds show no
useful friction reduction.

**Deliverable:** One structured proposal becomes a complete draft
automatically, one protected compact action activates it, and multiple
matching tool calls use that task without repeated review.

**Status (September 9, 2026):** Built and verified in-process; the live Cursor
trials that decide the kill condition have not been run yet. See
[Week 13 Handover](./Week%2013%20Handover.md) for what is proven by tests,
what is still unverified, and how to run the measurement.

### Before Week 14: UI Foundation Pass (bounded, ~1.5 days)

**Why now (decided September 10, 2026):** the control center was built
without applying the project's UI standard (monochrome, hairline borders,
inverted CTAs, one label per control, grouped settings). Weeks 14–16 add
policy tiers, an OS-level fallback, provider connections, and sessions; if
those land on the current pattern they will be rebuilt in Week 16. This pass
fixes the bones only.

**Scope:**

- Replace the current tokens with the standard's light "blueprint" set and
  rebuild four primitives every page consumes: page header, section header,
  setting row (one label, right-aligned value, at most one supporting line),
  card.
- Write the Settings information architecture before building it, grouped
  like a production settings surface: Workspace, Agents (connections,
  coverage, MCP), Policy (approval preference, ceiling, guardrails
  placeholder), Activity & data. Later weeks add to these groups rather than
  appending rows.
- Re-skin Overview and Settings using the primitives. Tasks, Approvals, and
  Activity take the new tokens but keep their layouts; Weeks 14 and 16
  restructure them.
- Update mocked Playwright specs whose text assertions change; screenshot
  before/after for the handover.

**Explicitly out:** new features, dark mode, the command-center layout,
anything session-related, marketing surfaces.

**Done when:** Overview and Settings pass the standard's "would Linear or
Plain ship this" check in a screenshot review, every page uses the shared
primitives, and the full mocked Playwright suite is green.

### Week 14: Transition Drafts and Persistent Guardrails

**Goal:** Handle changing work with compact protected review and a durable
local policy ceiling.

**Riskiest assumption:** Sentinel can classify task changes conservatively
enough to reduce repeated setup while keeping every Cursor-originated
authority change behind browser confirmation.

**Planned outcome:**

- Evolve Week 12's immutable startup ceiling into protected, versioned local
  guardrails.
- Intersect every draft, transition, approval, and execution with the
  server-owned ceiling.
- Allow runtime changes only to narrow the ceiling. Widening remains a
  protected restart procedure with a new content binding and never expands an
  active task; Week 14 adds no widening UI or API.
- Prepare transition drafts only for narrow, replace, and sensitive expansion.
  Treat continue and ordinary extension as fresh replacement drafts this week.
- Require protected browser confirmation for every Cursor-originated authority
  change until an authenticated host-provenance gate passes.
- Keep the previous task active while replacement or sensitive expansion is
  pending or rejected.
- Measure classification errors, review time, stale-authority reuse, and
  unnecessary transition prompts on a preregistered workflow pack.

**Kill condition:** If a transition draft can retain stale targets, cross the
guardrail ceiling, or alter authority before confirmation, keep every new
prompt as a fresh replacement draft. Also retain the previous flow if
preregistered classification-error or unnecessary-prompt thresholds fail.

**Deliverable:** Persistent local guardrails and conservative task-change
drafts that reduce reconstruction work without granting authority from Cursor
events, history, or agent suggestions.

**Friction candidates carried from Week 13 (user verdict, September 10, 2026):**
the one-click proposal loop worked end to end in a real Cursor chat, but the
user judged it impractical next to Cursor's inline approve box and found
per-write approval after a reviewed contract excessive. These are candidates
for Week 14 planning, not commitments; each needs its own threat-model pass.

1. **Tiered write policy.** Activation grants scope; the risk tier decides
   review. Reversible in-scope writes (a note on an issue) run and are
   audited; confirmation is reserved for irreversible, bulk, production, or
   out-of-pattern effects; blocks stay blocks. Optionally a per-card *write
   budget* ("allow up to N notes without asking") so the consent happens at
   activation. Kill condition: any path where a write escapes both the
   contract's exact scope and a confirm/block tier.
2. **OS-level confirmation surface.** A macOS notification with Activate /
   Approve actions (deep-linking to the browser card as fallback) or a small
   always-on-top window, so confirmation happens where the user already is
   while staying outside the agent's reach. Prioritized over further browser
   polish. Kill condition: the surface can be driven or spoofed by a same-user
   agent process, or it needs a dependency the project would not otherwise
   take.
3. **Standing read permission at startup.** The ceiling auto-activates a
   read-only task over the fixture scope so reads never raise a card; only
   writes and scope changes do. Kill condition: it changes what "no active
   task" means anywhere in the authority model without a fresh review of the
   stale-view and supersession rules.

The Week 13 measurement targets (false interruptions, repeated reviews) stay
the yardstick: if these do not bring routine work to one confirmation per job,
the friction problem is not solved.

## Phase 7: Real Provider Mediation and Session Isolation

### Week 15: First Sentinel-Mediated Provider Tool

**Goal:** Retain the local fixture as a regression baseline and conditionally
add one narrow disposable provider action whose credential and execution path
Sentinel controls.

**Preferred proof:** GitHub issue triage in a disposable repository: bounded
repository reads followed by one exact, approved issue or comment write. The
provider choice may change if the initial API and credential-isolation spike
fails.

**Riskiest assumption:** A dedicated provider identity can be isolated from
the guarded agent while the live API returns stable account, permission,
repository, resource, and payload facts needed before execution.

**Entry gate:** Before implementation, prove the guarded agent has no ambient
GitHub credential, browser session, inherited environment secret, or
unrestricted equivalent network path for the dedicated provider identity.
Then verify the actual provider responses contain the policy facts Sentinel
needs. If credentials are required for this spike, the user supplies only a
disposable, narrowly scoped identity outside Git.

**Planned outcome:**

- Validate the actual provider response and narrow credential scopes before
  implementing the adapter.
- Keep the credential in a separate Sentinel-controlled service identity or
  equivalent boundary unexposed through the declared and tested guarded
  capabilities.
- Canonicalize provider account, repository, operation, every target, payload,
  audience/effect, and returned resource identity.
- Add a durable provider-operation lifecycle. Send at most once while the
  outcome is known; after an uncertain write, record `unknown`, never retry
  automatically, and require reconciliation.
- Prove allowed reads, exact write approval, denial, changed-payload rejection,
  known-outcome replay handling, revocation, and provider failure.
- Keep all untested provider operations unavailable.

**Kill condition:** If the agent can discover or reuse the credential, invoke
an equivalent privileged path, or the provider cannot expose required
pre-action facts, stop the integration and retain the local fixture.

**Deliverable:** If the entry gate passes, one honestly scoped live provider
workflow mediated through Sentinel, with the credential unexposed through the
declared and tested guarded capabilities and no claim of general GitHub or
provider enforcement. Arbitrary same-user operating-system compromise remains
out of scope. If the gate fails, deliver a documented provider spike and retain
the supported local fixture.

### Week 16: Isolated Local Sessions and Agent Command Center

**Goal:** Prove session isolation first, then reshape the web app around
supervising active agents rather than constructing contracts.

**Riskiest assumption:** Exactly two independently authenticated local sessions
using the already measured adapter can coexist without sharing task authority,
history, approvals, guardrails, or audit scope.

**Planned outcome:**

- First prove backend isolation across separate adapter capability, authority,
  approval, audit, attempt/idempotency, policy, and fixture-target namespaces.
- Derive the supervision session from authenticated adapter credentials rather
  than accepting a caller-selected session as authority.
- Support exactly two local sessions through the measured adapter; do not claim
  multiple agent kinds.
- Prove cross-session rejection for task references, prompt events, approval,
  retries, history, and audit queries.
- Only after the isolation gate passes, add a session list/switcher with scoped
  current work, approvals, recent decisions, and coverage status.
- Add disconnect, revoke, stale-session, and unavailable states.
- Keep activity explicitly limited to observed or mediated actions.

**Kill condition:** If one session can select or reuse another session's task,
history, approval, or adapter proof, retain single-session mode and do not
build comparison UI.

**Deliverable:** Two isolated backend sessions and a minimal scoped
list/switcher using one measured adapter, with no claim that a second host or
agent kind is supported. The broader command-center redesign and contract
editor move remain post-validation work.

## Phase 8: Validation and Release

### Week 17: Validation, Hardening, and Release Decision

**Goal:** Freeze new features, test the complete verified local path, and decide
whether the result is ready to label a release candidate.

**Entry gate:** Before running final workflows, preregister the exact test
environment, scenario pack, denominators, zero-tolerance security failures,
maximum acceptable false-interruption and repeated-review rates, and minimum
task-completion/usability result. Do not change thresholds after inspecting
failures.

**Planned outcome:**

- Run the Sentinel-owned Docker path and measured MCP path through task
  preparation, guardrails, isolated sessions, exact approval, execution, and
  audit. Include the provider path only if Week 15 passed its entry and safety
  gates.
- Keep Cursor-native shell, file, browser, and subagent actions explicitly
  advisory.
- Measure enforcement coverage, observed bypass rate, task-overstep recall,
  compliant false interruptions, repeated reviews, review time, decision
  latency, known and unknown provider outcomes, duplicate effects, and audit
  success.
- Fix release-blocking correctness, security, accessibility, installation, and
  recovery issues; defer new features.
- Package the local application and write clear operational limits.
- Complete independent correctness and security reviews and focused
  accessibility and usability checks.
- Make an evidence-based release-candidate or research-prototype decision.

**Kill condition:** If a tested protected path can bypass Sentinel, session
isolation fails, routine supported work still requires contract construction,
or preregistered safety/usability gates fail, do not call the result a release
candidate. A fixture-only result remains a research prototype;
release-candidate status requires at least one useful non-synthetic mediated
workflow.

**Deliverable:** A hardened, measured local package and explicit release
decision. Public marketing publication begins only after this gate passes.

## Local Product Non-Goals Through Week 17

These are intentionally excluded from the local product proof:

- Hosted multi-tenant enterprise control plane.
- Multi-tenant user management.
- Hosted SaaS billing.
- Organization-wide RBAC.
- Production container orchestration.
- Datadog/Splunk streaming integrations.
- Slack/email approval queues.
- Rich organization-wide policy authoring.
- Full managed deployment for customer workloads.
- Production-ready real-agent framework adapters.
- Production provider credentials or customer accounts.
- A claim that Sentinel observes or controls unmediated agent behavior.
- Public marketing before the Week 17 release gate.
- LLM task suggestions before a separate shadow evaluation.
- A general-purpose prompt-writing assistant unrelated to high-impact action safety.
- Automatic permission expansion based on learned behavior; any future
  user-created template must still produce a fresh reviewed contract.
- Enforcement claims for hosts or tools that do not provide complete interception.

## Post-Gate Local Follow-Up

If Week 17 passes its preregistered release gates:

- Build and publish the separate public marketing site using sanitized
  screenshots, measured claims, clear installation guidance, and no protected
  local data.
- Run one preregistered shadow evaluation of draft-only LLM task suggestions
  against the deterministic baseline.
- Require explicit opt-in before protected local history is sent to any remote
  model; redact unnecessary content and document retention.
- Measure unsafe suggestion rate, acceptance, edits, clarification reduction,
  latency, and cost.
- Let the evaluation enable draft assistance only. Suggestions never activate
  authority, weaken rules, or approve actions.
- Keep command-risk model training, calibration, and blind promotion as a
  separate process.

## Part 2: Hosted/Hybrid Production Scaling

After Week 17, the roadmap turns the validated local product into a
hosted/hybrid platform while preserving enforcement close to the agent.

### Stage 1: Hosted Control Plane and Multi-Tenant Web App

**Goal:** Evolve the local web control center into an authenticated production control plane for teams.

Planned capabilities:

- Migrate the web app from single-user local state to organizations, workspaces, authenticated users, and isolated tenant data.
- Visualize audit logs by verdict, risk tier, environment, agent ID, and time range using a managed database such as Postgres.
- Provide one centralized activity view for mediated actions, showing which
  protected data each agent accesses through Sentinel, which tools and external
  services it invokes, and which task contract authorized each action.
- Add agent-specific guardrails for resource access, tool scopes, environments,
  rate limits, and escalation rules, with monitoring that makes observed bypass
  attempts, explicit enforcement-coverage gaps, repeated denials, and suspicious
  action sequences visible.
- Show blocked-command timelines and reason-code breakdowns.
- Display model score distributions and policy-trigger trends.
- Manage API keys for agents, CI systems, and team integrations.
- Create and review human-in-the-loop approval requests.
- Let reviewers approve or deny exact high-risk actions.
- Show execution metadata for allowed commands without exposing sensitive outputs by default.
- Keep customer-hosted or regional enforcement gateways separate from the hosted management UI so sensitive code and credentials may remain local.
- Keep the centralized control plane administrative: policy, identity, and
  audit indexing may be centralized, but raw protected data and enforcement
  stay local, regional, or customer-hosted by default.

### Stage 2: Enterprise Identity, Tenancy, and Policy Management

**Goal:** Support real organizations rather than single-developer local usage.

Planned capabilities:

- Organizations and workspaces.
- User roles such as admin, security reviewer, developer, and read-only auditor.
- Per-environment policies for sandbox, dev, staging, and production.
- Signed approval tokens tied to exact requests.
- API key rotation and scoped service tokens.
- Keep Slack, Google, GitHub, and other broad provider credentials behind a Sentinel-controlled gateway so agents receive task-scoped authority rather than reusable OAuth tokens.
- Issue short-lived agent grants bound to task, operation, resource, environment, identity, version, and expiry.
- Revoke or supersede active task grants without disconnecting the underlying provider account.
- Policy versioning and rollback.
- Policy simulation before rollout.

### Stage 3: Observability and SIEM Integrations

**Goal:** Fit into enterprise security operations workflows.

Planned integrations:

- Stream audit events to Datadog.
- Stream audit events to Splunk.
- Emit OpenTelemetry traces and metrics.
- Support CloudWatch log export for AWS-native teams.
- Add webhook sinks for internal security automation.
- Add alert rules for repeated blocks, exfiltration attempts, and suspicious agent loops.
- Export compatible audit and trace data to reliability platforms such as `uselemma.ai`; Sentinel should complement production observability rather than rebuild it.

### Stage 4: Managed Execution Infrastructure

**Goal:** Upgrade from local Docker execution to managed, scalable, policy-controlled execution with stronger security boundaries.

Potential options:

- AWS ECS/Fargate task-per-execution model for stronger managed isolation than local Docker.
- EKS or Kubernetes Jobs for high-volume ephemeral execution with admission control, Pod Security Standards, and namespace-level isolation.
- Firecracker-style microVM isolation for stronger tenant boundaries and reduced container-escape blast radius.
- Per-tenant network policies and egress allowlists.
- Managed ephemeral workspaces with encrypted storage.
- Cluster-level scheduling and quota controls for thousands of short-lived agent sandboxes.
- Runtime security monitoring for executor containers or microVMs.
- Centralized executor fleet metrics and failure reporting.

This stage should preserve the local Docker executor for development while making clear that enterprise workloads require stronger isolation and orchestration than `docker run` on a shared host.

### Stage 5: Production Agent and Workflow Expansion

**Goal:** Expand the measured local adapter and provider pattern into supported
production agent and automation workflows.

Potential integrations:

- Real-agent validation harness that replays representative tasks through Sentinel before building full adapters.
- An isolated OpenClaw demonstration using mock or throwaway accounts, with Sentinel-managed tools as the only path to protected actions.
- OpenClaw adapter as the first production candidate only if its command/tool execution layer can be intercepted without bypass.
- MCP proxy or middleware.
- LangChain, AutoGen, and OpenClaw adapters.
- CI/CD guardrail mode for GitHub Actions or other build systems.
- Cloud-operation guardrails for AWS CLI, Terraform, and Kubernetes commands.
- External communication guardrails for mass email, Slack, and ticketing workflows.

### Stage 6: Production Model and Policy Intelligence

**Goal:** Govern and improve optional intelligence using isolated production
feedback while preserving trust and tenant boundaries.

Planned capabilities:

- Reviewed-audit feedback loop for retraining.
- Per-organization policy recommendations.
- Risk scoring by command category and historical behavior.
- Drift monitoring for model performance.
- Shadow-mode evaluation before enforcing new model versions.
- Model/version provenance in every audit event.
- Detect repeated accepted task patterns from trusted structured history and suggest candidate templates in shadow mode.
- Suggest missing task-contract fields and safer boundaries with an LLM,
  including field-level provenance and confidence. Suggestions must remain
  editable draft input and require explicit human review and activation; they
  may never grant authority or weaken deterministic policy.
- Learn convenience preferences such as usual targets, environments, dry-run steps, and draft-before-send behavior without weakening hard policy.
- Require explicit save/edit/reject for every suggested template; learned patterns never activate authority.
- Let users inspect, reset, export, and delete preference data.

## Long-Term Product Direction

Sentinel should evolve from a local agent command center and enforcement
gateway into an enterprise authorization platform for AI-agent operations:

```text
Local command center + automatic supervision + measured enforcement
        |
        v
Hosted team control plane + managed tenant-aware storage
        |
        v
Regional/customer-hosted enforcement gateways + approval queues
        |
        v
Protected provider credentials + stronger managed execution
        |
        v
Full AI-agent security control plane
```

Weeks 12-17 should remain disciplined: prove that automatic task preparation,
persistent guardrails, agent management, and narrow mandatory mediation create
a useful local product. Multi-tenant hosting, production credential brokering,
production agent integrations, and managed execution come only after those
properties work and their interruption and bypass rates are measured.