# Project Sentinel: Roadmap

This document is the source of truth for sequencing, milestones, dependencies, and outcomes. Stable product/security behavior belongs in `docs/Product Architecture.md`; implementation-level checklists belong only in the active week plan.

Project Sentinel is a local-first supervisor for AI coding agents. People
keep working where their agents already run while Sentinel infers an advisory
boundary from the prompt, tells the agent that boundary, watches every action
through the host's hooks, blocks or confirms a deterministic floor of
dangerous actions, surfaces stuck and off-track agents, and records every
verdict before the action runs. The web app is the monitor and flight
recorder. The direction decision of October 9, 2026 and its evidence are in
[Product Direction](./Product%20Direction.md); it governs Weeks 15-18 below.

This roadmap separates the work into two phases:

- **Part 1: Local Product Proof (Weeks 1-18)** builds the guardrail engine,
  persistent task authority, local execution and audit, protected human review,
  one mandatory MCP fixture path, low-friction task preparation (Weeks 1-14),
  then moves the proven seam onto Claude Code's hooks with a deterministic
  floor, an inferred boundary, a stuck detector, and a published evaluation
  (Weeks 15-18).
- **Part 2: Hosted/Hybrid Expansion** adds organizations, enterprise identity,
  production credential brokering, regional or customer-hosted enforcement,
  observability integrations, and managed execution after the local product is
  useful and enforceable.

## Product Thesis

AI agents are becoming powerful enough to run shell commands, modify infrastructure, send external communications, and trigger production workflows. Every vendor now ships a permission prompt and a phone relay for its own agent; none offers an independent second opinion that works across agents, can actually stop an action, surfaces stuck and off-track behaviour, and keeps a record the agent did not write.

Sentinel's wedge is that independent second opinion for the individual
developer. The local product should prove that quiet supervision and
mandatory enforcement work together:

- hear the prompt through the host's hook and infer an advisory boundary from
  the working directory, its repository, and the launch environment, narrowing
  on prompt facts and asking one question before widening;
- tell the agent the boundary in one line of context, the single most
  effective intervention measured in the literature;
- block or confirm a deterministic floor of dangerous-by-facts actions on hook
  facts alone, before the action runs;
- let everything else run, with a stuck detector and an off-track detector
  that warn or confirm within a per-boundary message budget and never block;
- never treat the inferred boundary, agent suggestions, or content read from
  tools, files, or messages as authority;
- state enforcement coverage per host and per surface and claim nothing more;
- reserve any model for gray areas after an evaluation set exists, able to
  escalate but never to downgrade a floor decision;
- run commands Sentinel owns in a restricted Docker sandbox;
- write every verdict to a tamper-evident local SQLite store before the action;
- publish dangerous recall, false-flag rate, messages per hour, latency, and
  audit integrity against real incidents and benign twins;
- expose the system through FastAPI, per-host hook adapters, and a protected
  local web app for monitoring, approvals, and audit review;
- defer public marketing until the measured local workflow is ready to explain
  honestly.

## Core Product Principles

- **Context matters:** decisions depend on `context`, `command`, and `environment`, not command text alone.
- **Prompt text is not authorization:** a boundary inferred from the prompt is advisory; it may warn or confirm, never allow or block. Inference may only narrow; widening needs the person's answer.
- **Supervision should be quiet:** people should never fill out a boundary. Sentinel infers it, tells the agent, and speaks only at the edges, within a per-boundary message budget. If Sentinel is louder than the host's own prompts, it has failed.
- **The floor is deterministic and uses hook facts alone:** destructive operations whose target escapes the working directory, credential reads, exfiltration, production deletion, defense evasion, and writes to hook or Sentinel configuration block or confirm before the action runs, regardless of what the prompt said.
- **Only trusted authority events can expand authority:** the person answering a question or approving an exact action may grant permission. Agent suggestions, inferred boundaries, and content read from tools, webpages, messages, or files cannot.
- **Exact-action approval is exceptional:** one-time approval is reserved for the floor and must not turn every ordinary command into a permission prompt.
- **Learn convenience, never permission:** templates and personalization may suggest safer defaults, but only a fresh trusted answer or protected approval can grant authority.
- **Temporal context matters:** decisions should consider the recent action window for the agent session, not only the current command; the stuck detector is built on it.
- **Malicious is different from destructive:** authorized destructive work may be allowed or require confirmation; malicious or agent-gone-haywire actions should block.
- **Deterministic policy comes first:** the floor decides before any detector; detectors decide before any model.
- **A model handles gray areas conservatively, later:** no model runs in Weeks 15-18. When one exists it may escalate, never downgrade a floor decision, and never sends prompt content off the machine.
- **Coverage is per host and per surface:** mandatory only where the hook can deny and the configuration is locked against the agent; advisory where it can only observe or the agent can edit the hook; unsupported where there is no hook.
- **MCP alone is not enforcement:** an MCP tool is advisory unless the host or a proxy guarantees complete mediation of protected actions.
- **Docker is not a production security boundary:** local Docker is acceptable
  for the local product proof; enterprise execution requires stronger
  isolation such as managed orchestration, microVMs, or hardened Kubernetes
  controls.
- **Audit everything, before the action:** every verdict is written durably before the action runs, hash-chained so tampering is evident, and the hook fails closed if the write fails. Prompt text is not stored; the boundary and the prompt's hash are.
- **Local-first security:** teams should be able to test policies and commands locally before using hosted infrastructure.
- **Web app is the monitor and flight recorder:** active agents, boundaries, decisions with reasons, detector signals, approvals, and audit belong there. It is never a form before work.
- **Integrate where work happens:** Claude Code, Cursor, Codex, and MCP provide the hooks. Verdicts travel through existing notification channels; exceptional review routes to the protected web app.
- **Scale without replacing the core:** a future hosted control plane may manage organizations, identity, policy, and audit indexing while enforcement remains local, regional, or customer-hosted.

## Part 1: Local Product Proof (Weeks 1-18)

### Local Product Definition of Done

The local product proof is complete when Sentinel can:

- Accept command-evaluation requests through a FastAPI service.
- Hear a prompt through Claude Code's hooks, infer an advisory boundary that
  narrows from the working directory, repository, and launch environment, and
  ask one question before any widening.
- Tell the agent that boundary as one line of context it then sees.
- Block or confirm a deterministic floor of dangerous-by-facts actions through
  the hook, on hook facts alone, before the action runs, under managed
  settings the agent cannot edit.
- Classify real shell commands (compound, globbed, interpreted) for the floor
  without failing closed on benign work.
- Surface stuck agents in `warn` within a per-boundary message budget.
- Bind one-use exact-action approvals to a floor rule, canonical action,
  working directory, and session.
- Return structured verdicts: `allow`, `warn`, `confirm_required`, or `block`.
- Run commands Sentinel owns in a restricted local Docker executor.
- Write every hook-path verdict durably before the action and fail closed if
  it cannot; record audit events in a local SQLite store with a JSONL export.
- Keep the MCP fixture path mandatory as a regression bench.
- State enforcement coverage per host and per surface honestly.
- Publish dangerous recall on real incidents and held-out cases, false-flag
  rate per benign session, messages per hour against the host's own prompts,
  decision latency at the hook, and audit integrity under deletion.
- Make a release-candidate decision only after those numbers are measured and
  reviewed.
- Keep any CLI limited to non-blocking health, fixture evaluation, and CI diagnostics.

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

### Planning discipline for Weeks 12-18

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
inverted CTAs, one label per control, grouped settings). Weeks 14–17 add
policy tiers, an OS-level fallback, provider connections, and sessions; if
those land on the current pattern they will be rebuilt in Week 17. This pass
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

**Status (September 11, 2026):** Merged to `main`. The look diverged from the
scope above by user decision (cream canvas, blue ticket, black hairlines
rather than monochrome), and Tasks, Approvals, and Activity were restructured
rather than only re-skinned. See
[UI Foundation Handover](./UI%20Foundation%20Handover.md). A
[Week 14 Plan](./Week%2014%20Plan.md) proposes spending Week 14 on the
friction candidates and moving transition drafts and guardrails to Week 15;
the reordering was approved on September 11 and is reflected below.

### Week 14: Consent at Activation

**Goal:** Make routine, in-scope work cost one human interaction without
changing what can be granted.

**Decided September 11, 2026:** the Week 13 live run ended with the user's
verdict that per-write approval after a reviewed contract is overkill and the
browser tab is the wrong place to approve. The friction candidates below were
promoted from "for planning" to the Week 14 scope, and the former Week 14
(transition drafts and guardrails) moved to Week 15, shifting Weeks 15–17 by
one week. Full plan, threat model, phases, and measurement:
[Week 14 Plan](./Week%2014%20Plan.md).

**Riskiest assumption:** A write budget granted at activation can be enforced
so no write ever runs outside both the contract's exact scope and a
confirm/block tier, and doing so brings routine fixture work to one
interaction per job.

**Planned outcome:**

- A bounded write budget carried by the activated contract ("up to N notes"),
  capped by a new ceiling field, part of the content hash, shown on the
  ticket, card, and receipt; in-scope, in-budget writes run and are audited,
  everything else stops exactly as today.
- Standing reads under the ceiling: in-pattern fixture reads pass with no
  active task; writes still require one. "No active task" keeps its meaning
  for writes and for the stale-view and supersession rules.
- A half-day spike on a browser-sent notification: the paired Sentinel tab
  uses the standard Notification API to surface a pending proposal or
  approval on any OS, with an action button that completes the decision
  through the existing protected route where the browser supports it, and a
  click that focuses the card everywhere. No OS-native prompt, no deep link.
- The ten-fresh-chat baseline Week 13 left unmeasured, run before and after.

**Kill condition:** Any path where a write escapes both exact scope and a
confirm/block tier, or a budget that anything but the protected activation
click can set or raise. Then budgets are dropped and per-write approval stays.
If a notification click can complete a decision without the paired session
and Origin check, it is reduced to open-only.

**Deliverable:** Activation that carries its own consent, standing reads, a
measured before/after, and a notification from the paired tab.

**Amended September 11 (afternoon):** implementation approved after three
plan gaps were fixed: the budgetable tier is now defined as a third disjoint
operation set (`issue_add_note` moves there from `confirm_operations`; no
budget means confirm, as today); the notification spike targets the browser
Notification API instead of macOS-only `osascript`/`tkinter`; and the
harness separates read-only jobs so standing reads do not distort the
before/after. Details in the plan's "Amendments" section.

**Built September 11 (evening), unmeasured:** all three parts are implemented
and verified in-process (637 pytest, 33 Playwright, Bugbot and Security
reviews clean after fixes). The kill condition did not trip: the agent cannot
set a budget, the confirm body cannot carry one, blocked and replayed writes
spend nothing, and the notification click is no stronger than the card
button. Standing reads were additionally made to fail closed while authority
is quarantined. The ten-run baseline and post-change runs and a live
notification check are still owed; see
[Week 14 Handover](./Week%2014%20Handover.md).

**User verdict, September 11 (evening):** the per-task write budget is the
wrong abstraction and is dropped as a concept. What the user wanted was (a) no
activation click for work that does not need one, not only reads, and (b) a
per-action prompt only when the action is actually dangerous. Standing reads
and the three ceiling tiers (ordinary / in-scope write / confirm) stay; the
user-facing count was removed the same evening from every card, form, and
agent message, leaving only a silent runaway cap in the ceiling (50 per task,
blocks with "propose a fresh task" rather than raising a card). The
fixture's exact-ticket scope was a
proof of the narrowest boundary, not the scope model for real tools. Both
points feed the Week 15 scope decision below.

### Week 15: Gates for the Hook-Based Supervisor

**Direction change, October 9, 2026.** The Week 15 standing-permissions plan
and scope decision drafted on September 11 are superseded; both documents are
kept for the record and marked as such. The reasons and evidence are in
[Product Direction](./Product%20Direction.md). In short: authoring a boundary
was the friction, not the boundary itself; prompt-inferred scope cannot be
authority; and the enforcement seam exists only in coding agents' hooks.

**Goal:** Verify the three load-bearing assumptions the new direction rests
on, and write no adapter code until they pass. This week contains gates only,
per the project's own de-risking rule.

**Gate 1: Claude Code hooks (half a day).** On the user's machine, with the
Claude Code version recorded: install a `PreToolUse` hook under
`managed-settings.json` that denies one floor action (`rm -rf` of a path
outside the working directory) and confirm the agent cannot perform it or edit
the hook away; confirm `UserPromptSubmit` can attach one line of context the
agent then sees; check whether the `Stop` transcript exposes the host's own
permission prompts. **Kill condition:** deny or injection fails under managed
settings → Claude Code is advisory and the hook work pauses until a host
passes.

**Gate 2a: target extraction on real shell (one to two days).** The shipped
canonicalizer knows fourteen commands and rejects compound commands, pipes,
globs, and interpreters. A Bash hook delivers everything. Capture at least two
hundred real `Bash` arguments from the user's own sessions and measure how many
a floor-oriented extraction pass can classify (target, destructive or not,
inside or outside the working directory) without failing closed. **Kill
condition:** more than one in twenty benign commands unclassifiable → the floor
cannot ship on Bash and the direction is revisited before any adapter.

**Gate 2b: the floor against reality (one to two days).** Build the evaluation
set: the 2026 incidents (Replit production wipe, Antigravity `rmdir d:\`,
three Claude Code home-directory wipes, Cursor YOLO), held-out dangerous
commands from BashArena and Terminal-Bench that the rules were not written
against, and at least one hundred benign twins (`rm -rf node_modules`, an
intentional migration, `git clean -fdx` inside the repo). Run the floor rules.
**Kill condition:** below 100% on the incidents, below 90% on held-out
dangerous cases, or more than one in twenty benign twins flagged → the list is
fixed before anything else is built.

**Also this week:** decide whether the manual form, proposal card, and budget
UI are deleted or kept as the fixture regression bench (one day either way,
scheduled in Week 16); design ceiling v2 (floor list, detector thresholds,
message budget, environments beyond `sandbox`) and its state-database
migration message.

**Deliverable:** three gate results with numbers, the evaluation set checked
in, the Claude Code version recorded, and a go/no-go for Week 16.

**Outcome (October 10, 2026): go.** Gate 1 passed on Claude Code 2.1.296;
Gate 2a measured 0.5% unparseable on 18,551 real commands; Gate 2b caught
14/14 incidents and 26/26 held-out cases with 0/120 benign twins flagged.
Decisions: the Week 14 UI is kept as a `/bench` route (deleted at Week 18 if
unused); ceiling v2 adds `version`, `floor_rules`, four environments,
detector thresholds, the message budget, and a parser-gap policy, with no
automatic v1 migration. Details, the adversarial-review findings, and the
honest limits are in [Week 15 Handover](./Week%2015%20Handover.md).

## Phase 7: The Supervisor on One Host

### Week 16: Claude Code Adapter with the Floor

**Goal:** One host, one detector. Sentinel denies the floor through Claude
Code's `PreToolUse` hook under managed settings and records every verdict
before the action runs.

**Entry gate:** Week 15 gates 1, 2a, and 2b passed.

**Planned outcome:**

- **Done (part 1, October 10):** the decision record, one typed shape for
  every verdict Sentinel writes (`docs/Decision Record.md`). Carries resolved
  targets with zones for shell, audience counts for sends, resources for
  everything else, and a judgment with rule, floor verdict, enforcement claim,
  guidance, message outcome, and latency. Wired into `AuditEvent`, the SQLite
  store (queryable by `rule_id` and `zone`), the control API, the web types,
  and the MCP gateway. Every Gate 2b incident and hard twin fits it.
- **Done (part 2, October 11; live gates owed):** the Claude Code hook
  adapter (`docs/Week 16 Plan.md`; Architecture §16.2). The Week 15 floor
  ported to `src/sentinel/floor/` with three new rules
  (`F2.supervisor_disable`, `F2.session_escape`, `F5.symlink_escape`), the
  home carve-outs, `tee`/`cp` destinations, command-substitution walking,
  and a file-tool path floor; 15/15 incidents, 26/26 held-out, 0/69 hard
  twins, 1/120 benign twins (the nested `claude -p` the new rule exists
  for). `FloorPolicy` (ceiling v2) frozen, hashed, bound to the state
  database, v1 database refused by name. HTTP hook routes that always answer
  200, never emit `permissionDecision: "allow"`, write the row with
  `write_required` before answering, and fail closed on every error path.
  Sessions keyed by the host's `session_id` with a narrow-only launch
  directory and history rebuilt from rows on restart. `sentinel serve`,
  `sentinel claude-code install | doctor | launchd`; stdlib `SessionStart`
  hook; `scripts/hook_harness.py`. In-process: p50 5 ms, p95 15 ms with the
  durable write; 230/230 rows before action. Two independent review passes
  and a security review; findings fixed with regression tests (fake heredoc
  opener hiding later lines, boundary re-derived after restart, session-escape
  prefixes, `cp` into home).
- **Changed from the plan above:** `confirm` is delivered as the host's own
  `ask` prompt carrying Sentinel's reason, every time, rather than a deny
  with an approval reference; the person answers in Claude Code, so no
  Sentinel-side approval binding or TTL exists on this path (a deny-with-
  guidance fallback is configurable per permission mode for hosts that do
  not render `ask`). The `Boundary` record is the session's launch directory
  with its source; inference and supersession stay in Week 17.
- **Live gates passed (October 12; plan §7.1):** under root-owned managed
  settings on Claude Code 2.1.296, `doctor` reported `mandatory`, and the
  real host honoured `deny` (Bash and `Edit`), showed its own confirmation
  dialog for `ask` with Sentinel's reason, refused every tool call with
  `onFailure: "block"` while Sentinel was stopped, and kept firing the
  managed hook with `disableAllHooks: true` in a local settings file. Nested
  `claude -p` tripped `F2.session_escape`. **Coverage claim for Claude Code
  on this machine: mandatory.** Live hook-side latency on 43 real calls: p50
  0.57 ms, p95 5.1 ms, max 21 ms; 37/37 actions had their decision row
  written first. Still unverified: `deny` under `bypassPermissions` and
  skill-frontmatter hooks.
- A thin Claude Code adapter translating hook events into one Sentinel
  decision API and verdicts back; `confirm` delivered as deny with an approval
  reference and retry guidance, exactly as the Week 12 MCP path does. Writes
  the decision record for every verdict.
- The `Boundary` record with its default only (working directory, containing
  repository, launch environment); no inference yet. States `inferred →
  superseded`; supersession invalidates pending approvals.
- Ceiling v2 with the floor list, thresholds, and budget; a v2 process refuses
  a v1 state database with a clear message.
- Durable pre-action audit writes on the hook path; the hook fails closed if
  the write fails. The hook configuration's hash recorded at session start.
- Approvals bound to (floor rule, canonical action, working directory,
  session) with a short TTL.
- The measurement harness producing the Product Direction §6 numbers on the
  Week 15 evaluation set and on the user's own sessions.
- The delete-or-bench decision for the removed UI carried out.

**Kill condition:** any floor action reaches execution under the tested
configuration, or Sentinel produces more messages than Claude Code's own
permission prompts on the same benign sessions.

**Deliverable:** a mandatory Claude Code path for the floor under managed
settings, with published recall, false-flag, message-rate, latency, and audit
numbers, and an honest coverage statement (advisory without managed
settings; unsupported elsewhere).

### Week 17: Hear, Tell, and Stuck

**Status (October 12): closed.** Planned, reviewed twice, built, reviewed
again (security + correctness, 12 findings fixed), verified live on Claude
Code 2.1.296. Plan and review log: `docs/Week 17 Plan.md`. Verified:
`src/sentinel/boundary/`, `src/sentinel/detectors/`, routes
`user-prompt-submit` and `post-tool-use-failure`, 146 new tests (862 total),
harness 5/5 loops and 0/8 benign twins under a per-step check, Week 16
numbers unchanged. Spike S2 passed before build (3.7% of 164 real sessions
under the upper bound; kill was 10%). Spike S3 passed live: all five hook
payload shapes parse. Live gates H1, H2, H3, H5 passed through `claude -p`
(narrowing, caution without widening, negation, nudge at the 3rd failure
and one `systemMessage` at the 4th). **Carried to Week 18:** H4 (TUI paste
strip) and H6 (twenty-minute benign task, zero messages) need an interactive
session; Spike S1 (boundary-line A/B, n=20, pre-registered pass line) is
measurement, not a ship gate, and runs inside Week 18's evaluation pack. One change from the
sketch below, forced by review: there is **no widening path** in this week
(the `include <path>` answer was forgeable from Bash and a prompt `block`
would discard the person's words); an outside path yields a caution to the
agent, and widening waits for the monitor.

**Goal:** Infer the boundary from the prompt (narrowing only), tell it to the
agent, and surface stuck agents, each behind its own spike.

**Spikes first (one day):** paired runs on twenty benign tasks with and
without the injected boundary line (kill: no visible effect → tune the
phrasing; nothing else depends on it); replay the user's own traces against
the OpenHands stuck thresholds (kill: more than one in ten benign sessions
trip → raise thresholds before any message is shown).

**Planned outcome:**

- Boundary inference from `UserPromptSubmit`: narrow from the default on
  prompt facts; any widening (second repository, home directory, staging or
  production, external channel) raises the one clarifying question through
  the existing notification path and is never accepted silently from text.
- Injection of the boundary line as `UserPromptSubmit` additional context.
- The stuck detector (same action → same result 4×; same action → error 3×;
  A/B alternation over 6 steps; identity is tool plus canonical arguments) in
  `warn`, with one message per boundary when the pattern persists.
- Per-boundary message budget enforced (at most two detector messages).
- Measurement extended with out-of-scope action rate with and without the
  line, and stuck true/false positives on the user's sessions.

**Kill condition:** the inferred boundary ever contributes to an `allow` or
`block`; or widening is accepted without the person's answer.

**Deliverable:** the hear → tell → watch loop on Claude Code with the floor
and the stuck detector, measured.

## Phase 8: Sentinel Where the Person Works, Then Release

### Week 18: Sentinel on Cursor

**Status (October 13):** built and reviewed; live gates C-H0, C-H0b, C-H2
passed; C-H3 exposed that Cursor ignores `ask` on `preToolUse` (a confirmed
`Delete` ran with no popup), Spike C2 (`spikes/week18/cursor_ask/RESULTS.md`)
found the working channel (`beforeShellExecution` / `beforeMCPExecution`,
same `tool_use_id`, 72–124 ms later), and the adapter was reworked the same
evening: shell and MCP confirms are held and delivered there, file-tool
confirms are a deny with "ask the user in chat" guidance. C-H3, C-H5, C-H1,
C-H4, C-H6 still owed. Plan: `docs/Week 18 Plan.md`; verified
implementation: `docs/Product Architecture.md` §16.4.

**Why inserted:** the release week's central test is a person living with
Sentinel on for a week, and the person lives in Cursor. Claude Code proved
the floor and the advisory layer under lockable hooks (Weeks 16-17, live
gates passed); Cursor gets the same supervisor through a translation layer
over the same service, with `enforcement: advisory` stated plainly because
the user-level Cursor hooks file is writable by the agent's user.

**Spike C1 (verified October 13, Cursor 3.24.12):** `additional_context`
reaches the agent on `beforeSubmitPrompt`, `preToolUse`, `postToolUse`, and
`postToolUseFailure`; no person-facing text on `allow`; payload shapes
logged. Hear, Tell, and Stuck port one-for-one; the single budgeted stuck
message is delivered as Cursor's own `ask` popup.

**Built (October 13):** dependency-free forwarder (`sentinel_forward.py`,
stdlib only, 3 s timeout, proxy-free loopback, exit 2 with a stderr reason
on gating events when Sentinel is unreachable; pass-through on non-gating
events); `hosts/cursor/` adapter that translates Cursor payloads into the
Claude Code envelope and delegates every decision to the shared service;
`Delete` judged as a delete, `ApplyPatch` as an opaque write,
`.cursor/mcp.json` added to the protected-config rule; `sentinel cursor
install | doctor`; `scripts/hook_harness.py --host both` reports 0 verdict
mismatches on 230 cases and 0 stuck-signal mismatches on 13 sequences
between the two hosts; 104 adapter tests plus the full suite (966) pass.
Two independent review passes (correctness, authority) found and fixed
seven defects before the docs were written, the most important being a
narrowing of the launch directory that did not re-derive the environment
(a session launched at `/` could keep `dev` rules on a production path).

**Still owed:** live gates C-H3 (rerun), C-H5, C-H1, C-H4, C-H6 on this
machine with a real Cursor process, `doctor` timing its synthetic event end
to end (the in-row `forwarder_ms` misses interpreter start), the week of
real work in Week 19, and the H4/H6/S1 gates carried from Week 17.

**Kill condition:** a stopped Sentinel lets a Cursor action through; or the
Cursor path produces a different floor verdict than the Claude Code path on
any incident or benign twin.

### Week 19: Validation, Hardening, and Release Decision (on Cursor)

**Goal:** Freeze new features, test the complete verified path, and decide
whether the result is ready to label a release candidate.

**Entry gate:** Before running final workflows, preregister the exact test
environment, scenario pack, denominators, zero-tolerance security failures,
maximum acceptable false-flag and message rates, and minimum usability result.
Do not change thresholds after inspecting failures.

**Planned outcome:**

- Run the Cursor hook path (floor, boundary, stuck) for a week of real work,
  the Claude Code path interactively under root-owned managed settings
  (`enforcement: mandatory`; closes Week 17's carried gates H4 and H6 and
  Spike S1), the MCP fixture path, and the Docker executor path end to end.
- Measure dangerous recall on incidents and held-out cases, false-flag rate
  per benign session, messages per hour against the host's prompts, decision
  latency at the hook, and audit integrity under a deliberate deletion.
- Independent correctness and security reviews; accessibility and usability
  checks on the monitor and approvals pages.
- Fix release-blocking issues; defer new features.
- Package the local application and write clear operational limits, including
  the honest statement that the audit is tamper-evident, not tamper-proof,
  because Sentinel runs as the same operating-system user as the agent.

**Kill condition:** a floor action reaches execution under the tested
configuration, the inferred boundary influences an allow or block, Sentinel is
louder than the host, or preregistered gates fail. Then the result is a
research prototype, not a release candidate.

**Deliverable:** a hardened, measured local package and an explicit release
decision, with the evaluation numbers as the public artifact.

> **Amendment (Week 18, October 14).** The Week 18 gates and the corpus
> review (`spikes/week18/prompt_corpus/`, Direction §3.1 and §3.4
> amendments) moved four fixes into the end of Week 18 and three items into
> Week 19 ahead of the freeze. End of Week 18, before C-H6: the `.cursor/`
> carve-out split, credential-taint decay, and launch-directory boundary with
> per-prompt focus hint (removes the sticky narrowing). Week 19, in this
> order, each with its own gate and the last with an independent authority
> review: `ApplyPatch` path parsing (gate: the corpus's 1,759 patches judged
> with 0 `opaque_write`); hook `confirm` denies create a one-use pending
> approval and carry its link (gate: a denied `rm` outside the repo is
> approvable from the paired tab and the retry allows exactly once); the
> after-action summary per session, pushed where a notification is paired.
> The `adjacent_repo` warn zone is deferred pending the corpus split. The
> "messages per hour" gate is restated per session as well, checked on a
> ~4-turn session (the published median) and not only on the person's long
> ones. The off-track detector is reframed: the launch directory is its unit,
> and its primary surface is the after-action summary, not a message.
>
> **Built (Week 19 item 1, October 15):** `ApplyPatch` path parsing
> (`src/sentinel/floor/patch.py`). The Cursor translator reads the
> `*** Update File:` / `*** Add File:` / `*** Delete File:` (and `*** Move
> to:`) headers into a `files` list, so patch bodies still never enter the
> envelope; `decide_patch` judges each path through `decide_path` as `Write`
> or `Delete` and the most severe verdict wins (most severe zone among
> blocks, as in the shell floor). No readable header stays `F5.opaque_write`;
> an empty or relative-only path is denied as unresolved, not skipped. Gate
> met: 2,276 corpus patches (the corpus grew past 1,759) judged with 0
> `opaque_write`; 2,245 allow, 27 block (all writes to `.cursor/hooks*` or
> the `.cursor/skills/` carve-out, the same answer `Write` gives), 4 confirm
> (outside-workspace writes); p95 0.07 ms. Not yet re-run live against
> Cursor 3.24.12; the unit path uses the recorded raw-string shape.

### Next phase (after Week 19, in order)

Off-track detector (`warn`, `confirm` only for out-of-boundary writes or
sends); hash-chained audit; the web app's monitor view; Codex adapter via the
app-server approval protocol; a calibrated model for gray areas once the
evaluation set is large enough. The Cursor adapter stays advisory until
enterprise or MDM hooks lock the hooks file against the agent.

## Local Product Non-Goals Through Week 19

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
- Public marketing before the Week 19 release gate.
- Any model-based judge before an evaluation set exists to calibrate it.
- A general-purpose prompt-writing or prompt-restructuring assistant; Sentinel adds one boundary line and never edits the person's words.
- Treating an inferred boundary as authority, or widening one without the person's answer.
- Automatic permission expansion based on learned behavior.
- Enforcement claims for hosts or tools that do not provide complete interception, or where the agent can edit the hook.
- A phone or menu-bar application; verdicts travel through existing notification channels.
- Monitoring closed consumer assistants that expose no hook.
- Agent orchestration (launching, sequencing, scheduling agents).
- The Codex hook adapter, the off-track detector, the hash-chained audit, and the monitor view before Week 19; they are the next phase.

## Post-Gate Local Follow-Up

If Week 19 passes its preregistered release gates:

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

After Week 19, the roadmap turns the validated local product into a
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

Weeks 12-18 should remain disciplined: prove that automatic task preparation,
persistent guardrails, agent management, and narrow mandatory mediation create
a useful local product. Multi-tenant hosting, production credential brokering,
production agent integrations, and managed execution come only after those
properties work and their interruption and bypass rates are measured.