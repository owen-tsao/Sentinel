# Project Sentinel: Roadmap

This document is the source of truth for sequencing, milestones, dependencies, and outcomes. Stable product/security behavior belongs in `docs/Product Architecture.md`; implementation-level checklists belong only in the active week plan.

Project Sentinel is a local-first, OAuth-like authorization layer for agent tasks. Its visible UX helps users turn ambiguous instructions into reviewed task contracts; its enforcement layer keeps each contract active across compliant actions and stops agents from gaining authority through tool output, webpages, messages, files, or their own reasoning.

This roadmap separates the work into two phases:

- **Part 1: Summer MVP (Weeks 1-12)** builds the core guardrail engine, persistent task-authority layer, local Docker execution, SQLite audit logging, one protected local control-center flow, a public marketing site, and one measured coding-agent integration. In-editor/MCP clarification and a thin diagnostic CLI are supporting surfaces.
- **Part 2: Post-Summer Expansion** turns the local product into a hosted/hybrid agent authorization platform with organizations, protected provider credentials, regional or customer-hosted enforcement, and managed execution infrastructure.

## Product Thesis

AI agents are becoming powerful enough to run shell commands, modify infrastructure, send external communications, and trigger production workflows. Enterprises will need a middleware layer that treats every agent action as untrusted until it is evaluated, policy-checked, scoped, and logged.

Sentinel's near-term wedge is not enterprise-wide agent discovery or a general prompt-writing assistant. The Summer MVP should prove that a useful local web product and mandatory local enforcement work together:

- detect when a high-impact request lacks an exact operation, target, environment, scope, or safety constraint,
- propose an editable prompt and structured `ActionContract` without silently changing user intent,
- keep one accepted task contract active across many compliant commands and tool calls,
- let a new direct instruction from the trusted user narrow, replace, or clearly extend the current task without repeated approval,
- require separate approval only when a task adds sensitive authority such as production access, credentials, deployment, external sending, or broad deletion,
- intercept shell, file, MCP, database, cloud, and Git actions through a host hook or mandatory proxy,
- deterministically compare each proposed action with the accepted contract,
- use a PyTorch/ONNX model only for ambiguity or contract-overstep gray areas after evaluation is trustworthy,
- apply deterministic policy rules and risk tiers,
- require confirmation for high-risk but possibly legitimate actions,
- run approved commands in a restricted Docker sandbox,
- write audit logs to a local SQLite store,
- expose the system through FastAPI and a protected local control center for onboarding, initial contract activation, exact approval, audit, and health,
- use in-editor/MCP prompt revision only as a compact supporting feature,
- publish a separate marketing site that explains and demonstrates the product without receiving protected local data.

## Core Product Principles

- **Context matters:** decisions depend on `context`, `command`, and `environment`, not command text alone.
- **Prompt text is not authorization:** vague natural language must be clarified before it can authorize a high-impact action.
- **Prompt restructuring is the UX:** Sentinel should explain missing fields and offer an editable proposal; it must never silently rewrite and execute.
- **Authority lasts for a task, not one command:** an active contract covers multiple matching actions until the trusted user switches tasks, or it is suspended, superseded, expired, or revoked.
- **Only trusted user input can expand authority:** agent suggestions and content read from tools, webpages, messages, or files can never grant new permissions.
- **The contract is the boundary:** task identity, operation, exact target, environment, maximum scope, constraints, rollback requirements, authorization source, lifecycle, and approval state must be machine-checkable.
- **Exact-action approval is exceptional:** one-time approval is reserved for sensitive actions and must not turn every ordinary command into a permission prompt.
- **Learn convenience, never permission:** future saved templates and personalization may suggest familiar targets and safety steps, but only a fresh trusted instruction or protected approval can activate authority.
- **Temporal context matters:** decisions should consider the recent action window for the agent session, not only the current command.
- **Malicious is different from destructive:** authorized destructive work may be allowed or require confirmation; malicious or agent-gone-haywire actions should block.
- **Deterministic policy comes first:** critical allow/block rules and environment policy short-circuit before ML inference whenever possible.
- **ML handles gray areas conservatively:** ONNX inference is reserved for ambiguity and contract-overstep signals and may deny/escalate, never independently approve high-impact work.
- **ML cannot broaden permission:** a model score can never downgrade a contract mismatch, environment restriction, deterministic block, missing trusted authority, or incomplete enforcement path.
- **MCP alone is not enforcement:** an MCP tool is advisory unless the host or a proxy guarantees complete mediation of protected actions.
- **Docker is not a production security boundary:** local Docker is acceptable for the Summer MVP proof-of-concept; enterprise execution requires stronger isolation such as managed orchestration, microVMs, or hardened Kubernetes controls.
- **Audit everything:** allowed, blocked, warned, and confirmation-required requests must all be logged.
- **Local-first security:** teams should be able to test policies and commands locally before using hosted infrastructure.
- **Web app is the primary product:** contract creation, authority management, approval, audit, onboarding, and health belong in the local control center. Templates and custom rules are later extensions.
- **Integrate where work happens:** Cursor, Codex, MCP, and similar surfaces should provide compact clarification and status, then route protected review to the web control center.
- **Scale without replacing the core:** a future hosted control plane may manage organizations, identity, policy, and audit indexing while enforcement remains local, regional, or customer-hosted.

## Part 1: Summer MVP (Weeks 1-12) - The Engine & Local Web Product

### Summer MVP Definition of Done

The Summer MVP is complete when Sentinel can:

- Accept command-evaluation requests through a FastAPI service.
- Detect ambiguous high-impact prompts and return focused clarification questions plus an editable proposed contract.
- Keep an accepted task contract active across multiple compliant canonical actions.
- Version, replace, narrow, expire, and revoke task authority while preserving its trusted source.
- Let direct trusted user instructions move to a different ordinary task without stale-contract blocks; require review for sensitive capability expansion.
- Bind one-use exact-action approvals to a specific contract version and canonical action.
- Evaluate requests using deterministic contract/rule enforcement, with ONNX scoring only if it proves value beyond the rules-only baseline.
- Return structured verdicts: `allow`, `warn`, `confirm_required`, or `block`.
- Run approved commands in a restricted local Docker executor.
- Record audit events in a local SQLite store with a JSONL export/debug format.
- Provide one protected local control-center flow, a public marketing site, and a measured coding-agent integration.
- Keep any CLI limited to non-blocking health, fixture evaluation, and CI diagnostics.
- Produce system metrics: contract-overstep recall, compliant-action false interruption rate, enforcement coverage, approval bypass rate, p50/p99 inference latency, sandbox latency, and audit logging success rate.

### Summer Architecture

```text
Public marketing site -> installation and product education only

Local web control center
        |
        | onboarding, initial contract activation, active authority, approval, audit
        v
FastAPI control service + SQLite
        |
        | active authority and policy
        v
Mandatory host adapter / enforcement proxy
        |
        | proposed canonical action
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
        |-- local web control center
        |-- compact host/MCP status
        |-- SQLite audit + JSONL export
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
- Explicitly document that Docker reduces blast radius for the Summer MVP but is not treated as a production-grade security boundary.

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
- Document the post-summer migration path from local Docker to stronger managed isolation.

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

**Deferred from Week 11:** templates, custom rules, broad task presets,
multi-workspace management, GitHub OAuth, marketing, ML, production provider
enforcement, and mandatory external-agent integration.

### Week 12: Mandatory Integration, Marketing Site, and Release Candidate

**Goal:** Prove the web-app-to-enforcement loop in a real coding-agent workflow, publish the product story, and freeze the Summer MVP.

**Tasks:**

- Build a public marketing site that:
  - explains task-scoped authority, deterministic enforcement, optional ML, and local-first trust,
  - shows the local web control center and one honest end-to-end demonstration,
  - documents supported versus advisory integrations and installation,
  - remains completely separate from local contracts, approvals, credentials, output, and audit data.
- Keep the CLI optional and thin: health, offline fixture evaluation, and machine-readable CI diagnostics only. Defer interactive contract, approval, template, and audit commands to the web app.
- Run end-to-end tests covering onboarding, prompt clarification, initial contract acceptance, action matching, exact approval, API, local web app, Docker executor, and audit logging.
- Select one coding-agent path only after a tiny interception spike proves authenticated user provenance or routes authority through the protected web app, plus complete mediation of the protected action. If no candidate passes, keep all host integrations advisory and demonstrate only the Sentinel-owned API → Docker boundary.
- Run the real-agent boundary evaluation through the selected mandatory adapter/proxy. Evaluate Cursor separately as an advisory clarification/deep-link surface:
  - ambiguous high-impact prompts,
  - clear compliant requests,
  - multiple ordinary actions under one task contract,
  - stale or replayed trusted prompt events and concurrent amendment conflicts,
  - multi-target actions whose second target exceeds authority,
  - untrusted content attempting to grant itself authority,
  - target/environment/scope oversteps,
  - subagent and indirect-script bypass attempts,
  - ordinary benign development tasks.
- Measure overstep catch rate, false interruptions, unnecessary repeated approvals, clarification acceptance/edit rate, enforcement-path coverage, and approval bypass rate.
- Document adapter limitations explicitly; do not claim enforcement for hosts or tools that can bypass Sentinel.
- Freeze the Summer MVP scope and document installation, local usage, and operational limits.

**Deliverable:** A local-first Sentinel release candidate with a complete local web control center, a separate public marketing site, persistent task-scoped authority, deterministic pre-action enforcement, one-use exact-action approval, restricted Docker execution, SQLite audit evidence, and one honestly measured coding-agent integration. In-editor/MCP prompt revision remains a supporting feature; the thin CLI is not release-critical.

## Summer MVP Non-Goals

These are intentionally excluded from the first 12 weeks:

- Hosted multi-tenant enterprise control plane; the full single-user local web control center and separate marketing site are in scope.
- Multi-tenant user management.
- Hosted SaaS billing.
- Organization-wide RBAC.
- Production container orchestration.
- Datadog/Splunk streaming integrations.
- Slack/email approval queues.
- Rich organization-wide policy authoring; local custom rules are deferred.
- Full managed deployment for customer workloads.
- Production-ready real-agent framework adapters.
- A general-purpose prompt-writing assistant unrelated to high-impact action safety.
- Automatic permission expansion based on learned behavior; any future
  user-created template must still produce a fresh reviewed contract.
- Enforcement claims for hosts or tools that do not provide complete interception.

## Part 2: Post-Summer Expansion - Hosted/Hybrid Production Scaling

The post-summer roadmap turns the local-first product into a hosted/hybrid platform while preserving enforcement close to the agent.

### Stage 1: Hosted Control Plane and Multi-Tenant Web App

**Goal:** Evolve the local web control center into an authenticated production control plane for teams.

Planned capabilities:

- Migrate the web app from single-user local state to organizations, workspaces, authenticated users, and isolated tenant data.
- Visualize audit logs by verdict, risk tier, environment, agent ID, and time range using a managed database such as Postgres.
- Show blocked-command timelines and reason-code breakdowns.
- Display model score distributions and policy-trigger trends.
- Manage API keys for agents, CI systems, and team integrations.
- Create and review human-in-the-loop approval requests.
- Let reviewers approve or deny exact high-risk actions.
- Show execution metadata for allowed commands without exposing sensitive outputs by default.
- Keep customer-hosted or regional enforcement gateways separate from the hosted management UI so sensitive code and credentials may remain local.

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

### Stage 5: Agent and Workflow Integrations

**Goal:** Place Sentinel directly in common agent and automation workflows.

Potential integrations:

- Real-agent validation harness that replays representative tasks through Sentinel before building full adapters.
- An isolated OpenClaw demonstration using mock or throwaway accounts, with Sentinel-managed tools as the only path to protected actions.
- OpenClaw adapter as the first production candidate only if its command/tool execution layer can be intercepted without bypass.
- MCP proxy or middleware.
- LangChain, AutoGen, and OpenClaw adapters.
- CI/CD guardrail mode for GitHub Actions or other build systems.
- Cloud-operation guardrails for AWS CLI, Terraform, and Kubernetes commands.
- External communication guardrails for mass email, Slack, and ticketing workflows.

### Stage 6: Model and Policy Intelligence

**Goal:** Improve detection quality using production feedback while preserving trust.

Planned capabilities:

- Reviewed-audit feedback loop for retraining.
- Per-organization policy recommendations.
- Risk scoring by command category and historical behavior.
- Drift monitoring for model performance.
- Shadow-mode evaluation before enforcing new model versions.
- Model/version provenance in every audit event.
- Detect repeated accepted task patterns from trusted structured history and suggest candidate templates in shadow mode.
- Learn convenience preferences such as usual targets, environments, dry-run steps, and draft-before-send behavior without weakening hard policy.
- Require explicit save/edit/reject for every suggested template; learned patterns never activate authority.
- Let users inspect, reset, export, and delete preference data.

## Long-Term Product Direction

Sentinel should evolve from a local guardrail engine into an enterprise authorization platform for AI-agent operations:

```text
Local web control center + local enforcement + Docker
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

The Summer MVP should remain disciplined: prove persistent task authority, trusted task changes, mandatory interception, and low false-interruption behavior through a useful local web product. Multi-tenant hosting, provider credential brokering, production agent integrations, and managed execution come after those core authorization properties work.