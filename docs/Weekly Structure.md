# Project Sentinel: Enterprise Security Product Roadmap

Project Sentinel is a B2B security control plane for AI-agent command execution. The product sits between autonomous agents and high-impact tools, evaluates proposed actions against model and policy signals, executes approved commands inside a controlled sandbox, and records an auditable trail of every decision.

This roadmap separates the work into two phases:

- **Part 1: Summer MVP (Weeks 1-12)** builds the core guardrail engine, local Docker execution, SQLite audit logging, and a developer-facing CLI for DevOps/security teams.
- **Part 2: Post-Summer Expansion** turns the engine into an enterprise SaaS platform with dashboards, approvals, integrations, and managed execution infrastructure.

## Product Thesis

AI agents are becoming powerful enough to run shell commands, modify infrastructure, send external communications, and trigger production workflows. Enterprises will need a middleware layer that treats every agent action as untrusted until it is evaluated, policy-checked, scoped, and logged.

Sentinel's near-term wedge is not a full enterprise platform. The Summer MVP should prove the core enforcement engine works locally:

- classify risky commands using a PyTorch-trained model served through ONNX Runtime,
- apply deterministic policy rules and risk tiers,
- require confirmation for high-risk but possibly legitimate actions,
- run approved commands in a restricted Docker sandbox,
- write audit logs to a local SQLite store,
- expose the system through both FastAPI and a robust CLI.

## Core Product Principles

- **Context matters:** decisions depend on `context`, `command`, and `environment`, not command text alone.
- **Temporal context matters:** decisions should consider the recent action window for the agent session, not only the current command.
- **Malicious is different from destructive:** authorized destructive work may be allowed or require confirmation; malicious or agent-gone-haywire actions should block.
- **Deterministic policy comes first:** critical allow/block rules and environment policy short-circuit before ML inference whenever possible.
- **ML handles gray areas:** ONNX inference is reserved for commands that are not conclusively handled by deterministic policy.
- **Docker is not a production security boundary:** local Docker is acceptable for the Summer MVP proof-of-concept; enterprise execution requires stronger isolation such as managed orchestration, microVMs, or hardened Kubernetes controls.
- **Audit everything:** allowed, blocked, warned, and confirmation-required requests must all be logged.
- **Local-first security:** teams should be able to test policies and commands locally before using hosted infrastructure.
- **CLI before dashboard:** the first professional user is a DevOps/security engineer in a terminal.

## Part 1: Summer MVP (Weeks 1-12) - The Engine & CLI

### Summer MVP Definition of Done

The Summer MVP is complete when Sentinel can:

- Accept command-evaluation requests through a FastAPI service.
- Evaluate requests using deterministic rules plus an ONNX-served ML model.
- Return structured verdicts: `allow`, `warn`, `confirm_required`, or `block`.
- Run approved commands in a restricted local Docker executor.
- Record audit events in a local SQLite store with a JSONL export/debug format.
- Provide a CLI that lets teams evaluate commands, run sandboxed executions, manage local policy files, and inspect blocked-command logs.
- Produce system metrics: dangerous-command recall, false positive rate, p50/p99 inference latency, sandbox execution latency, and audit logging success rate.

### Summer Architecture

```text
Developer or CI job
        |
        | sentinel CLI
        v
FastAPI guardrail service
        |
        | validate request
        v
Decision engine
        |
        |-- deterministic policy prefilter
        |-- recent action history
        |-- ONNX model score for gray-area requests
        |-- confirmation state
        v
Verdict: allow / warn / confirm_required / block
        |
        | if allowed
        v
Local Docker executor
        |
        v
Response + audit event
        |
        |-- terminal output
        |-- SQLite audit log
        |-- JSONL export for debugging
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

## Phase 5: Audit Logging and Developer CLI

### Week 10: SQLite Audit Logging, Eval Set Expansion, and Custom Deny Rules

**Goal:** Add durable, queryable, local-first audit logging; harden the model evaluation set with realistic agent workloads; and let users define their own deny/confirm rules as a second security layer.

**Audit logging tasks:**

- Design the SQLite audit log schema with indexes for verdict, environment, agent ID, and timestamp.
- Implement an `AuditStore` interface with `write()` and `query()` so the storage backend can be swapped later (e.g. DynamoDB or Postgres for a hosted deployment) without touching the rest of the system.
- Implement the SQLite-backed store using Python's built-in `sqlite3` module.
- Add a JSONL export/debug format for easy inspection and portability.
- Log every decision:
  - request ID,
  - timestamp,
  - command,
- recent action summary,
  - context summary,
  - environment,
  - model score,
  - rules triggered,
  - routing path (`rules`, `policy`, `model`, or `combined`),
  - verdict,
  - confirmation state,
  - execution result.
- Add tests for successful logging, query filters, and schema behavior.
- Optional stretch: implement a DynamoDB-backed `AuditStore` behind the same interface for AWS experience, without making it a core dependency.

**Eval set expansion tasks (golden eval hardening):**

- Grow the held-out golden eval set with cases drawn from real agent workloads rather than synthetic one-liners:
  - coding agents (Cursor/Copilot-style): force pushes, dependency installs from untrusted URLs, `.env`/secret reads mid-task, CI config edits,
  - agentic browsers / computer-use agents: downloads piped to shell, credential file access after visiting untrusted pages, installer execution,
  - ops agents: cloud CLI mutations, database operations, and Kubernetes actions in the wrong environment.
- Prioritize context-flip pairs (same command, different context/history changes the verdict) and sequence-dependent cases where `recent_actions` determines risk.
- Mine realistic traces from published agent-safety benchmarks (OS-Harm execution traces, AgentHarm) after validating with a small pilot extraction that the traces contain usable command-level actions. Kill condition: if a benchmark lacks concrete commands, keep it diagnostic-only.
- Add paraphrase variants of contexts to test that the model is not keying on exact wording.
- Maintain a small "canary" suite of critical cases (root deletion, credential exfiltration, defense evasion) that must always pass before any model or rules change ships.

**Custom deny rules tasks (user-defined policy layer):**

- Let users author their own deny/confirm rules on top of Sentinel's built-in rules, as a deterministic second security layer (e.g. block access to production Slack channels while testing, block `curl` to non-allowlisted domains, block reads of `~/.ssh`).
- Design a simple user rule format (JSON or YAML): pattern or matcher, scope (environment, agent, session), verdict (`block` or `confirm_required`), and a human-readable reason.
- Evaluate user rules in the deterministic layer alongside built-in rules, before model inference. User rules may only escalate; they can never downgrade a built-in block.
- Return the triggering user rule in the response reasons so agents and humans can see exactly why an action was denied.
- Add tests: user rule matches, scope filtering, escalation-only enforcement, and malformed rule file rejection.
- Note: command/path/domain matching ships first; action-level browser integrations (e.g. Slack channel awareness) are post-summer scope once real agent adapters exist.

**Deliverable:** Every allowed, blocked, warned, and confirmation-required request is queryable from the local SQLite audit log; the golden eval set covers realistic coding-agent, browser-agent, and ops-agent scenarios with context-flip pairs; and users can define custom deny/confirm rules that Sentinel enforces deterministically.

### Week 11: Sentinel CLI - Evaluation, Policy, and Execution

**Goal:** Build the primary developer-facing interface for the Summer MVP.

**Tasks:**

- Implement a `sentinel` CLI using a Python CLI framework such as Typer or Click.
- Add local command evaluation:
  - `sentinel eval --context "..." --command "..."`
  - `sentinel eval --context "..." --history history.json --command "..."`
- Add sandboxed execution:
  - `sentinel run --context "..." --command "..."`
- Add policy support:
  - `sentinel policy validate sentinel.policy.yaml`
  - `sentinel policy explain --command "..."`
- Add local service management helpers:
  - `sentinel server start`
  - `sentinel health`
- Make CLI output readable for humans and scriptable for CI through `--json`.

**Deliverable:** DevOps teams can test agent commands and policies locally from the terminal.

### Week 12: Sentinel CLI - Audit Log Workflows and Release Candidate

**Goal:** Make the CLI useful for security review and operational debugging.

**Tasks:**

- Add log inspection commands:
  - `sentinel logs list --blocked`
  - `sentinel logs show <request_id>`
  - `sentinel logs tail`
- Add filters for:
  - verdict,
  - environment,
  - risk category,
  - agent ID,
  - time range.
- Add CLI flows for confirmation-required actions:
  - show why confirmation is needed,
  - approve or deny a local confirmation request,
  - retry with a confirmation token.
- Run end-to-end tests covering API, CLI, Docker executor, and audit logging.
- Define the adapter contract a real agent would need to call Sentinel, including request shape, response handling, and recent-action history format.
- If OpenClaw or another real agent exposes an easy command/tool hook by this point, run a non-blocking smoke test through the API or CLI. This validates the integration path but is not required for the Summer MVP release candidate.
- Freeze the Summer MVP scope and document installation, local usage, and operational limits.

**Deliverable:** A local-first Sentinel release candidate: guardrail engine, Docker sandbox, SQLite audit logging, and CLI workflows for evaluation, execution, policy validation, and blocked-command review.

## Summer MVP Non-Goals

These are intentionally excluded from the first 12 weeks:

- Enterprise web dashboard.
- Multi-tenant user management.
- Hosted SaaS billing.
- Organization-wide RBAC.
- Production container orchestration.
- Datadog/Splunk streaming integrations.
- Slack/email approval queues.
- Browser-based policy editing.
- Full managed deployment for customer workloads.
- Production-ready real-agent framework adapters.

## Part 2: Post-Summer Expansion - Observability & Enterprise Scaling

The post-summer roadmap turns the local-first guardrail engine into an enterprise SaaS platform.

### Stage 1: Enterprise Web Dashboard

**Goal:** Give security and platform teams a central UI for visibility and approvals.

Planned capabilities:

- Visualize audit logs by verdict, risk tier, environment, agent ID, and time range (migrating the audit store from local SQLite to a managed database such as DynamoDB or Postgres).
- Show blocked-command timelines and reason-code breakdowns.
- Display model score distributions and policy-trigger trends.
- Manage API keys for agents, CI systems, and team integrations.
- Create and review human-in-the-loop approval requests.
- Let reviewers approve or deny exact high-risk actions.
- Show execution metadata for allowed commands without exposing sensitive outputs by default.

### Stage 2: Enterprise Identity, Tenancy, and Policy Management

**Goal:** Support real organizations rather than single-developer local usage.

Planned capabilities:

- Organizations and workspaces.
- User roles such as admin, security reviewer, developer, and read-only auditor.
- Per-environment policies for sandbox, dev, staging, and production.
- Signed approval tokens tied to exact requests.
- API key rotation and scoped service tokens.
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
- OpenClaw adapter as the first candidate if its command/tool execution layer can be intercepted cleanly.
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

## Long-Term Product Direction

Sentinel should evolve from a local guardrail engine into an enterprise security platform for AI-agent operations:

```text
Local CLI and Docker executor
        |
        v
Team API with managed audit log storage
        |
        v
Enterprise dashboard and approval queues
        |
        v
SIEM integrations and managed execution fleet
        |
        v
Full AI-agent security control plane
```

The Summer MVP should remain disciplined: build the reliable enforcement engine and CLI first. The enterprise dashboard, integrations, and managed execution platform come after the core product can already evaluate, block, confirm, execute, and audit agent actions locally.