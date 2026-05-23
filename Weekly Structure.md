# Project Sentinel: 12-Week Summer Roadmap

Project Sentinel is a backend security service for AI agents. An agent sends Sentinel a task context and a command it wants to run. Sentinel scores the command with a trained model, applies policy rules, blocks or allows the command, runs allowed commands inside a Docker sandbox, and logs every decision for auditing.

The goal of this roadmap is to build one strong, complete project instead of several shallow ones. By the end of the summer, Sentinel should have a working API, a trained PyTorch model, Docker-based execution isolation, AWS-backed audit logging, evaluation metrics, and a realistic agent integration demo.

## Core Mental Model

- **PyTorch:** used to train the command-risk model on your local PC/GPU.
- **FastAPI:** exposes Sentinel as an API that agents can call with `POST /execute`.
- **Docker:** packages Sentinel and provides the sandbox where approved commands run.
- **AWS:** stores audit logs in DynamoDB and optionally hosts the service for a public demo.
- **OpenClaw:** optional final integration target. If it is too difficult, use a small local agent simulator as the fallback demo.

## Definition of Done

Sentinel is considered summer-complete when it can:

- Accept `{ "context": "...", "command": "...", "environment": "sandbox" }` through an API.
- Score the command with a trained model.
- Apply simple risk tiers instead of a single magic threshold.
- Block clearly dangerous commands.
- Run allowed commands inside a restricted Docker sandbox.
- Log every request, score, verdict, and result to DynamoDB or a local fallback log.
- Report evaluation metrics such as recall, false positive rate, and latency.
- Demonstrate end-to-end behavior through `curl`, a Python client, and ideally OpenClaw.

## Phase 1: Understand the Problem and Build the Dataset

### Week 1: Project Foundations and Threat Model

**Goal:** Understand exactly what Sentinel protects against and what it does not protect against.

**Tasks:**

- Write a short threat model: what counts as malicious, risky, allowed, or user-approved destructive behavior.
- Define initial risk tiers: `allow`, `warn`, `block`, and possibly `requires_approval`.
- Decide the first supported command environment: local sandbox only, not production systems.
- Set up the repository structure for data, training, API, sandbox, infra, and tests.
- Create a small hand-written dataset of safe and dangerous commands to validate the full workflow later.

**Deliverable:** A clear project README section explaining Sentinel in plain English, plus 50-100 starter examples in JSONL format.

### Week 2: Benchmark Research and Data Pipeline

**Goal:** Turn public agent-safety benchmarks and hand-written examples into a usable training dataset.

**Tasks:**

- Explore CUAHarm and OS-Harm to understand their format and what data can realistically be extracted.
- Build `data_pipeline.py` to output examples with:
  - `context`
  - `command`
  - `label`
  - `source`
  - `risk_category`
- Include safe examples, obvious dangerous examples, and context-dependent examples.
- Keep labels tied to intent. For example, deleting `./build` can be safe during cleanup but risky during a backup task.

**Deliverable:** A reproducible dataset file such as `data/processed/sentinel_train.jsonl` and `data/processed/sentinel_eval.jsonl`.

### Week 3: Dataset Quality and Baseline Rules

**Goal:** Build a simple non-ML baseline before training the model.

**Tasks:**

- Add validation checks for missing fields, duplicate examples, and label balance.
- Split the data into train, validation, and test sets.
- Build a small rules baseline for obvious dangerous patterns such as `rm -rf /`, `mkfs`, suspicious `curl | sh`, credential dumping, or destructive AWS CLI calls.
- Measure the baseline's recall and false positive rate on the test set.
- Add a small synthetic data generator only if needed, with strict cost limits.

**Deliverable:** A baseline metrics table. This gives you something to compare the PyTorch model against.

## Phase 2: Train the Guardrail Model

### Week 4: First PyTorch Model

**Goal:** Train the first working binary classifier.

**Tasks:**

- Use PyTorch and a small text model such as DistilBERT for command-risk classification.
- Train on `(context, command)` pairs, not command text alone.
- Track accuracy, recall on dangerous examples, false positive rate, and confusion matrix.
- Save the trained model and tokenizer artifacts.
- Document the model's known weaknesses.

**Deliverable:** A first model that beats or complements the rules baseline on the held-out test set.

### Week 5: Model Improvement and ONNX Export

**Goal:** Make the model usable for a real API server.

**Tasks:**

- Improve the dataset where the first model fails: obfuscated commands, benign destructive commands, and context mismatch.
- Tune the decision threshold using validation data instead of hard-coding `0.8`.
- Export the trained model to ONNX for lighter and faster inference.
- Test ONNX Runtime locally and compare its predictions against the PyTorch version.
- Measure p50 and p99 inference latency on CPU.

**Deliverable:** A production-ready model file plus a short model card explaining training data, metrics, latency, and limitations.

## Phase 3: Build the Sentinel API

### Week 6: FastAPI Interception Layer

**Goal:** Build the backend service agents will call.

**Tasks:**

- Create a FastAPI app with `POST /execute`.
- Accept request fields such as `context`, `command`, `environment`, and optional `user_confirmed`.
- Load the ONNX model on startup.
- Return structured JSON responses for `allowed`, `blocked`, and `error` cases.
- Include request IDs for tracing and logging.
- Add basic tests for safe commands, blocked commands, malformed requests, and model errors.

**Deliverable:** A working local API that can score and decide on commands without executing them yet.

### Week 7: Policy Engine and Risk Tiers

**Goal:** Avoid relying on one ML score alone.

**Tasks:**

- Combine three signals:
  - rules baseline
  - model score
  - environment policy
- Implement risk tiers:
  - low risk: allow
  - medium risk: allow only in sandbox and log
  - high risk: block or require explicit approval
- Treat `sandbox`, `dev`, and `production` differently, even if production is only simulated.
- Add tests for context-dependent cases, such as destructive cleanup commands that are safe only in a sandbox.

**Deliverable:** A more realistic decision system that can explain why a command was allowed or blocked.

## Phase 4: Docker Sandbox and Local End-to-End System

### Week 8: Dockerized Sentinel Service

**Goal:** Package Sentinel so it runs consistently across machines.

**Tasks:**

- Write a Dockerfile for the Sentinel API.
- Run the API as a non-root user.
- Keep the production image small by using ONNX Runtime instead of full PyTorch when possible.
- Add `docker-compose.yml` for local development.
- Document how to build and run Sentinel locally.

**Deliverable:** `docker compose up` starts the Sentinel API locally.

### Week 9: Isolated Command Execution

**Goal:** Run approved commands in a restricted Docker sandbox instead of directly on the host.

**Tasks:**

- Create a minimal executor image for approved commands.
- Run allowed commands with restrictions such as:
  - short timeout
  - non-root user
  - limited CPU and memory
  - no network by default
  - restricted mounted directory
- Capture `stdout`, `stderr`, exit code, and timeout status.
- Make sure blocked commands are never executed.
- Add tests proving the sandbox limits damage.

**Deliverable:** End-to-end local flow: request -> score -> policy decision -> sandboxed execution or block -> response.

## Phase 5: AWS Logging and Optional Cloud Deployment

### Week 10: Audit Logging with DynamoDB

**Goal:** Add real AWS experience without requiring expensive cloud hosting.

**Tasks:**

- Create a DynamoDB table for audit logs.
- Log request ID, timestamp, context summary, command, model score, rules triggered, verdict, environment, and execution result.
- Use `boto3` from the API server.
- Add a local fallback logger so development still works without AWS credentials.
- Keep AWS usage low. DynamoDB logging for a demo should cost little or nothing at small scale.

**Deliverable:** Every Sentinel decision appears in DynamoDB or the local fallback log.

### Week 11: Deployment Path and Demo Environment

**Goal:** Prove Sentinel can run beyond your laptop without requiring always-on paid infrastructure.

**Tasks:**

- Choose one deployment path:
  - **Recommended no-credit path:** local Docker + real DynamoDB logging.
  - **Optional AWS path:** EC2 free tier running Docker.
  - **Stretch path:** ECS/Fargate + API Gateway for a short-lived demo, then destroy resources.
- Add simple infrastructure notes or scripts using one tool, either AWS CDK or Terraform.
- Measure API latency locally and, if deployed, from the cloud endpoint.
- Prepare a repeatable demo script with safe, risky, and blocked commands.

**Deliverable:** A documented deployment story and a demo that does not depend on leaving expensive AWS resources running.

## Phase 6: Agent Integration, Evaluation, and Portfolio Polish

### Week 12: OpenClaw Integration and Final Evaluation

**Goal:** Test Sentinel against a real or realistic agent workflow.

**Tasks:**

- Attempt OpenClaw integration by routing command execution through Sentinel's `POST /execute` endpoint.
- If OpenClaw integration is too time-consuming, build a small local agent simulator that:
  - receives a task
  - proposes commands
  - sends them to Sentinel
  - follows allow/block responses
- Run final tests with safe tasks, malicious prompts, and ambiguous commands.
- Produce final metrics:
  - dangerous-command recall
  - false positive rate
  - p50/p99 inference latency
  - sandbox execution latency
  - number of logged audit events
- Record a short demo video and polish the README.

**Deliverable:** A complete portfolio-ready project with a clear demo, metrics, architecture diagram, and limitations section.

## OpenClaw Plausibility

Testing on OpenClaw is plausible if OpenClaw exposes a way to intercept or replace its command/tool execution step. The integration should be treated as a final stretch goal, not the core proof that Sentinel works.

The fallback plan is still strong: build a small agent simulator that behaves like an agent by generating commands and sending them to Sentinel. This proves the same architecture without depending on OpenClaw internals.

## Final Portfolio Artifacts

By the end of the summer, prepare:

- `README.md` with plain-English overview and architecture diagram.
- API documentation with example requests and responses.
- Model card with dataset sources, metrics, and limitations.
- Demo script and optional demo video.
- AWS logging instructions.
- Clear setup instructions using Docker.
- Resume bullet with measurable results.

Example resume bullet:

> Built Sentinel, a Dockerized FastAPI security proxy for AI agents that uses a PyTorch-trained command-risk classifier, ONNX inference, Docker sandboxing, and AWS DynamoDB audit logs to block risky tool executions with measured recall, false positive rate, and latency.

## Future Improvement Goals for Startup Potential

- Add a small web dashboard for audit logs, blocked commands, and approval queues.
- Add human-in-the-loop approval for high-risk commands instead of only allow/block.
- Support team and organization policies, such as different rules for sandbox, staging, and production.
- Build adapters for MCP, LangChain, OpenClaw, AutoGen, and other agent frameworks.
- Add role-based access control so different users or agents have different permissions.
- Add signed user intent or approval tokens so Sentinel can distinguish authorized destructive work from unexpected agent behavior.
- Add stronger sandboxing with network allowlists, filesystem policies, and per-command resource limits.
- Add SIEM/export integrations such as CloudWatch, Datadog, Splunk, or OpenTelemetry.
- Add continuous learning from reviewed audit logs so the model improves over time.
- Offer a hosted version for teams that want agent safety logging without running their own infrastructure.