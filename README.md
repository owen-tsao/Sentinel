# Project Sentinel

Enterprise guardrail engine for AI-agent actions: evaluate commands with deterministic policy and sequence-aware ML, run approved actions in a local Docker executor, expose developer workflows through a CLI, and audit decisions to AWS DynamoDB.

## Docs

- [docs/Weekly Structure.md](./docs/Weekly%20Structure.md) — enterprise roadmap and 12-week Engine & CLI MVP
- [docs/Final Plan.md](./docs/Final%20Plan.md) — architecture and component specs
- [docs/week1_threat_model.md](./docs/week1_threat_model.md) — initial threat model and risk categories
- [docs/data_strategy.md](./docs/data_strategy.md) — dataset strategy and labeling guidance

## Status

Week 6 FastAPI evaluation service. Sentinel can now evaluate proposed commands through a local API using deterministic rules first and ONNX model scoring for gray-area requests when a local model artifact is available.

## Stack

- PyTorch (training) + ONNX Runtime (inference)
- FastAPI
- Docker
- AWS DynamoDB (audit logs)

## Local API

Use a Python 3.11+ environment, then install the local package with API and test dependencies:

```bash
python3 -m pip install -e ".[test]"
```

Start the evaluation service:

```bash
PYTHONPATH=src uvicorn sentinel.api.main:app --reload
```

Check service health:

```bash
curl http://127.0.0.1:8000/health
```

If the ONNX model artifact is not present, health returns `status: "degraded"`. That is expected during local development: deterministic rules still run, and gray-area requests fall back to `confirm_required` instead of being allowed blindly.

Evaluate a command without executing it:

```bash
curl -X POST http://127.0.0.1:8000/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "context": "Show git status for this repository.",
    "command": "git status --short",
    "recent_actions": [],
    "environment": "sandbox",
    "shell_type": "bash",
    "session_id": "local-session",
    "agent_id": "local-agent",
    "user_id": "local-user"
  }'
```

`POST /evaluate` never executes commands in Week 6. It returns a structured verdict with a request ID, risk score, risk tier, reason codes, routing path, agent-facing message, and suggested safer actions.

Run the focused API and decision checks:

```bash
python3 -m unittest tests.test_api_service tests.test_api_schemas tests.test_decision_engine tests.test_rules tests.test_onnx_inference
```
