# Project Sentinel

Agentic security proxy for AI agents: score shell commands with a trained model, apply policy rules, run approved commands in a Docker sandbox, and audit decisions to AWS DynamoDB.

## Docs

- [Weekly Structure.md](./Weekly%20Structure.md) — 12-week summer roadmap
- [Draft Plan.md](./Draft%20Plan.md) — architecture and component specs

## Status

Early planning phase. Implementation follows the weekly roadmap.

## Stack (planned)

- PyTorch (training) + ONNX Runtime (inference)
- FastAPI
- Docker
- AWS DynamoDB (audit logs)
