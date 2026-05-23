# Project Sentinel

Agentic security proxy for AI agents: score shell commands with a trained model, apply policy rules, run approved commands in a Docker sandbox, and audit decisions to AWS DynamoDB.

## Docs

- [Weekly Structure.md](./Weekly%20Structure.md) — 12-week summer roadmap
- [Final Plan.md](./Final%20Plan.md) — architecture and component specs
- [docs/week1_threat_model.md](./docs/week1_threat_model.md) — initial threat model and risk categories
- [docs/data_strategy.md](./docs/data_strategy.md) — dataset strategy and labeling guidance

## Status

Week 1 scaffolding phase. The current focus is threat modeling, starter data, and repository structure.

## Stack (planned)

- PyTorch (training) + ONNX Runtime (inference)
- FastAPI
- Docker
- AWS DynamoDB (audit logs)
