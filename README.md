# Project Sentinel

Enterprise guardrail engine for AI-agent actions: evaluate commands with deterministic policy and sequence-aware ML, run approved actions in a local Docker executor, expose developer workflows through a CLI, and audit decisions to AWS DynamoDB.

## Docs

- [docs/Weekly Structure.md](./docs/Weekly%20Structure.md) — enterprise roadmap and 12-week Engine & CLI MVP
- [docs/Final Plan.md](./docs/Final%20Plan.md) — architecture and component specs
- [docs/week1_threat_model.md](./docs/week1_threat_model.md) — initial threat model and risk categories
- [docs/data_strategy.md](./docs/data_strategy.md) — dataset strategy and labeling guidance

## Status

Week 1/2 data foundation phase. The current focus is sequence-aware seed data, benchmark ingestion planning, and the data pipeline.

## Stack (planned)

- PyTorch (training) + ONNX Runtime (inference)
- FastAPI
- Docker
- AWS DynamoDB (audit logs)
