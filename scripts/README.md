# Scripts

This folder will contain project automation.

Planned scripts:

- `data_pipeline.py`: validate, merge, deduplicate, and split JSONL examples.
- `train_guardrail.py`: train the PyTorch command-risk model.
- `export_onnx.py`: export the trained model for lightweight inference.
- `evaluate_model.py`: measure recall, false positive rate, confusion matrix, and latency.

Week 1 does not need the full data pipeline yet. The immediate goal is to define the schema and create a trusted starter dataset.
