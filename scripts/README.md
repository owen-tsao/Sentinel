# Scripts

This folder will contain project automation.

Planned scripts:

- `data_pipeline.py`: validate, merge, deduplicate, and split JSONL examples.
- `train_guardrail.py`: train the PyTorch command-risk model.
- `export_onnx.py`: export the trained model for lightweight inference.
- `evaluate_model.py`: measure recall, false positive rate, confusion matrix, and latency.

Week 1 does not need the full data pipeline yet. The immediate goal is to define the schema and create a trusted starter dataset.

## Data Pipeline

Run the local seed pipeline:

```bash
python3 scripts/data_pipeline.py --examples-dir data/examples --output-dir data/processed
```

Optional benchmark inputs can be added after exporting/downloading them locally:

```bash
python3 scripts/data_pipeline.py \
  --terminalbench-jsonl path/to/terminalbench.jsonl \
  --atbench-jsonl path/to/atbench.jsonl \
  --cuaharm-config-jsonl path/to/cuaharm_terminal_configs.jsonl \
  --osharm-results-dir path/to/os-harm/results \
  --output-dir data/processed
```

The pipeline writes reproducible processed JSONL files and `source_report.json` under `data/processed/`, which are ignored by git because they are generated artifacts.

By default, it also reserves 14 handwritten rows in `data/processed/sentinel_seed_eval.jsonl`. Keep that file conceptually separate from training data; it is the trusted gold check for whether rules or models still match Sentinel's label policy after benchmark rows are added.

CUAHarm static task/config inputs are treated as diagnostic inventory unless you also have real agent trajectories. Their setup commands and evaluator commands are not used as training examples because they are not agent-proposed actions.

ATBench rows are converted only when the pipeline can extract concrete tool actions. Unsafe ATBench trajectories are filtered to likely sink/mutation actions named in the dataset's rationale, so source-only actions such as searches are not blindly labeled unsafe.

OS-Harm rows are written to `data/processed/sentinel_osharm_diagnostic.jsonl` instead of the main train/validation/eval split. The converter uses `judgment.json` `safety` and `violation_step` fields to localize unsafe desktop actions, but these GUI-control snippets should stay a small diagnostic slice until Sentinel has stronger general tool-action support.

## Rules Baseline Evaluation

Run the deterministic rules baseline against the held-out seed eval and processed eval files:

```bash
python3 scripts/evaluate_rules.py
```

Add OS-Harm diagnostic rows when you want to measure desktop-agent behavior separately:

```bash
python3 scripts/evaluate_rules.py --include-osharm
```

The evaluator reports dangerous recall, benign block false positive rate, verdict confusion, source/risk-category breakdowns, and representative failure samples. Use this report to decide which rules or targeted examples are needed before scaling data or training the PyTorch model.

## Guardrail Model Training

`train_guardrail.py` fine-tunes a pretrained DistilBERT-style text classifier on Sentinel's binary `label` field. It does not train a serious neural architecture from scratch, and it does not try to predict `expected_verdict`; verdicts remain part of the policy/rules layer.

Install training dependencies in the environment where you plan to train:

```bash
python3 -m pip install torch transformers
```

Use the Mac for a tiny smoke run that checks data loading, tokenization, and metrics:

```bash
python3 scripts/train_guardrail.py --device cpu --smoke-limit 16 --epochs 1 --output-dir models/smoke-distilbert
```

Use the 3070 PC for the real fine-tuning run:

```bash
python3 scripts/train_guardrail.py --device cuda --epochs 3 --batch-size 8 --output-dir models/sentinel-distilbert
```

The script reports accuracy, precision, dangerous recall, false positive rate, and a binary confusion matrix. Treat the model's positive-class probability as a risk score that will later be combined with deterministic rules and policy.
