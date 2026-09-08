# Script command index

Run commands from the repository root. Generated datasets, model artifacts, local spike output, and unreviewed review queues are not source evidence and should stay out of commits.

## Authority and contract evaluation

### `build_contract_golden_candidates.py`

Regenerates the 60-row unreviewed core candidate queue and Markdown review packet:

```bash
python3 scripts/build_contract_golden_candidates.py
```

Outputs:

- `data/evaluation/contract_golden_candidates.jsonl`
- `data/evaluation/contract_golden_review.md`

Both outputs are generated and ignored. The builder always marks rows unreviewed; running it does not approve data.

### `build_communications_contract_candidates.py`

Regenerates the 30-row unreviewed provider-metadata candidate queue and review packet:

```bash
python3 scripts/build_communications_contract_candidates.py
```

Outputs:

- `data/evaluation/contract_communications_candidates.jsonl`
- `data/evaluation/contract_communications_review.md`

These outputs are also generated, ignored, and non-authoritative.

### `evaluate_contracts.py`

Evaluates reviewed contract/action JSONL with deterministic matching and writes an optional manifest:

```bash
python3 scripts/evaluate_contracts.py \
  data/evaluation/contract_combined_reviewed.jsonl \
  --minimum-rows-per-category 1 \
  --manifest /tmp/sentinel-known-regression.json
```

The minimum is `1` only because reviewed categories are sparse, so this command
is regression-only. Sparse coverage remains a blocker for blind promotion.
The only supported role is currently `known_regression`. Promotion is disabled
until protected blind-set registration exists. Use `--comparison-dataset`,
`--training-dataset`, and `--validation-dataset` to check declared group
separation; never overwrite the committed baseline or historical regression
manifests for an exploratory run.

## Legacy data and rules diagnostics

### `data_pipeline.py`

Validates, normalizes, deduplicates, and splits legacy `(context, recent_actions, command, environment)` JSONL:

```bash
python3 scripts/data_pipeline.py \
  --examples-dir data/examples \
  --output-dir data/processed
```

Optional benchmark inputs:

```bash
python3 scripts/data_pipeline.py \
  --terminalbench-jsonl path/to/terminalbench.jsonl \
  --atbench-jsonl path/to/atbench.jsonl \
  --cuaharm-config-jsonl path/to/cuaharm-config.jsonl \
  --osharm-results-dir path/to/os-harm/results \
  --output-dir data/processed
```

Files under `data/processed/` are generated and ignored. CUAHarm, OS-Harm, and ATBench conversions are diagnostic unless the source exposes enough pre-action, action-level authority evidence for fresh Sentinel review. TerminalBench heuristic labels are quarantined from promotion data.

### `evaluate_rules.py`

Reports the deterministic legacy rules baseline, confusion data, source/category breakdowns, and sample failures:

```bash
python3 scripts/evaluate_rules.py
python3 scripts/evaluate_rules.py --include-osharm
python3 scripts/evaluate_rules.py --json
```

This is a diagnostic for the legacy command-risk layer, not the contract promotion evaluator.

## ML diagnostics and guarded export

The current model is disabled. There is no independent reviewed calibration set, so no current threshold output can authorize export or serving.
The base project does not install the heavy training/export toolchain. Run these
commands only in a separately provisioned ML environment containing PyTorch;
ONNX export also requires the `onnx` package. Their versions must be recorded in
the generated report metadata before an artifact can be reviewed.

### `train_guardrail.py`

Fine-tunes the legacy binary command-risk classifier and writes a checkpoint plus `training_report.json`:

```bash
python3 scripts/train_guardrail.py \
  --device cpu \
  --smoke-limit 16 \
  --epochs 1 \
  --output-dir models/smoke-distilbert
```

Use this only as a local training diagnostic. A checkpoint is not deployable evidence.

### `calibrate_thresholds.py`

Renders threshold and weak-group analysis from a training report:

```bash
python3 scripts/calibrate_thresholds.py \
  --report models/smoke-distilbert/training_report.json
```

This script's output is a review aid. It is not an approved calibration artifact. Promotion requires a distinct human-reviewed calibration dataset with content-bound hashes and provenance.

### `export_onnx.py`

Exports a checkpoint only when current formatter/checkpoint metadata and a human-reviewed, content-bound calibration artifact all validate:

```bash
python3 scripts/export_onnx.py \
  --model-dir models/sentinel-distilbert \
  --output-path models/sentinel-distilbert-onnx/model.onnx \
  --thresholds-path path/to/reviewed-thresholds.json \
  --calibration-dataset-path path/to/independent-calibration.jsonl
```

The command fails closed when the calibration data, hashes, review metadata, checkpoint metadata, or input format is missing or stale. The current repository intentionally does not contain qualifying independent calibration data.

### `measure_onnx_latency.py`

Measures local CPU ONNX inference latency for an already valid serving artifact:

```bash
python3 scripts/measure_onnx_latency.py \
  --onnx-path models/sentinel-distilbert-onnx/model.onnx \
  --model-dir models/sentinel-distilbert-mps-v2
```

Latency does not imply model quality or promotion.

## Provider metadata diagnostic

### `run_live_metadata_spike.py`

Runs one bounded, read-only Slack or Google Workspace metadata probe. It never sends, shares, modifies, or grants production authority.

```bash
SENTINEL_SPIKE_SLACK_TOKEN=... \
  python3 scripts/run_live_metadata_spike.py \
  --output data/spikes/local/slack-summary.json \
  slack --channel-id CHANNEL_ID
```

Google subcommands are `google-drive --file-id`, `gmail --draft-id`, and `calendar --calendar-id --event-id`; they use `SENTINEL_SPIKE_GOOGLE_TOKEN`. Keep credentials in environment variables and local output under `data/spikes/local/`. The script refuses to overwrite an existing summary.

## Docker verification

### `docker_smoke_check.py`

Requires Docker Desktop and available local ports:

```bash
python3 scripts/docker_smoke_check.py
python3 scripts/docker_smoke_check.py --port 8010
```

The smoke validates Compose configuration, builds the API and executor images, checks non-root read-only sandbox execution, exercises trusted activation through durable SQLite audit, verifies destructive blocking, confirms the Compose API has no Docker socket, and tears down its project. Use `--skip-build` only when intentionally reusing current images and `--keep-running` only for manual inspection.
