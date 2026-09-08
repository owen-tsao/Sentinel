# Data Strategy

## Short Answer

You should not rely only on hand-written examples, but you should keep a small hand-labeled seed set.

The safe path is:

1. Use `data/examples/starter_seed.jsonl` as the label policy and sanity-check set.
2. Identify a measured coverage gap.
3. Use public or generated examples only when their pre-action evidence can support an action-level Sentinel label.
4. Human-review labels and keep training, validation, calibration, blind evaluation, and known regression data separate.

## Why Not Use Only Online Data?

Public benchmarks are useful, but they may not map perfectly to Sentinel's exact API shape. Some are task-level, GUI-heavy, or do not provide clean `(context, recent_actions, command)` examples. A small seed set defines what Sentinel means by `safe`, `authorized_destructive`, `confirm_required`, and `malicious`.

CUAHarm is diagnostic or inspiration unless actual run outputs expose the
pre-action history, exact proposed action, and authority evidence needed for a
Sentinel label. Static tasks, setup commands, and evaluator commands are not
agent-proposed action evidence.

OS-Harm is also diagnostic or inspiration unless an individual step can be
bound to complete pre-action evidence. Its GUI-heavy trajectories and
contamination warning make direct training inappropriate by default.

ATBench provides trajectory-level safety labels, not a complete action-level
authority boundary. Use it for taxonomy and diagnostic patterns unless the
released evidence supports a fresh Sentinel review.

TerminalBench conversions use heuristic labels. Keep them quarantined from
trusted training, calibration, and promotion data.

## Why Not Use Only GPT Data?

GPT can generate many examples quickly, but it can also:

- overrepresent obvious attacks,
- label destructive-but-authorized commands incorrectly,
- miss realistic benign developer workflows,
- generate commands that are syntactically odd or unrealistic,
- leak your own assumptions back into the dataset.

Use GPT to expand coverage, not to define the ground truth alone.

## Dataset composition

Do not target fixed percentages by source. A percentage target rewards volume,
not evidence quality, and can force weak benchmark conversions into the data.
Build by measured category and failure coverage instead.

Before training, require distinct group-disjoint training and validation sets.
Before export, require an independent human-reviewed calibration set. Before
promotion, require a preregistered human-reviewed blind set. The frozen known
regression corpus is never training, calibration, or blind promotion data.

## Legacy pipeline behavior

The first `scripts/data_pipeline.py` should:

- load JSONL files from `data/examples/`,
- optionally load converted benchmark examples,
- validate required fields,
- normalize missing `recent_actions` to `[]`,
- deduplicate exact `(context, recent_actions, command, environment)` pairs,
- split into train/eval files,
- report label and risk-category counts.

## Labeling Rule

Always ask:

> Given this context, recent action history, and environment, is this command appropriate?

Do not ask:

> Does this command look scary?

That difference is what makes Sentinel valuable.

## Source kill condition

Keep a source diagnostic-only if reviewers cannot derive the active authority,
pre-action history, exact action, all targets/effects, expected outcome, and
reason codes without inventing facts.
