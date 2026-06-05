#!/usr/bin/env python3
"""Fine-tune a lightweight text classifier for Sentinel command risk.

The model target is binary risk probability from `label`, not the final
allow/warn/confirm/block product verdict. Policy verdicts remain in the rules
and decision layers.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_MODEL = "distilbert-base-uncased"
DEFAULT_TRAIN_PATH = Path("data/processed/sentinel_train.jsonl")
DEFAULT_VALIDATION_PATH = Path("data/processed/sentinel_validation.jsonl")
DEFAULT_EVAL_PATH = Path("data/processed/sentinel_eval.jsonl")
DEFAULT_THRESHOLDS = (0.2, 0.3, 0.4, 0.5, 0.6, 0.7)
DEFAULT_TEXT_PREVIEW_CHARS = 280
DEFAULT_CHECKPOINT_OBJECTIVE = "bounded_fpr"
DEFAULT_CHECKPOINT_MIN_RECALL = 0.9
DEFAULT_CHECKPOINT_MAX_FPR = 0.3
CHECKPOINT_OBJECTIVES = ("bounded_fpr", "dangerous_recall")


@dataclass(frozen=True)
class TrainingExample:
    id: str
    text: str
    label: int
    source: str
    risk_category: str


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSONL: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            rows.append(row)
    return rows


def format_recent_actions(recent_actions: Any) -> str:
    if not isinstance(recent_actions, list) or not recent_actions:
        return "None"

    formatted: list[str] = []
    for index, action in enumerate(recent_actions[-5:], start=1):
        if not isinstance(action, dict):
            formatted.append(f"{index}. {str(action)[:240]}")
            continue
        summary = str(action.get("summary", "")).strip() or "No summary"
        action_type = str(action.get("type", "unknown")).strip() or "unknown"
        resources = action.get("sensitive_resources", [])
        resources_text = ", ".join(str(resource) for resource in resources) if isinstance(resources, list) and resources else "none"
        formatted.append(f"{index}. type={action_type}; summary={summary}; sensitive_resources={resources_text}")
    return "\n".join(formatted)


def row_to_text(row: dict[str, Any]) -> str:
    """Format one Sentinel row as the text DistilBERT will classify."""

    return "\n".join(
        [
            f"Context: {str(row.get('context', '')).strip()}",
            f"Recent actions:\n{format_recent_actions(row.get('recent_actions'))}",
            f"Environment: {str(row.get('environment', 'sandbox')).strip()}",
            f"Command: {str(row.get('command', '')).strip()}",
        ]
    )


def rows_to_examples(rows: list[dict[str, Any]], limit: int | None = None) -> list[TrainingExample]:
    examples: list[TrainingExample] = []
    selected_rows = rows[:limit] if limit is not None else rows
    for index, row in enumerate(selected_rows, start=1):
        if row.get("label") not in (0, 1):
            raise ValueError(f"{row.get('id', index)}: label must be 0 or 1")
        examples.append(
            TrainingExample(
                id=str(row.get("id", f"row-{index}")),
                text=row_to_text(row),
                label=int(row["label"]),
                source=str(row.get("source", "unknown")),
                risk_category=str(row.get("risk_category", "unknown")),
            )
        )
    return examples


def compute_binary_metrics(labels: list[int], probabilities: list[float], threshold: float = 0.5) -> dict[str, Any]:
    if len(labels) != len(probabilities):
        raise ValueError("labels and probabilities must have the same length")
    if not labels:
        return {
            "total": 0,
            "threshold": threshold,
            "accuracy": None,
            "precision": None,
            "dangerous_recall": None,
            "false_positive_rate": None,
            "confusion": {"tp": 0, "fp": 0, "tn": 0, "fn": 0},
        }

    predictions = [1 if probability >= threshold else 0 for probability in probabilities]
    tp = sum(1 for label, prediction in zip(labels, predictions) if label == 1 and prediction == 1)
    fp = sum(1 for label, prediction in zip(labels, predictions) if label == 0 and prediction == 1)
    tn = sum(1 for label, prediction in zip(labels, predictions) if label == 0 and prediction == 0)
    fn = sum(1 for label, prediction in zip(labels, predictions) if label == 1 and prediction == 0)

    return {
        "total": len(labels),
        "threshold": threshold,
        "accuracy": _safe_ratio(tp + tn, len(labels)),
        "precision": _safe_ratio(tp, tp + fp),
        "dangerous_recall": _safe_ratio(tp, tp + fn),
        "false_positive_rate": _safe_ratio(fp, fp + tn),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


def compute_threshold_sweep(labels: list[int], probabilities: list[float], thresholds: list[float]) -> list[dict[str, Any]]:
    return [compute_binary_metrics(labels, probabilities, threshold=threshold) for threshold in thresholds]


def compute_evaluation_metrics(
    labels: list[int],
    probabilities: list[float],
    threshold: float,
    thresholds: list[float],
    examples: list[TrainingExample] | None = None,
) -> dict[str, Any]:
    metrics = compute_binary_metrics(labels, probabilities, threshold=threshold)
    metrics["threshold_sweep"] = compute_threshold_sweep(labels, probabilities, thresholds)
    if examples is not None:
        metrics["by_source"] = compute_group_metric_breakdowns(examples, probabilities, "source", threshold, thresholds)
        metrics["by_risk_category"] = compute_group_metric_breakdowns(
            examples,
            probabilities,
            "risk_category",
            threshold,
            thresholds,
        )
    return metrics


def compute_group_metric_breakdowns(
    examples: list[TrainingExample],
    probabilities: list[float],
    group_field: str,
    threshold: float,
    thresholds: list[float],
) -> dict[str, dict[str, Any]]:
    if len(examples) != len(probabilities):
        raise ValueError("examples and probabilities must have the same length")
    if group_field not in {"source", "risk_category"}:
        raise ValueError(f"unsupported breakdown field: {group_field}")

    grouped_labels: dict[str, list[int]] = {}
    grouped_probabilities: dict[str, list[float]] = {}
    for example, probability in zip(examples, probabilities):
        group_name = getattr(example, group_field).strip() or "unknown"
        grouped_labels.setdefault(group_name, []).append(example.label)
        grouped_probabilities.setdefault(group_name, []).append(probability)

    return {
        group_name: {
            **compute_binary_metrics(
                grouped_labels[group_name],
                grouped_probabilities[group_name],
                threshold=threshold,
            ),
            "threshold_sweep": compute_threshold_sweep(
                grouped_labels[group_name],
                grouped_probabilities[group_name],
                thresholds,
            ),
        }
        for group_name in sorted(grouped_labels)
    }


def select_checkpoint_candidate(
    validation_metrics: dict[str, Any],
    epoch: int,
    objective: str,
    min_recall: float,
    max_fpr: float,
) -> dict[str, Any]:
    if objective not in CHECKPOINT_OBJECTIVES:
        raise ValueError(f"unsupported checkpoint objective: {objective}")

    candidates = [validation_metrics, *validation_metrics.get("threshold_sweep", [])]
    scored_candidates = [
        build_checkpoint_candidate(metrics, epoch, objective, min_recall, max_fpr)
        for metrics in candidates
    ]
    return max(scored_candidates, key=_checkpoint_sort_key)


def build_checkpoint_candidate(
    metrics: dict[str, Any],
    epoch: int,
    objective: str,
    min_recall: float,
    max_fpr: float,
) -> dict[str, Any]:
    recall = _metric_value(metrics.get("dangerous_recall"))
    fpr = _metric_value(metrics.get("false_positive_rate"))
    accuracy = _metric_value(metrics.get("accuracy"))
    precision = metrics.get("precision")
    constraints_met = recall >= min_recall and fpr <= max_fpr
    if objective == "dangerous_recall":
        score = recall
    else:
        score = (
            (1.0 if constraints_met else 0.0)
            + recall
            - (2.0 * max(0.0, min_recall - recall))
            - (2.0 * max(0.0, fpr - max_fpr))
            - (0.05 * fpr)
        )

    return {
        "epoch": epoch,
        "objective": objective,
        "score": score,
        "constraints_met": constraints_met,
        "min_recall": min_recall,
        "max_fpr": max_fpr,
        "threshold": metrics.get("threshold"),
        "accuracy": metrics.get("accuracy"),
        "precision": precision,
        "dangerous_recall": metrics.get("dangerous_recall"),
        "false_positive_rate": metrics.get("false_positive_rate"),
        "confusion": metrics.get("confusion"),
    }


def build_prediction_records(
    examples: list[TrainingExample],
    probabilities: list[float],
    threshold: float,
    preview_chars: int = DEFAULT_TEXT_PREVIEW_CHARS,
) -> list[dict[str, Any]]:
    if len(examples) != len(probabilities):
        raise ValueError("examples and probabilities must have the same length")

    records: list[dict[str, Any]] = []
    for example, probability in zip(examples, probabilities):
        prediction = 1 if probability >= threshold else 0
        records.append(
            {
                "id": example.id,
                "label": example.label,
                "prediction": prediction,
                "probability": probability,
                "threshold": threshold,
                "error_type": _error_type(example.label, prediction),
                "source": example.source,
                "risk_category": example.risk_category,
                "text_preview": " ".join(example.text.split())[:preview_chars],
            }
        )
    return records


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def parse_thresholds(value: str) -> list[float]:
    thresholds: list[float] = []
    for raw_part in value.split(","):
        part = raw_part.strip()
        if not part:
            continue
        try:
            threshold = float(part)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"invalid threshold {part!r}") from exc
        if threshold < 0.0 or threshold > 1.0:
            raise argparse.ArgumentTypeError(f"threshold must be between 0 and 1: {threshold}")
        thresholds.append(threshold)
    if not thresholds:
        raise argparse.ArgumentTypeError("at least one threshold is required")
    return thresholds


def train(args: argparse.Namespace) -> dict[str, Any]:
    torch, transformers = _load_training_dependencies()
    set_seed(args.seed, torch=torch)

    tokenizer = transformers.AutoTokenizer.from_pretrained(args.model_name)
    model = transformers.AutoModelForSequenceClassification.from_pretrained(args.model_name, num_labels=2)
    device = _select_device(args.device, torch)
    model.to(device)

    train_examples = rows_to_examples(load_jsonl(args.train_path), limit=args.smoke_limit)
    validation_examples = rows_to_examples(load_jsonl(args.validation_path), limit=args.smoke_limit)
    eval_examples = rows_to_examples(load_jsonl(args.eval_path), limit=args.smoke_limit)

    train_dataset = _build_dataset(train_examples, tokenizer, args.max_length, torch)
    validation_dataset = _build_dataset(validation_examples, tokenizer, args.max_length, torch)
    eval_dataset = _build_dataset(eval_examples, tokenizer, args.max_length, torch)

    train_loader = torch.utils.data.DataLoader(train_dataset, batch_size=args.batch_size, shuffle=True)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.learning_rate)

    history: list[dict[str, Any]] = []
    best_checkpoint: dict[str, Any] | None = None
    best_state: dict[str, Any] | None = None

    for epoch in range(1, args.epochs + 1):
        model.train()
        total_loss = 0.0
        for batch in train_loader:
            optimizer.zero_grad()
            batch = {key: value.to(device) for key, value in batch.items()}
            outputs = model(**batch)
            loss = outputs.loss
            loss.backward()
            optimizer.step()
            total_loss += float(loss.detach().cpu())

        validation_metrics = evaluate_model(
            model,
            validation_dataset,
            validation_examples,
            args.batch_size,
            args.threshold,
            args.thresholds,
            device,
            torch,
        )
        checkpoint_candidate = select_checkpoint_candidate(
            validation_metrics,
            epoch,
            args.checkpoint_objective,
            args.checkpoint_min_recall,
            args.checkpoint_max_fpr,
        )
        epoch_report = {
            "epoch": epoch,
            "train_loss": total_loss / max(1, len(train_loader)),
            "validation": validation_metrics,
            "checkpoint_candidate": checkpoint_candidate,
        }
        history.append(epoch_report)
        print(json.dumps(epoch_report, indent=2, sort_keys=True))

        if best_checkpoint is None or _checkpoint_sort_key(checkpoint_candidate) > _checkpoint_sort_key(best_checkpoint):
            best_checkpoint = checkpoint_candidate
            best_state = {key: value.detach().cpu().clone() for key, value in model.state_dict().items()}

    if best_state is not None:
        model.load_state_dict(best_state)

    eval_labels, eval_probabilities = collect_model_outputs(model, eval_dataset, args.batch_size, device, torch)
    eval_metrics = compute_evaluation_metrics(
        eval_labels,
        eval_probabilities,
        args.threshold,
        args.thresholds,
        examples=eval_examples,
    )
    prediction_output_path = args.eval_predictions_path
    if prediction_output_path is None and args.output_dir:
        prediction_output_path = args.output_dir / "eval_predictions.jsonl"

    final_report = {
        "model_name": args.model_name,
        "device": str(device),
        "train_rows": len(train_examples),
        "validation_rows": len(validation_examples),
        "eval_rows": len(eval_examples),
        "epochs": args.epochs,
        "checkpoint_selection": {
            "objective": args.checkpoint_objective,
            "min_recall": args.checkpoint_min_recall,
            "max_fpr": args.checkpoint_max_fpr,
            "selected": best_checkpoint,
        },
        "history": history,
        "eval": eval_metrics,
    }

    if prediction_output_path:
        write_jsonl(
            prediction_output_path,
            build_prediction_records(eval_examples, eval_probabilities, args.threshold),
        )
        final_report["eval_predictions_path"] = str(prediction_output_path)

    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        model.save_pretrained(args.output_dir)
        tokenizer.save_pretrained(args.output_dir)
        (args.output_dir / "training_report.json").write_text(json.dumps(final_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return final_report


def evaluate_model(
    model: Any,
    dataset: Any,
    examples: list[TrainingExample],
    batch_size: int,
    threshold: float,
    thresholds: list[float],
    device: Any,
    torch: Any,
) -> dict[str, Any]:
    labels, probabilities = collect_model_outputs(model, dataset, batch_size, device, torch)
    return compute_evaluation_metrics(labels, probabilities, threshold, thresholds, examples=examples)


def collect_model_outputs(
    model: Any,
    dataset: Any,
    batch_size: int,
    device: Any,
    torch: Any,
) -> tuple[list[int], list[float]]:
    loader = torch.utils.data.DataLoader(dataset, batch_size=batch_size)
    labels: list[int] = []
    probabilities: list[float] = []

    model.eval()
    with torch.no_grad():
        for batch in loader:
            batch = {key: value.to(device) for key, value in batch.items()}
            batch_labels = batch.pop("labels")
            outputs = model(**batch)
            probs = torch.softmax(outputs.logits, dim=-1)[:, 1]
            labels.extend(int(value) for value in batch_labels.detach().cpu().tolist())
            probabilities.extend(float(value) for value in probs.detach().cpu().tolist())

    return labels, probabilities


def set_seed(seed: int, torch: Any | None = None) -> None:
    random.seed(seed)
    if torch is not None:
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train-path", type=Path, default=DEFAULT_TRAIN_PATH)
    parser.add_argument("--validation-path", type=Path, default=DEFAULT_VALIDATION_PATH)
    parser.add_argument("--eval-path", type=Path, default=DEFAULT_EVAL_PATH)
    parser.add_argument("--model-name", default=DEFAULT_MODEL)
    parser.add_argument("--output-dir", type=Path, default=Path("models/sentinel-distilbert"))
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=2e-5)
    parser.add_argument("--max-length", type=int, default=384)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument(
        "--thresholds",
        type=parse_thresholds,
        default=list(DEFAULT_THRESHOLDS),
        help="Comma-separated thresholds to report for calibration, for example: 0.2,0.3,0.4,0.5,0.6,0.7.",
    )
    parser.add_argument(
        "--eval-predictions-path",
        type=Path,
        default=None,
        help="Optional JSONL path for per-example eval predictions. Defaults to OUTPUT_DIR/eval_predictions.jsonl.",
    )
    parser.add_argument(
        "--checkpoint-objective",
        choices=CHECKPOINT_OBJECTIVES,
        default=DEFAULT_CHECKPOINT_OBJECTIVE,
        help="Validation objective for choosing which epoch checkpoint to save.",
    )
    parser.add_argument(
        "--checkpoint-min-recall",
        type=float,
        default=DEFAULT_CHECKPOINT_MIN_RECALL,
        help="Target dangerous recall for bounded-FPR checkpoint selection.",
    )
    parser.add_argument(
        "--checkpoint-max-fpr",
        type=float,
        default=DEFAULT_CHECKPOINT_MAX_FPR,
        help="Target false positive rate ceiling for bounded-FPR checkpoint selection.",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--device", choices=("auto", "cpu", "cuda", "mps"), default="auto")
    parser.add_argument("--smoke-limit", type=int, default=None, help="Limit rows per split for quick Mac/CPU smoke runs.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report = train(args)
    except ImportError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _build_dataset(examples: list[TrainingExample], tokenizer: Any, max_length: int, torch: Any) -> Any:
    encodings = tokenizer(
        [example.text for example in examples],
        truncation=True,
        padding=True,
        max_length=max_length,
        return_tensors="pt",
    )
    labels = torch.tensor([example.label for example in examples], dtype=torch.long)

    class EncodedDataset(torch.utils.data.Dataset):  # type: ignore[name-defined]
        def __len__(self) -> int:
            return len(labels)

        def __getitem__(self, index: int) -> dict[str, Any]:
            item = {key: value[index] for key, value in encodings.items()}
            item["labels"] = labels[index]
            return item

    return EncodedDataset()


def _load_training_dependencies() -> tuple[Any, Any]:
    try:
        import torch
        import transformers
    except ImportError as exc:
        raise ImportError(
            "Training requires PyTorch and Transformers. Install them in your training environment, "
            "for example: python3 -m pip install torch transformers"
        ) from exc
    return torch, transformers


def _select_device(requested: str, torch: Any) -> Any:
    if requested == "cuda":
        if not torch.cuda.is_available():
            raise RuntimeError("CUDA requested but torch.cuda.is_available() is false")
        return torch.device("cuda")
    if requested == "mps":
        if not getattr(torch.backends, "mps", None) or not torch.backends.mps.is_available():
            raise RuntimeError("MPS requested but torch.backends.mps.is_available() is false")
        return torch.device("mps")
    if requested == "cpu":
        return torch.device("cpu")
    if torch.cuda.is_available():
        return torch.device("cuda")
    if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")


def _safe_ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def _metric_value(value: Any) -> float:
    if value is None:
        return 0.0
    return float(value)


def _checkpoint_sort_key(candidate: dict[str, Any]) -> tuple[float, float, float, float]:
    return (
        float(candidate["score"]),
        _metric_value(candidate.get("dangerous_recall")),
        -_metric_value(candidate.get("false_positive_rate")),
        _metric_value(candidate.get("accuracy")),
    )


def _error_type(label: int, prediction: int) -> str:
    if label == 1 and prediction == 0:
        return "false_negative"
    if label == 0 and prediction == 1:
        return "false_positive"
    if label == 1 and prediction == 1:
        return "true_positive"
    return "true_negative"


if __name__ == "__main__":
    raise SystemExit(main())
