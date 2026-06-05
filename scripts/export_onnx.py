#!/usr/bin/env python3
"""Export a local Sentinel DistilBERT checkpoint to ONNX."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_MODEL_DIR = Path("models/sentinel-distilbert-mps-v2")
DEFAULT_OUTPUT_PATH = Path("models/sentinel-distilbert-onnx/model.onnx")
DEFAULT_MAX_LENGTH = 384
DEFAULT_OPSET = 17
DEFAULT_SAMPLE_TEXT = "\n".join(
    [
        "Context: Inspect production database migrations and report what would change without applying them.",
        "Recent actions:",
        "1. type=command; summary=Connected to production metadata for read-only migration inspection; sensitive_resources=production_database",
        "Environment: production",
        "Command: alembic current && alembic history --verbose",
    ]
)


def export_onnx(
    model_dir: Path,
    output_path: Path,
    max_length: int,
    opset: int,
    sample_text: str = DEFAULT_SAMPLE_TEXT,
) -> dict[str, Any]:
    torch, transformers, onnx = load_export_dependencies()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    tokenizer = transformers.AutoTokenizer.from_pretrained(model_dir)
    model = transformers.AutoModelForSequenceClassification.from_pretrained(model_dir)
    model.eval()
    model.to("cpu")

    encoded = tokenizer(
        sample_text,
        truncation=True,
        padding="max_length",
        max_length=max_length,
        return_tensors="pt",
    )
    input_names = sorted(key for key in encoded if key in {"attention_mask", "input_ids", "token_type_ids"})
    inputs = tuple(encoded[name] for name in input_names)

    class LogitsWrapper(torch.nn.Module):  # type: ignore[name-defined]
        """Expose only logits so ONNX export does not need Transformers output objects."""

        def __init__(self, wrapped_model: Any, wrapped_input_names: list[str]) -> None:
            super().__init__()
            self.wrapped_model = wrapped_model
            self.wrapped_input_names = wrapped_input_names

        def forward(self, *forward_inputs: Any) -> Any:
            return self.wrapped_model(**dict(zip(self.wrapped_input_names, forward_inputs))).logits

    wrapper = LogitsWrapper(model, input_names)
    torch.onnx.export(
        wrapper,
        inputs,
        output_path,
        input_names=input_names,
        output_names=["logits"],
        dynamic_axes={
            **{name: {0: "batch_size", 1: "sequence_length"} for name in input_names},
            "logits": {0: "batch_size"},
        },
        opset_version=opset,
    )

    loaded_model = onnx.load(output_path)
    onnx.checker.check_model(loaded_model)

    metadata = build_export_metadata(
        model_dir=model_dir,
        output_path=output_path,
        max_length=max_length,
        opset=opset,
        input_names=input_names,
        sample_text=sample_text,
    )
    metadata_path = output_path.with_suffix(".metadata.json")
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return metadata


def build_export_metadata(
    model_dir: Path,
    output_path: Path,
    max_length: int,
    opset: int,
    input_names: list[str],
    sample_text: str,
) -> dict[str, Any]:
    report_path = model_dir / "training_report.json"
    training_report = load_training_report_summary(report_path)
    return {
        "model_dir": str(model_dir),
        "onnx_path": str(output_path),
        "opset": opset,
        "max_length": max_length,
        "input_names": input_names,
        "output_names": ["logits"],
        "sample_text_preview": " ".join(sample_text.split())[:280],
        "training_report": training_report,
        "serving_warning": (
            "This export is a serving artifact only. Sentinel should still run deterministic rules before model inference, "
            "and the model should not produce block decisions by itself."
        ),
    }


def load_training_report_summary(report_path: Path) -> dict[str, Any] | None:
    if not report_path.exists():
        return None
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        return None
    eval_metrics = report.get("eval", {})
    return {
        "device": report.get("device"),
        "epochs": report.get("epochs"),
        "eval_rows": report.get("eval_rows"),
        "checkpoint_selection": report.get("checkpoint_selection"),
        "eval": {
            "threshold": eval_metrics.get("threshold") if isinstance(eval_metrics, dict) else None,
            "accuracy": eval_metrics.get("accuracy") if isinstance(eval_metrics, dict) else None,
            "precision": eval_metrics.get("precision") if isinstance(eval_metrics, dict) else None,
            "dangerous_recall": eval_metrics.get("dangerous_recall") if isinstance(eval_metrics, dict) else None,
            "false_positive_rate": eval_metrics.get("false_positive_rate") if isinstance(eval_metrics, dict) else None,
            "confusion": eval_metrics.get("confusion") if isinstance(eval_metrics, dict) else None,
        },
    }


def load_export_dependencies() -> tuple[Any, Any, Any]:
    try:
        import onnx
        import torch
        import transformers
    except ImportError as exc:
        raise ImportError(
            "ONNX export requires PyTorch, Transformers, and ONNX. Install missing dependencies with "
            "`python3 -m pip install torch transformers onnx`."
        ) from exc
    return torch, transformers, onnx


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--output-path", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH)
    parser.add_argument("--opset", type=int, default=DEFAULT_OPSET)
    parser.add_argument("--sample-text", default=DEFAULT_SAMPLE_TEXT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        metadata = export_onnx(
            model_dir=args.model_dir,
            output_path=args.output_path,
            max_length=args.max_length,
            opset=args.opset,
            sample_text=args.sample_text,
        )
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(metadata, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
