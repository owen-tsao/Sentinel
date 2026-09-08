#!/usr/bin/env python3
"""Export a local Sentinel DistilBERT checkpoint to ONNX."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinel.ml.inference import (
    INPUT_FORMAT_VERSION,
    serving_threshold_binding_sha256,
    verify_checkpoint_artifact_hashes,
)


DEFAULT_MODEL_DIR = Path("models/sentinel-distilbert-mps-v2")
DEFAULT_OUTPUT_PATH = Path("models/sentinel-distilbert-onnx/model.onnx")
DEFAULT_MAX_LENGTH = 384
DEFAULT_OPSET = 17
TRAINING_METADATA_SCHEMA_VERSION = "sentinel-training-metadata-v1"
DEFAULT_SAMPLE_TEXT = "\n".join(
    [
        "Command: alembic current && alembic history --verbose",
        "Environment: production",
        "Context: Inspect production database migrations and report what would change without applying them.",
        "Recent actions:",
        "1. type=command; summary=Connected to production metadata for read-only migration inspection; sensitive_resources=production_database",
    ]
)


def export_onnx(
    model_dir: Path,
    output_path: Path,
    max_length: int,
    opset: int,
    sample_text: str = DEFAULT_SAMPLE_TEXT,
    thresholds_path: Path | None = None,
    calibration_dataset_path: Path | None = None,
) -> dict[str, Any]:
    training_report = load_training_report(model_dir / "training_report.json")
    validate_checkpoint_selection(training_report)
    validate_training_metadata(
        training_report,
        max_length=max_length,
        model_dir=model_dir,
    )
    calibrated_thresholds = load_calibrated_thresholds(
        thresholds_path,
        calibration_dataset_path,
    )
    if calibrated_thresholds is None:
        raise ValueError(
            "export requires human-reviewed calibrated thresholds; "
            "refusing to create an uncalibrated ONNX artifact"
        )
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
    onnx_sha256 = _file_sha256(output_path)

    metadata = build_export_metadata(
        model_dir=model_dir,
        output_path=output_path,
        max_length=max_length,
        opset=opset,
        input_names=input_names,
        sample_text=sample_text,
        training_report=training_report,
        calibrated_thresholds=calibrated_thresholds,
        onnx_sha256=onnx_sha256,
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
    training_report: dict[str, Any] | None = None,
    calibrated_thresholds: dict[str, Any] | None = None,
    onnx_sha256: str | None = None,
) -> dict[str, Any]:
    full_training_report = training_report or load_training_report(
        model_dir / "training_report.json"
    )
    training_metadata = validate_training_metadata(
        full_training_report,
        max_length=max_length,
        model_dir=model_dir,
    )
    validate_checkpoint_selection(full_training_report)
    if calibrated_thresholds is None:
        raise ValueError(
            "export requires human-reviewed calibrated thresholds; "
            "refusing to publish hardcoded serving defaults"
        )
    resolved_onnx_sha256 = onnx_sha256
    if resolved_onnx_sha256 is None and output_path.is_file():
        resolved_onnx_sha256 = _file_sha256(output_path)
    if not isinstance(resolved_onnx_sha256, str) or not _is_sha256(
        resolved_onnx_sha256.lower()
    ):
        raise ValueError(
            "export metadata requires the SHA-256 of the checked ONNX artifact"
        )
    return {
        "model_dir": str(model_dir),
        "onnx_path": str(output_path),
        "onnx_sha256": resolved_onnx_sha256.lower(),
        "opset": opset,
        "max_length": max_length,
        "input_format_version": INPUT_FORMAT_VERSION,
        "input_names": input_names,
        "output_names": ["logits"],
        "sample_text_preview": " ".join(sample_text.split())[:280],
        "training_metadata": training_metadata,
        "training_report": summarize_training_report(full_training_report),
        "thresholds": calibrated_thresholds,
        "serving_threshold_binding_sha256": (
            serving_threshold_binding_sha256(calibrated_thresholds)
        ),
        "serving_warning": (
            "This export is a serving artifact only. Sentinel should still run deterministic rules before model inference, "
            "and the model should not produce block decisions by itself."
        ),
    }


def load_training_report(report_path: Path) -> dict[str, Any]:
    if not report_path.exists():
        raise ValueError(
            f"{report_path}: export requires a training report that binds the checkpoint "
            "to its input formatter"
        )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise ValueError(f"{report_path}: expected JSON object")
    return report


def validate_training_metadata(
    report: dict[str, Any],
    *,
    max_length: int,
    model_dir: Path | None = None,
) -> dict[str, Any]:
    metadata = report.get("training_metadata")
    if not isinstance(metadata, dict):
        raise ValueError(
            "training report lacks training_metadata; refusing to stamp legacy "
            "checkpoint with the current formatter version"
        )
    if metadata.get("schema_version") != TRAINING_METADATA_SCHEMA_VERSION:
        raise ValueError("training metadata schema version is missing or unsupported")
    if metadata.get("input_format_version") != INPUT_FORMAT_VERSION:
        raise ValueError(
            "checkpoint input formatter does not match the exporter; retrain with "
            f"{INPUT_FORMAT_VERSION!r} before export"
        )
    if metadata.get("max_length") != max_length:
        raise ValueError(
            "export max_length does not match the value recorded during training"
        )
    tokenizer = metadata.get("tokenizer")
    if not isinstance(tokenizer, dict) or not all(
        str(tokenizer.get(field, "")).strip()
        for field in ("class", "name_or_path")
    ):
        raise ValueError("training metadata must identify the tokenizer")
    datasets = metadata.get("datasets")
    if not isinstance(datasets, dict):
        raise ValueError("training metadata must include dataset hashes")
    for split in ("train", "validation", "eval"):
        item = datasets.get(split)
        digest = item.get("sha256") if isinstance(item, dict) else None
        if (
            not isinstance(item, dict)
            or not str(item.get("path", "")).strip()
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest.lower())
        ):
            raise ValueError(
                f"training metadata requires a valid {split} dataset path and SHA-256"
            )
    if model_dir is not None:
        verify_checkpoint_artifact_hashes(
            model_dir,
            {"training_metadata": metadata},
        )
    return metadata


def validate_checkpoint_selection(report: dict[str, Any]) -> dict[str, Any]:
    checkpoint_selection = report.get("checkpoint_selection")
    selected = (
        checkpoint_selection.get("selected")
        if isinstance(checkpoint_selection, dict)
        else None
    )
    if not isinstance(selected, dict) or selected.get("constraints_met") is not True:
        raise ValueError(
            "export requires checkpoint_selection.selected.constraints_met=true"
        )
    return selected


def load_calibrated_thresholds(
    path: Path | None,
    calibration_dataset_path: Path | None,
) -> dict[str, Any] | None:
    if path is None:
        return None
    if calibration_dataset_path is None:
        raise ValueError(
            "calibrated thresholds require an explicit calibration dataset path"
        )
    if not calibration_dataset_path.is_file():
        raise ValueError(
            f"{calibration_dataset_path}: calibration dataset does not exist"
        )
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: calibrated thresholds must be a JSON object")
    bands = payload.get("policy_bands", payload)
    if not isinstance(bands, dict):
        raise ValueError(f"{path}: policy_bands must be a JSON object")
    try:
        warn = float(bands["warn_threshold"])
        confirm = float(bands["confirm_threshold"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            f"{path}: warn_threshold and confirm_threshold must be numbers"
        ) from exc
    if not 0.0 <= warn <= confirm <= 1.0:
        raise ValueError(
            f"{path}: thresholds must satisfy 0 <= warn <= confirm <= 1"
        )
    if bands.get("model_block") is not False:
        raise ValueError(f"{path}: model_block must be false")
    required_review_fields = (
        "reviewer_id",
        "reviewed_at",
        "review_policy_version",
        "calibration_dataset_sha256",
        "review_content_sha256",
    )
    missing_review_fields = [
        field
        for field in required_review_fields
        if not str(payload.get(field, "")).strip()
    ]
    if missing_review_fields:
        raise ValueError(
            f"{path}: calibrated thresholds require review fields "
            f"{', '.join(missing_review_fields)}"
        )
    review_status = str(payload.get("review_status", "")).strip()
    reviewer_id = str(payload["reviewer_id"]).strip()
    reviewed_at = str(payload["reviewed_at"]).strip()
    review_policy_version = str(payload["review_policy_version"]).strip()
    dataset_hash = str(payload["calibration_dataset_sha256"]).strip().lower()
    review_hash = str(payload["review_content_sha256"]).strip().lower()
    if review_status != "human_reviewed":
        raise ValueError(
            f"{path}: calibrated thresholds require review_status='human_reviewed'"
        )
    if not _is_sha256(dataset_hash):
        raise ValueError(
            f"{path}: calibration_dataset_sha256 must be a SHA-256 digest"
        )
    actual_dataset_hash = _file_sha256(calibration_dataset_path)
    if actual_dataset_hash != dataset_hash:
        raise ValueError(
            f"{path}: calibration dataset hash does not match "
            f"{calibration_dataset_path}"
        )
    try:
        datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"{path}: reviewed_at must be an ISO-8601 timestamp"
        ) from exc
    if not _is_sha256(review_hash):
        raise ValueError(
            f"{path}: review_content_sha256 must be a SHA-256 digest"
        )
    expected_review_hash = threshold_review_content_sha256(payload)
    if review_hash != expected_review_hash:
        raise ValueError(
            f"{path}: review_content_sha256 does not match review content"
        )
    return {
        "warn": warn,
        "confirm_required": confirm,
        "model_block": False,
        "review_status": review_status,
        "reviewer_id": reviewer_id,
        "reviewed_at": reviewed_at,
        "review_policy_version": review_policy_version,
        "calibration_dataset_sha256": dataset_hash,
        "review_content_sha256": review_hash,
    }


def threshold_review_content_sha256(payload: dict[str, Any]) -> str:
    review_content = {
        key: value
        for key, value in payload.items()
        if key not in {"review_status", "review_content_sha256"}
    }
    encoded = json.dumps(
        review_content,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def summarize_training_report(report: dict[str, Any]) -> dict[str, Any]:
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


def load_training_report_summary(report_path: Path) -> dict[str, Any] | None:
    if not report_path.exists():
        return None
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        return None
    return summarize_training_report(report)


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
    parser.add_argument(
        "--thresholds-path",
        type=Path,
        required=True,
        help=(
            "Human-reviewed calibration JSON with content-bound review metadata."
        ),
    )
    parser.add_argument(
        "--calibration-dataset-path",
        type=Path,
        required=True,
        help=(
            "Exact calibration dataset whose bytes must match the hash in the "
            "threshold review."
        ),
    )
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
            thresholds_path=args.thresholds_path,
            calibration_dataset_path=args.calibration_dataset_path,
        )
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(metadata, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
