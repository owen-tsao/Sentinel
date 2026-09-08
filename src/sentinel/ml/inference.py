"""ONNX Runtime inference wrapper for Sentinel command-risk scoring."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal


ModelTier = Literal["allow", "warn", "confirm_required"]
DEFAULT_ONNX_PATH = Path("models/sentinel-distilbert-onnx/model.onnx")
DEFAULT_MODEL_DIR = Path("models/sentinel-distilbert-mps-v2")
DEFAULT_MAX_LENGTH = 384
DEFAULT_WARN_THRESHOLD = 0.20
DEFAULT_CONFIRM_THRESHOLD = 0.40
DEFAULT_INPUT_NAMES = ("attention_mask", "input_ids")
INPUT_FORMAT_VERSION = "sentinel-bounded-fields-v3"
MODEL_COMMAND_CHARS = 128
MODEL_CONTEXT_CHARS = 400
MODEL_HISTORY_ITEMS = 3
MODEL_HISTORY_FIELD_CHARS = 48
MODEL_HISTORY_TOTAL_CHARS = 160
TOKENIZER_VOCABULARY_ARTIFACTS = {"tokenizer.json", "vocab.txt"}
SERVING_THRESHOLD_BINDING_FIELDS = (
    "reviewer_id",
    "reviewed_at",
    "review_policy_version",
    "calibration_dataset_sha256",
    "review_content_sha256",
)


@dataclass(frozen=True)
class RiskPrediction:
    risk_probability: float
    model_tier: ModelTier
    threshold: dict[str, float]
    input_names: list[str]
    provider: str | None
    metadata: dict[str, Any]


def format_recent_actions(recent_actions: Any) -> str:
    if not isinstance(recent_actions, list) or not recent_actions:
        return "None"

    formatted: list[str] = []
    for index, action in enumerate(recent_actions[-MODEL_HISTORY_ITEMS:], start=1):
        if not isinstance(action, dict):
            formatted.append(
                f"{index}. {_head_tail_excerpt(str(action), MODEL_HISTORY_FIELD_CHARS)}"
            )
            continue
        summary = _head_tail_excerpt(
            str(action.get("summary", "")).strip() or "No summary",
            MODEL_HISTORY_FIELD_CHARS,
        )
        action_type = str(action.get("type", "unknown")).strip() or "unknown"
        resources = action.get("sensitive_resources", [])
        resources_text = (
            _head_tail_excerpt(
                ", ".join(str(resource) for resource in resources),
                MODEL_HISTORY_FIELD_CHARS,
            )
            if isinstance(resources, list) and resources
            else "none"
        )
        formatted.append(f"{index}. type={action_type}; summary={summary}; sensitive_resources={resources_text}")
    return _head_tail_excerpt(
        "\n".join(formatted),
        MODEL_HISTORY_TOTAL_CHARS,
    )


def row_to_text(row: dict[str, Any]) -> str:
    proposed_action = row.get("command") or row.get("action") or row.get("proposed_action") or ""
    if isinstance(proposed_action, dict):
        proposed_action = proposed_action.get("raw_command") or json.dumps(proposed_action, sort_keys=True)
    command_text = _head_tail_excerpt(str(proposed_action).strip(), MODEL_COMMAND_CHARS)
    context_text = _head_tail_excerpt(
        str(row.get("context", "")).strip(),
        MODEL_CONTEXT_CHARS,
    )
    return "\n".join(
        [
            # Security-relevant command suffixes and recent actions are bounded
            # before tokenization so long caller fields cannot crowd them out.
            f"Command: {command_text}",
            f"Environment: {str(row.get('environment', 'sandbox')).strip()}",
            f"Recent actions:\n{format_recent_actions(row.get('recent_actions'))}",
            f"Context: {context_text}",
        ]
    )


def _head_tail_excerpt(value: str, maximum_chars: int) -> str:
    if len(value) <= maximum_chars:
        return value
    marker = " …[middle omitted]… "
    remaining = maximum_chars - len(marker)
    left = remaining // 2
    right = remaining - left
    return f"{value[:left]}{marker}{value[-right:]}"


class OnnxRiskModel:
    def __init__(
        self,
        *,
        onnx_path: Path = DEFAULT_ONNX_PATH,
        model_dir: Path = DEFAULT_MODEL_DIR,
        metadata_path: Path | None = None,
        warn_threshold: float | None = None,
        confirm_threshold: float | None = None,
        max_length: int = DEFAULT_MAX_LENGTH,
        session: Any | None = None,
        tokenizer: Any | None = None,
    ) -> None:
        self.onnx_path = onnx_path
        self.model_dir = model_dir
        self.metadata_path = metadata_path or onnx_path.with_suffix(".metadata.json")
        self.metadata = load_metadata(self.metadata_path)
        metadata_thresholds = load_thresholds(self.metadata)
        self.warn_threshold = (
            warn_threshold
            if warn_threshold is not None
            else metadata_thresholds.get("warn", DEFAULT_WARN_THRESHOLD)
        )
        self.confirm_threshold = (
            confirm_threshold
            if confirm_threshold is not None
            else metadata_thresholds.get(
                "confirm_required",
                DEFAULT_CONFIRM_THRESHOLD,
            )
        )
        if not 0.0 <= self.warn_threshold <= self.confirm_threshold <= 1.0:
            raise ValueError(
                "thresholds must satisfy 0 <= warn_threshold <= "
                "confirm_threshold <= 1"
            )
        input_format_version = self.metadata.get("input_format_version")
        if self.onnx_path.exists() and input_format_version != INPUT_FORMAT_VERSION:
            raise ValueError(
                "ONNX model metadata is missing the current bounded-field input format; "
                "retrain and re-export before serving this model."
            )
        if self.onnx_path.exists() and {
            "warn",
            "confirm_required",
        } - metadata_thresholds.keys():
            raise ValueError(
                "ONNX model metadata lacks reviewed serving thresholds; "
                "recalibrate before serving this model."
            )
        if self.onnx_path.exists() and (
            (
                warn_threshold is not None
                and warn_threshold != metadata_thresholds["warn"]
            )
            or (
                confirm_threshold is not None
                and confirm_threshold
                != metadata_thresholds["confirm_required"]
            )
        ):
            raise ValueError(
                "runtime thresholds must match the reviewed ONNX metadata "
                "threshold binding"
            )
        if self.onnx_path.exists():
            verify_onnx_sha256(self.onnx_path, self.metadata)
            verify_checkpoint_artifact_hashes(
                self.model_dir,
                self.metadata,
            )
            verify_serving_threshold_binding(self.metadata)
        self.max_length = int(self.metadata.get("max_length", max_length))
        self.input_names = list(self.metadata.get("input_names", DEFAULT_INPUT_NAMES))
        self.session = session if session is not None else load_onnx_session(onnx_path)
        self.tokenizer = tokenizer if tokenizer is not None else load_tokenizer(model_dir)

    def predict_row(self, row: dict[str, Any]) -> RiskPrediction:
        return self.predict_text(row_to_text(row))

    def predict_text(self, text: str) -> RiskPrediction:
        encoded = self.tokenizer(
            text,
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
            return_tensors="np",
        )
        feed = {name: encoded[name] for name in self.input_names if name in encoded}
        missing_inputs = [name for name in self.input_names if name not in feed]
        if missing_inputs:
            raise ValueError(f"tokenizer did not return required ONNX inputs: {missing_inputs}")

        logits = self.session.run(["logits"], feed)[0]
        risk_probability = positive_class_probability(logits[0])
        return RiskPrediction(
            risk_probability=risk_probability,
            model_tier=tier_for_probability(risk_probability, self.warn_threshold, self.confirm_threshold),
            threshold={"warn": self.warn_threshold, "confirm_required": self.confirm_threshold},
            input_names=self.input_names,
            provider=current_provider(self.session),
            metadata=self.metadata,
        )


def positive_class_probability(logits: Any) -> float:
    values = [float(value) for value in logits]
    if len(values) < 2:
        raise ValueError("expected at least two logits for binary risk classification")
    max_logit = max(values)
    exp_values = [math.exp(value - max_logit) for value in values]
    denominator = sum(exp_values)
    return exp_values[1] / denominator


def tier_for_probability(probability: float, warn_threshold: float, confirm_threshold: float) -> ModelTier:
    if probability >= confirm_threshold:
        return "confirm_required"
    if probability >= warn_threshold:
        return "warn"
    return "allow"


def load_metadata(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    metadata = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(metadata, dict):
        raise ValueError(f"{path}: expected JSON object")
    return metadata


def load_thresholds(metadata: dict[str, Any]) -> dict[str, float]:
    value = metadata.get("thresholds")
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("ONNX metadata thresholds must be an object")
    try:
        warn = float(value["warn"])
        confirm = float(value["confirm_required"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            "ONNX metadata thresholds require numeric warn and confirm_required values"
        ) from exc
    if not 0.0 <= warn <= confirm <= 1.0:
        raise ValueError(
            "ONNX metadata thresholds must satisfy 0 <= warn <= confirm_required <= 1"
        )
    if value.get("model_block") is not False:
        raise ValueError(
            "ONNX metadata must explicitly keep model_block false"
        )
    return {"warn": warn, "confirm_required": confirm}


def serving_threshold_binding_sha256(
    thresholds: dict[str, Any],
) -> str:
    """Bind reviewed serving thresholds to their local review evidence."""

    try:
        normalized: dict[str, Any] = {
            "warn": float(thresholds["warn"]),
            "confirm_required": float(thresholds["confirm_required"]),
            "model_block": thresholds["model_block"],
            **{
                field: str(thresholds[field]).strip()
                for field in SERVING_THRESHOLD_BINDING_FIELDS
            },
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            "serving threshold binding requires normalized thresholds and "
            "complete review evidence"
        ) from exc
    if normalized["model_block"] is not False:
        raise ValueError(
            "serving threshold binding requires model_block false"
        )
    for field in SERVING_THRESHOLD_BINDING_FIELDS:
        if not normalized[field]:
            raise ValueError(
                f"serving threshold binding requires {field}"
            )
    encoded = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def verify_serving_threshold_binding(metadata: dict[str, Any]) -> str:
    thresholds = metadata.get("thresholds")
    expected = metadata.get("serving_threshold_binding_sha256")
    if not isinstance(thresholds, dict) or not _is_sha256(expected):
        raise ValueError(
            "ONNX metadata requires a valid serving threshold binding digest"
        )
    actual = serving_threshold_binding_sha256(thresholds)
    if actual != expected.lower():
        raise ValueError(
            "ONNX serving threshold binding does not match its reviewed "
            "threshold metadata"
        )
    return actual


def verify_checkpoint_artifact_hashes(
    model_dir: Path,
    metadata: dict[str, Any],
) -> dict[str, str]:
    training_metadata = metadata.get("training_metadata")
    artifact_hashes = (
        training_metadata.get("checkpoint_artifact_sha256")
        if isinstance(training_metadata, dict)
        else None
    )
    if not isinstance(artifact_hashes, dict) or not artifact_hashes:
        raise ValueError(
            "ONNX metadata must bind checkpoint and tokenizer artifact hashes"
        )
    required = {"config.json", "tokenizer_config.json"}
    missing = required - artifact_hashes.keys()
    if missing:
        raise ValueError(
            "checkpoint artifact hashes must include "
            + ", ".join(sorted(missing))
        )
    if not (
        {"model.safetensors", "pytorch_model.bin"} & artifact_hashes.keys()
    ):
        raise ValueError(
            "checkpoint artifact hashes must include model weights"
        )
    if not (TOKENIZER_VOCABULARY_ARTIFACTS & artifact_hashes.keys()):
        raise ValueError(
            "checkpoint artifact hashes must include a tokenizer vocabulary "
            "artifact"
        )

    verified: dict[str, str] = {}
    for filename, expected in artifact_hashes.items():
        if (
            not isinstance(filename, str)
            or Path(filename).name != filename
            or not _is_sha256(expected)
        ):
            raise ValueError("invalid checkpoint artifact hash metadata")
        artifact_path = model_dir / filename
        if not artifact_path.is_file():
            raise ValueError(f"checkpoint artifact is missing: {filename}")
        actual = _file_sha256(artifact_path)
        if actual != expected.lower():
            raise ValueError(
                f"checkpoint artifact hash mismatch: {filename}"
            )
        verified[filename] = actual
    return verified


def verify_onnx_sha256(
    onnx_path: Path,
    metadata: dict[str, Any],
) -> str:
    expected = metadata.get("onnx_sha256")
    if (
        not isinstance(expected, str)
        or len(expected) != 64
        or any(
            character not in "0123456789abcdef"
            for character in expected.lower()
        )
    ):
        raise ValueError(
            "ONNX model metadata requires a valid onnx_sha256"
        )
    digest = hashlib.sha256()
    with onnx_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != expected.lower():
        raise ValueError(
            "ONNX model hash does not match metadata; the serving artifact "
            "may have been swapped or corrupted"
        )
    return actual


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(
            character in "0123456789abcdef"
            for character in value.lower()
        )
    )


def load_onnx_session(path: Path) -> Any:
    try:
        import onnxruntime as ort
    except ImportError as exc:
        raise ImportError(
            "ONNX inference requires ONNX Runtime. Install it with `python3 -m pip install onnxruntime`."
        ) from exc
    return ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])


def load_tokenizer(model_dir: Path) -> Any:
    try:
        from transformers import AutoTokenizer
    except ImportError as exc:
        raise ImportError(
            "ONNX inference requires Transformers for tokenization. Install it with `python3 -m pip install transformers`."
        ) from exc
    return AutoTokenizer.from_pretrained(model_dir)


def current_provider(session: Any) -> str | None:
    providers = session.get_providers() if hasattr(session, "get_providers") else []
    if not providers:
        return None
    return str(providers[0])
