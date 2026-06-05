"""ONNX Runtime inference wrapper for Sentinel command-risk scoring."""

from __future__ import annotations

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
    return "\n".join(
        [
            f"Context: {str(row.get('context', '')).strip()}",
            f"Recent actions:\n{format_recent_actions(row.get('recent_actions'))}",
            f"Environment: {str(row.get('environment', 'sandbox')).strip()}",
            f"Command: {str(row.get('command', '')).strip()}",
        ]
    )


class OnnxRiskModel:
    def __init__(
        self,
        *,
        onnx_path: Path = DEFAULT_ONNX_PATH,
        model_dir: Path = DEFAULT_MODEL_DIR,
        metadata_path: Path | None = None,
        warn_threshold: float = DEFAULT_WARN_THRESHOLD,
        confirm_threshold: float = DEFAULT_CONFIRM_THRESHOLD,
        max_length: int = DEFAULT_MAX_LENGTH,
        session: Any | None = None,
        tokenizer: Any | None = None,
    ) -> None:
        if warn_threshold > confirm_threshold:
            raise ValueError("warn_threshold must be <= confirm_threshold")

        self.onnx_path = onnx_path
        self.model_dir = model_dir
        self.metadata_path = metadata_path or onnx_path.with_suffix(".metadata.json")
        self.warn_threshold = warn_threshold
        self.confirm_threshold = confirm_threshold
        self.metadata = load_metadata(self.metadata_path)
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
