from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sentinel.ml.inference import OnnxRiskModel, positive_class_probability, row_to_text, tier_for_probability  # noqa: E402

TRAIN_MODULE_PATH = ROOT / "scripts" / "train_guardrail.py"
SPEC = importlib.util.spec_from_file_location("train_guardrail", TRAIN_MODULE_PATH)
assert SPEC is not None
train_guardrail = importlib.util.module_from_spec(SPEC)
sys.modules["train_guardrail"] = train_guardrail
assert SPEC.loader is not None
SPEC.loader.exec_module(train_guardrail)


class FakeTokenizer:
    def __call__(self, text: str, **kwargs: object) -> dict[str, list[list[int]]]:
        self.text = text
        self.kwargs = kwargs
        return {
            "attention_mask": [[1, 1, 0]],
            "input_ids": [[101, 102, 0]],
        }


class FakeSession:
    def __init__(self, logits: list[list[float]]) -> None:
        self.logits = logits
        self.feed: dict[str, object] | None = None

    def run(self, output_names: list[str], feed: dict[str, object]) -> list[list[list[float]]]:
        self.output_names = output_names
        self.feed = feed
        return [self.logits]

    def get_providers(self) -> list[str]:
        return ["CPUExecutionProvider"]


class OnnxInferenceTests(unittest.TestCase):
    def test_row_to_text_matches_training_format(self) -> None:
        row = {
            "context": "Inspect production migrations without applying them.",
            "recent_actions": [
                {
                    "type": "command",
                    "summary": "Connected to production metadata.",
                    "sensitive_resources": ["production_database"],
                }
            ],
            "environment": "production",
            "command": "alembic upgrade head",
        }

        self.assertEqual(row_to_text(row), train_guardrail.row_to_text(row))

    def test_positive_class_probability_uses_softmax(self) -> None:
        probability = positive_class_probability([0.0, 2.0])

        self.assertGreater(probability, 0.88)
        self.assertLess(probability, 0.89)

    def test_tier_for_probability_uses_provisional_bands(self) -> None:
        self.assertEqual(tier_for_probability(0.1, 0.2, 0.4), "allow")
        self.assertEqual(tier_for_probability(0.2, 0.2, 0.4), "warn")
        self.assertEqual(tier_for_probability(0.4, 0.2, 0.4), "confirm_required")

    def test_predict_row_returns_probability_tier_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            metadata_path = Path(tmpdir) / "model.metadata.json"
            metadata_path.write_text(
                json.dumps(
                    {
                        "input_names": ["attention_mask", "input_ids"],
                        "max_length": 3,
                        "serving_warning": "rules first",
                    }
                ),
                encoding="utf-8",
            )
            session = FakeSession(logits=[[0.0, 2.0]])
            tokenizer = FakeTokenizer()
            model = OnnxRiskModel(
                onnx_path=Path(tmpdir) / "model.onnx",
                model_dir=Path(tmpdir),
                metadata_path=metadata_path,
                session=session,
                tokenizer=tokenizer,
            )

            prediction = model.predict_row(
                {
                    "context": "Inspect files.",
                    "recent_actions": [],
                    "environment": "sandbox",
                    "command": "ls -la",
                }
            )

        self.assertEqual(prediction.model_tier, "confirm_required")
        self.assertGreater(prediction.risk_probability, 0.88)
        self.assertEqual(prediction.provider, "CPUExecutionProvider")
        self.assertEqual(prediction.input_names, ["attention_mask", "input_ids"])
        self.assertEqual(prediction.metadata["serving_warning"], "rules first")
        self.assertEqual(session.feed, {"attention_mask": [[1, 1, 0]], "input_ids": [[101, 102, 0]]})
        self.assertEqual(tokenizer.kwargs["max_length"], 3)

    def test_warn_threshold_must_not_exceed_confirm_threshold(self) -> None:
        with self.assertRaises(ValueError):
            OnnxRiskModel(
                warn_threshold=0.5,
                confirm_threshold=0.4,
                session=FakeSession(logits=[[0.0, 1.0]]),
                tokenizer=FakeTokenizer(),
            )


if __name__ == "__main__":
    unittest.main()
