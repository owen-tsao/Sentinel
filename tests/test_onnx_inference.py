from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sentinel.ml.inference import (  # noqa: E402
    INPUT_FORMAT_VERSION,
    OnnxRiskModel,
    positive_class_probability,
    row_to_text,
    serving_threshold_binding_sha256,
    tier_for_probability,
)

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


def bind_serving_integrity(
    root: Path,
    metadata: dict[str, object],
) -> None:
    artifacts = {
        "config.json": b'{"model_type":"distilbert"}',
        "model.safetensors": b"weights",
        "tokenizer_config.json": b'{"tokenizer_class":"DistilBertTokenizerFast"}',
        "tokenizer.json": b'{"version":"1.0"}',
    }
    for filename, content in artifacts.items():
        (root / filename).write_bytes(content)
    metadata["training_metadata"] = {
        "checkpoint_artifact_sha256": {
            filename: hashlib.sha256(content).hexdigest()
            for filename, content in artifacts.items()
        }
    }
    thresholds = metadata.get("thresholds")
    assert isinstance(thresholds, dict)
    thresholds.update(
        {
            "review_status": "human_reviewed",
            "reviewer_id": "reviewer-1",
            "reviewed_at": "2026-09-08T10:00:00-07:00",
            "review_policy_version": "sentinel-threshold-policy-v1",
            "calibration_dataset_sha256": "b" * 64,
            "review_content_sha256": "d" * 64,
        }
    )
    metadata["serving_threshold_binding_sha256"] = (
        serving_threshold_binding_sha256(thresholds)
    )


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
        self.assertEqual(INPUT_FORMAT_VERSION, train_guardrail.INPUT_FORMAT_VERSION)

    def test_row_to_text_puts_action_before_long_context_and_history(self) -> None:
        row = {
            "context": "Long context " * 1_000,
            "recent_actions": [{"type": "command", "summary": "history " * 100, "sensitive_resources": []}],
            "environment": "production",
            "proposed_action": {"raw_command": "rm -rf ./customer-exports"},
        }

        serving_text = row_to_text(row)

        self.assertTrue(serving_text.startswith("Command: rm -rf ./customer-exports\nEnvironment: production\n"))
        self.assertLess(serving_text.index("Command:"), serving_text.index("Context:"))
        self.assertLess(serving_text.index("Command:"), serving_text.index("Recent actions:"))
        self.assertEqual(serving_text, train_guardrail.row_to_text(row))

    def test_long_command_keeps_dangerous_suffix_and_recent_history(self) -> None:
        row = {
            "context": "context " * 2_000,
            "recent_actions": [
                {
                    "type": "command",
                    "summary": f"history-{index} " * 200,
                    "sensitive_resources": [f"/workspace/resource-{index}"],
                }
                for index in range(5)
            ],
            "environment": "production",
            "command": ("inspect-safe-file " * 1_000) + "rm -rf /",
        }

        text = row_to_text(row)

        self.assertIn("rm -rf /", text)
        self.assertIn("/workspace/resource-4", text)
        self.assertNotIn("/workspace/resource-0", text)
        self.assertIn("[middle omitted]", text)
        self.assertEqual(text, train_guardrail.row_to_text(row))

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
                        "thresholds": {
                            "warn": 0.7,
                            "confirm_required": 0.8,
                            "model_block": False,
                        },
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
        self.assertEqual(
            prediction.threshold,
            {"warn": 0.7, "confirm_required": 0.8},
        )
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

    def test_invalid_metadata_thresholds_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            metadata_path = Path(tmpdir) / "model.metadata.json"
            metadata_path.write_text(
                json.dumps(
                    {
                        "thresholds": {
                            "warn": 0.8,
                            "confirm_required": 0.4,
                        }
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "must satisfy"):
                OnnxRiskModel(
                    onnx_path=Path(tmpdir) / "model.onnx",
                    metadata_path=metadata_path,
                    session=FakeSession(logits=[[0.0, 1.0]]),
                    tokenizer=FakeTokenizer(),
                )

    def test_metadata_must_explicitly_disable_model_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            metadata_path = Path(tmpdir) / "model.metadata.json"
            metadata_path.write_text(
                json.dumps(
                    {
                        "thresholds": {
                            "warn": 0.2,
                            "confirm_required": 0.4,
                        }
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "model_block false"):
                OnnxRiskModel(
                    onnx_path=Path(tmpdir) / "model.onnx",
                    metadata_path=metadata_path,
                    session=FakeSession(logits=[[0.0, 1.0]]),
                    tokenizer=FakeTokenizer(),
                )

    def test_existing_model_with_legacy_input_format_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            onnx_path = Path(tmpdir) / "model.onnx"
            onnx_path.write_bytes(b"placeholder")
            metadata_path = onnx_path.with_suffix(".metadata.json")
            metadata_path.write_text(
                json.dumps({"max_length": 384, "input_names": ["attention_mask", "input_ids"]}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "retrain and re-export"):
                OnnxRiskModel(
                    onnx_path=onnx_path,
                    metadata_path=metadata_path,
                    session=FakeSession(logits=[[0.0, 1.0]]),
                    tokenizer=FakeTokenizer(),
                )

    def test_existing_model_without_reviewed_thresholds_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            onnx_path = Path(tmpdir) / "model.onnx"
            onnx_path.write_bytes(b"placeholder")
            metadata_path = onnx_path.with_suffix(".metadata.json")
            metadata_path.write_text(
                json.dumps(
                    {
                        "input_format_version": INPUT_FORMAT_VERSION,
                        "max_length": 384,
                        "input_names": ["attention_mask", "input_ids"],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "reviewed serving thresholds"):
                OnnxRiskModel(
                    onnx_path=onnx_path,
                    model_dir=Path(tmpdir),
                    metadata_path=metadata_path,
                    session=FakeSession(logits=[[0.0, 1.0]]),
                    tokenizer=FakeTokenizer(),
                )

    def test_existing_model_requires_matching_onnx_hash_before_session_use(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            onnx_path = Path(tmpdir) / "model.onnx"
            onnx_bytes = b"checked-model-bytes"
            onnx_path.write_bytes(onnx_bytes)
            metadata_path = onnx_path.with_suffix(".metadata.json")
            metadata = {
                "input_format_version": INPUT_FORMAT_VERSION,
                "onnx_sha256": hashlib.sha256(onnx_bytes).hexdigest(),
                "max_length": 384,
                "input_names": ["attention_mask", "input_ids"],
                "thresholds": {
                    "warn": 0.2,
                    "confirm_required": 0.4,
                    "model_block": False,
                },
            }
            bind_serving_integrity(Path(tmpdir), metadata)
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

            model = OnnxRiskModel(
                onnx_path=onnx_path,
                model_dir=Path(tmpdir),
                metadata_path=metadata_path,
                session=FakeSession(logits=[[0.0, 1.0]]),
                tokenizer=FakeTokenizer(),
            )
            self.assertEqual(model.metadata["onnx_sha256"], metadata["onnx_sha256"])

            onnx_path.write_bytes(b"tampered-model-bytes")
            with self.assertRaisesRegex(ValueError, "swapped or corrupted"):
                OnnxRiskModel(
                    onnx_path=onnx_path,
                    model_dir=Path(tmpdir),
                    metadata_path=metadata_path,
                    session=FakeSession(logits=[[0.0, 1.0]]),
                    tokenizer=FakeTokenizer(),
                )

    def test_existing_model_rejects_missing_or_swapped_hash_metadata(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            onnx_path = Path(tmpdir) / "model.onnx"
            onnx_path.write_bytes(b"model-a")
            metadata_path = onnx_path.with_suffix(".metadata.json")
            metadata = {
                "input_format_version": INPUT_FORMAT_VERSION,
                "max_length": 384,
                "input_names": ["attention_mask", "input_ids"],
                "thresholds": {
                    "warn": 0.2,
                    "confirm_required": 0.4,
                    "model_block": False,
                },
            }
            bind_serving_integrity(Path(tmpdir), metadata)
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "valid onnx_sha256"):
                OnnxRiskModel(
                    onnx_path=onnx_path,
                    metadata_path=metadata_path,
                    session=FakeSession(logits=[[0.0, 1.0]]),
                    tokenizer=FakeTokenizer(),
                )

            metadata["onnx_sha256"] = hashlib.sha256(b"model-b").hexdigest()
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "swapped or corrupted"):
                OnnxRiskModel(
                    onnx_path=onnx_path,
                    metadata_path=metadata_path,
                    session=FakeSession(logits=[[0.0, 1.0]]),
                    tokenizer=FakeTokenizer(),
                )

    def test_existing_model_rejects_swapped_tokenizer_before_session_use(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            onnx_path = root / "model.onnx"
            onnx_bytes = b"checked-model"
            onnx_path.write_bytes(onnx_bytes)
            metadata = {
                "input_format_version": INPUT_FORMAT_VERSION,
                "onnx_sha256": hashlib.sha256(onnx_bytes).hexdigest(),
                "thresholds": {
                    "warn": 0.2,
                    "confirm_required": 0.4,
                    "model_block": False,
                },
            }
            bind_serving_integrity(root, metadata)
            metadata_path = onnx_path.with_suffix(".metadata.json")
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            (root / "tokenizer.json").write_bytes(b"swapped-tokenizer")

            with self.assertRaisesRegex(
                ValueError,
                "checkpoint artifact hash mismatch: tokenizer.json",
            ):
                OnnxRiskModel(
                    onnx_path=onnx_path,
                    model_dir=root,
                    metadata_path=metadata_path,
                    session=FakeSession(logits=[[0.0, 1.0]]),
                    tokenizer=FakeTokenizer(),
                )

    def test_existing_model_rejects_thresholds_changed_after_export(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            onnx_path = root / "model.onnx"
            onnx_bytes = b"checked-model"
            onnx_path.write_bytes(onnx_bytes)
            metadata = {
                "input_format_version": INPUT_FORMAT_VERSION,
                "onnx_sha256": hashlib.sha256(onnx_bytes).hexdigest(),
                "thresholds": {
                    "warn": 0.2,
                    "confirm_required": 0.4,
                    "model_block": False,
                },
            }
            bind_serving_integrity(root, metadata)
            thresholds = metadata["thresholds"]
            assert isinstance(thresholds, dict)
            thresholds["warn"] = 0.3
            metadata_path = onnx_path.with_suffix(".metadata.json")
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError,
                "serving threshold binding",
            ):
                OnnxRiskModel(
                    onnx_path=onnx_path,
                    model_dir=root,
                    metadata_path=metadata_path,
                    session=FakeSession(logits=[[0.0, 1.0]]),
                    tokenizer=FakeTokenizer(),
                )

    def test_existing_model_rejects_unbound_runtime_threshold_override(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            onnx_path = root / "model.onnx"
            onnx_bytes = b"checked-model"
            onnx_path.write_bytes(onnx_bytes)
            metadata = {
                "input_format_version": INPUT_FORMAT_VERSION,
                "onnx_sha256": hashlib.sha256(onnx_bytes).hexdigest(),
                "thresholds": {
                    "warn": 0.2,
                    "confirm_required": 0.4,
                    "model_block": False,
                },
            }
            bind_serving_integrity(root, metadata)
            metadata_path = onnx_path.with_suffix(".metadata.json")
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError,
                "runtime thresholds",
            ):
                OnnxRiskModel(
                    onnx_path=onnx_path,
                    model_dir=root,
                    metadata_path=metadata_path,
                    warn_threshold=0.3,
                    session=FakeSession(logits=[[0.0, 1.0]]),
                    tokenizer=FakeTokenizer(),
                )


if __name__ == "__main__":
    unittest.main()
