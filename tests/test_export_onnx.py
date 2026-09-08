from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "export_onnx.py"
SPEC = importlib.util.spec_from_file_location("export_onnx", MODULE_PATH)
assert SPEC is not None
export_onnx = importlib.util.module_from_spec(SPEC)
sys.modules["export_onnx"] = export_onnx
assert SPEC.loader is not None
SPEC.loader.exec_module(export_onnx)


def make_training_report(
    *,
    input_format_version: str = export_onnx.INPUT_FORMAT_VERSION,
) -> dict[str, object]:
    dataset = {"path": "split.jsonl", "sha256": "a" * 64}
    return {
        "training_metadata": {
            "schema_version": "sentinel-training-metadata-v1",
            "input_format_version": input_format_version,
            "max_length": 384,
            "model_name": "distilbert-test",
            "tokenizer": {
                "class": "DistilBertTokenizerFast",
                "name_or_path": "distilbert-test",
            },
            "datasets": {
                "train": dataset,
                "validation": dataset,
                "eval": dataset,
            },
        },
        "device": "cpu",
        "epochs": 1,
        "eval_rows": 10,
        "checkpoint_selection": {
            "objective": "bounded_fpr",
            "selected": {"constraints_met": True},
        },
        "eval": {"threshold": 0.4},
    }


def write_bound_training_report(
    model_dir: Path,
    report: dict[str, object],
) -> None:
    artifacts = {
        "config.json": b'{"model_type":"distilbert"}',
        "model.safetensors": b"test-weights",
        "tokenizer_config.json": b'{"tokenizer_class":"DistilBertTokenizerFast"}',
        "tokenizer.json": b'{"version":"1.0"}',
    }
    for filename, content in artifacts.items():
        (model_dir / filename).write_bytes(content)
    training_metadata = report["training_metadata"]
    assert isinstance(training_metadata, dict)
    training_metadata["checkpoint_artifact_sha256"] = {
        filename: hashlib.sha256(content).hexdigest()
        for filename, content in artifacts.items()
    }
    (model_dir / "training_report.json").write_text(
        json.dumps(report),
        encoding="utf-8",
    )


def write_threshold_review(
    root: Path,
    *,
    dataset_bytes: bytes = b'{"id":"calibration-1"}\n',
) -> tuple[Path, Path, dict[str, object]]:
    dataset_path = root / "calibration.jsonl"
    dataset_path.write_bytes(dataset_bytes)
    review_path = root / "thresholds.json"
    payload: dict[str, object] = {
        "review_status": "human_reviewed",
        "reviewer_id": "reviewer-1",
        "reviewed_at": "2026-09-08T10:00:00-07:00",
        "review_policy_version": "sentinel-threshold-policy-v1",
        "calibration_dataset_sha256": hashlib.sha256(dataset_bytes).hexdigest(),
        "policy_bands": {
            "warn_threshold": 0.2,
            "confirm_threshold": 0.4,
            "model_block": False,
        },
    }
    payload["review_content_sha256"] = (
        export_onnx.threshold_review_content_sha256(payload)
    )
    review_path.write_text(json.dumps(payload), encoding="utf-8")
    return review_path, dataset_path, payload


class ExportOnnxTests(unittest.TestCase):
    def test_load_training_report_summary_extracts_serving_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "training_report.json"
            report_path.write_text(
                json.dumps(
                    {
                        "device": "mps",
                        "epochs": 5,
                        "eval_rows": 70,
                        "checkpoint_selection": {"objective": "bounded_fpr"},
                        "eval": {
                            "threshold": 0.5,
                            "accuracy": 0.8,
                            "precision": 0.7,
                            "dangerous_recall": 0.63,
                            "false_positive_rate": 0.12,
                            "confusion": {"tp": 14, "fp": 6, "tn": 42, "fn": 8},
                            "by_source": {"large": "omitted"},
                        },
                    }
                ),
                encoding="utf-8",
            )

            summary = export_onnx.load_training_report_summary(report_path)

        self.assertEqual(summary["device"], "mps")
        self.assertEqual(summary["eval_rows"], 70)
        self.assertEqual(summary["checkpoint_selection"], {"objective": "bounded_fpr"})
        self.assertEqual(summary["eval"]["dangerous_recall"], 0.63)
        self.assertNotIn("by_source", summary["eval"])

    def test_load_training_report_summary_missing_report_is_none(self) -> None:
        self.assertIsNone(export_onnx.load_training_report_summary(Path("does-not-exist.json")))

    def test_build_export_metadata_includes_warning_and_io_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            model_dir = Path(tmpdir) / "model"
            model_dir.mkdir()
            write_bound_training_report(
                model_dir,
                make_training_report(),
            )
            output_path = Path(tmpdir) / "out" / "model.onnx"
            output_path.parent.mkdir()
            output_path.write_bytes(b"checked-onnx")

            metadata = export_onnx.build_export_metadata(
                model_dir=model_dir,
                output_path=output_path,
                max_length=384,
                opset=17,
                input_names=["attention_mask", "input_ids"],
                sample_text="Context: inspect\nCommand: ls",
                calibrated_thresholds={
                    "warn": 0.2,
                    "confirm_required": 0.4,
                    "model_block": False,
                    "review_status": "human_reviewed",
                    "reviewer_id": "reviewer-1",
                    "reviewed_at": "2026-09-08T10:00:00-07:00",
                    "review_policy_version": "sentinel-threshold-policy-v1",
                    "calibration_dataset_sha256": "b" * 64,
                    "review_content_sha256": "d" * 64,
                },
            )

        self.assertEqual(metadata["onnx_path"], str(output_path))
        self.assertEqual(
            metadata["input_format_version"],
            export_onnx.INPUT_FORMAT_VERSION,
        )
        self.assertEqual(metadata["input_names"], ["attention_mask", "input_ids"])
        self.assertEqual(metadata["output_names"], ["logits"])
        self.assertEqual(
            metadata["onnx_sha256"],
            hashlib.sha256(b"checked-onnx").hexdigest(),
        )
        self.assertEqual(
            metadata["serving_threshold_binding_sha256"],
            export_onnx.serving_threshold_binding_sha256(
                metadata["thresholds"]
            ),
        )
        self.assertIn("deterministic rules", metadata["serving_warning"])

    def test_export_refuses_missing_reviewed_serving_thresholds(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            model_dir = Path(tmpdir)
            write_bound_training_report(model_dir, make_training_report())

            with self.assertRaisesRegex(ValueError, "calibrated thresholds"):
                export_onnx.build_export_metadata(
                    model_dir=model_dir,
                    output_path=model_dir / "model.onnx",
                    max_length=384,
                    opset=17,
                    input_names=["input_ids", "attention_mask"],
                    sample_text="Command: ls",
                )

    def test_export_does_not_write_orphan_model_without_thresholds(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            model_dir = Path(tmpdir) / "model"
            model_dir.mkdir()
            write_bound_training_report(model_dir, make_training_report())
            output_path = Path(tmpdir) / "output" / "model.onnx"

            with self.assertRaisesRegex(ValueError, "calibrated thresholds"):
                export_onnx.export_onnx(
                    model_dir=model_dir,
                    output_path=output_path,
                    max_length=384,
                    opset=17,
                )

            self.assertFalse(output_path.exists())

    def test_export_metadata_rejects_swapped_checkpoint_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            model_dir = Path(tmpdir)
            write_bound_training_report(model_dir, make_training_report())
            (model_dir / "model.safetensors").write_bytes(b"old-swapped-weights")

            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                export_onnx.build_export_metadata(
                    model_dir=model_dir,
                    output_path=model_dir / "model.onnx",
                    max_length=384,
                    opset=17,
                    input_names=["input_ids", "attention_mask"],
                    sample_text="Command: ls",
                )

    def test_export_requires_bound_tokenizer_config_and_vocabulary(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            model_dir = Path(tmpdir)
            report = make_training_report()
            write_bound_training_report(model_dir, report)
            training_metadata = report["training_metadata"]
            assert isinstance(training_metadata, dict)
            artifact_hashes = training_metadata["checkpoint_artifact_sha256"]
            assert isinstance(artifact_hashes, dict)

            artifact_hashes.pop("tokenizer_config.json")
            with self.assertRaisesRegex(ValueError, "tokenizer_config.json"):
                export_onnx.validate_training_metadata(
                    report,
                    max_length=384,
                    model_dir=model_dir,
                )

            artifact_hashes["tokenizer_config.json"] = hashlib.sha256(
                (model_dir / "tokenizer_config.json").read_bytes()
            ).hexdigest()
            artifact_hashes.pop("tokenizer.json")
            with self.assertRaisesRegex(ValueError, "tokenizer vocabulary"):
                export_onnx.validate_training_metadata(
                    report,
                    max_length=384,
                    model_dir=model_dir,
                )

    def test_export_rejects_swapped_tokenizer_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            model_dir = Path(tmpdir)
            report = make_training_report()
            write_bound_training_report(model_dir, report)
            (model_dir / "tokenizer.json").write_bytes(b"swapped-tokenizer")

            with self.assertRaisesRegex(
                ValueError,
                "hash mismatch: tokenizer.json",
            ):
                export_onnx.validate_training_metadata(
                    report,
                    max_length=384,
                    model_dir=model_dir,
                )

    def test_export_metadata_rejects_legacy_or_mismatched_formatter(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            model_dir = Path(tmpdir)
            report_path = model_dir / "training_report.json"
            report_path.write_text(json.dumps({"eval": {}}), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "legacy checkpoint"):
                export_onnx.build_export_metadata(
                    model_dir=model_dir,
                    output_path=model_dir / "model.onnx",
                    max_length=384,
                    opset=17,
                    input_names=["input_ids", "attention_mask"],
                    sample_text="Command: ls",
                )

            report_path.write_text(
                json.dumps(
                    make_training_report(
                        input_format_version="sentinel-context-first-v1"
                    )
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "does not match"):
                export_onnx.build_export_metadata(
                    model_dir=model_dir,
                    output_path=model_dir / "model.onnx",
                    max_length=384,
                    opset=17,
                    input_names=["input_ids", "attention_mask"],
                    sample_text="Command: ls",
                )

    def test_load_calibrated_thresholds_requires_review_and_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path, dataset_path, payload = write_threshold_review(Path(tmpdir))

            thresholds = export_onnx.load_calibrated_thresholds(
                path,
                dataset_path,
            )

            self.assertEqual(thresholds["warn"], 0.2)
            self.assertEqual(thresholds["confirm_required"], 0.4)
            payload["review_status"] = "pending"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "human_reviewed"):
                export_onnx.load_calibrated_thresholds(path, dataset_path)

    def test_threshold_review_is_bound_to_review_and_calibration_content(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path, dataset_path, payload = write_threshold_review(Path(tmpdir))

            payload["reviewer_id"] = "different-reviewer"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "review_content_sha256"):
                export_onnx.load_calibrated_thresholds(path, dataset_path)

            path, dataset_path, _ = write_threshold_review(Path(tmpdir))
            dataset_path.write_bytes(b"swapped calibration bytes\n")
            with self.assertRaisesRegex(ValueError, "dataset hash does not match"):
                export_onnx.load_calibrated_thresholds(path, dataset_path)

    def test_threshold_review_requires_complete_attestation_and_dataset_path(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path, dataset_path, payload = write_threshold_review(Path(tmpdir))
            payload.pop("review_policy_version")
            payload["review_content_sha256"] = (
                export_onnx.threshold_review_content_sha256(payload)
            )
            path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "review_policy_version"):
                export_onnx.load_calibrated_thresholds(path, dataset_path)
            with self.assertRaisesRegex(ValueError, "explicit calibration"):
                export_onnx.load_calibrated_thresholds(path, None)

    def test_export_requires_checkpoint_constraints_to_be_met(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            model_dir = Path(tmpdir)
            report = make_training_report()
            checkpoint_selection = report["checkpoint_selection"]
            assert isinstance(checkpoint_selection, dict)
            selected = checkpoint_selection["selected"]
            assert isinstance(selected, dict)
            selected["constraints_met"] = False
            write_bound_training_report(model_dir, report)

            with self.assertRaisesRegex(ValueError, "constraints_met=true"):
                export_onnx.build_export_metadata(
                    model_dir=model_dir,
                    output_path=model_dir / "model.onnx",
                    max_length=384,
                    opset=17,
                    input_names=["input_ids", "attention_mask"],
                    sample_text="Command: ls",
                    calibrated_thresholds={
                        "warn": 0.2,
                        "confirm_required": 0.4,
                        "model_block": False,
                        "review_status": "human_reviewed",
                        "reviewer_id": "reviewer-1",
                        "reviewed_at": "2026-09-08T10:00:00-07:00",
                        "review_policy_version": "sentinel-threshold-policy-v1",
                        "calibration_dataset_sha256": "b" * 64,
                        "review_content_sha256": "d" * 64,
                    },
                    onnx_sha256="c" * 64,
                )


if __name__ == "__main__":
    unittest.main()
