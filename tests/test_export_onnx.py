from __future__ import annotations

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
            output_path = Path(tmpdir) / "out" / "model.onnx"

            metadata = export_onnx.build_export_metadata(
                model_dir=model_dir,
                output_path=output_path,
                max_length=384,
                opset=17,
                input_names=["attention_mask", "input_ids"],
                sample_text="Context: inspect\nCommand: ls",
            )

        self.assertEqual(metadata["onnx_path"], str(output_path))
        self.assertEqual(metadata["input_names"], ["attention_mask", "input_ids"])
        self.assertEqual(metadata["output_names"], ["logits"])
        self.assertIn("deterministic rules", metadata["serving_warning"])


if __name__ == "__main__":
    unittest.main()
