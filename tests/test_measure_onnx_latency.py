from __future__ import annotations

import importlib.util
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "measure_onnx_latency.py"
SPEC = importlib.util.spec_from_file_location("measure_onnx_latency", MODULE_PATH)
assert SPEC is not None
measure_onnx_latency = importlib.util.module_from_spec(SPEC)
sys.modules["measure_onnx_latency"] = measure_onnx_latency
assert SPEC.loader is not None
SPEC.loader.exec_module(measure_onnx_latency)


@dataclass(frozen=True)
class FakePrediction:
    model_tier: str


class FakeClock:
    def __init__(self) -> None:
        self.values = iter([0.000, 0.010, 0.020, 0.050, 0.060, 0.160])

    def __call__(self) -> float:
        return next(self.values)


class MeasureOnnxLatencyTests(unittest.TestCase):
    def test_percentile_interpolates_sorted_values(self) -> None:
        self.assertEqual(measure_onnx_latency.percentile([10.0, 20.0, 30.0], 50), 20.0)
        self.assertEqual(measure_onnx_latency.percentile([10.0, 20.0, 30.0], 95), 29.0)

    def test_latency_summary_reports_core_percentiles(self) -> None:
        summary = measure_onnx_latency.latency_summary([10.0, 20.0, 30.0])

        self.assertEqual(summary["count"], 3)
        self.assertEqual(summary["min_ms"], 10.0)
        self.assertEqual(summary["p50_ms"], 20.0)
        self.assertEqual(summary["max_ms"], 30.0)

    def test_measure_latency_uses_warmup_repeat_and_tier_counts(self) -> None:
        rows = [{"id": "a"}, {"id": "b"}]
        calls: list[str] = []

        def predict(row: dict[str, str]) -> FakePrediction:
            calls.append(row["id"])
            return FakePrediction(model_tier="warn" if row["id"] == "a" else "confirm_required")

        report = measure_onnx_latency.measure_latency(
            rows,
            predict,
            warmup=1,
            repeat=1,
            clock=FakeClock(),
        )

        self.assertEqual(calls, ["a", "a", "b"])
        self.assertEqual(report["row_count"], 2)
        self.assertEqual(report["warmup"], 1)
        self.assertEqual(report["repeat"], 1)
        self.assertEqual(report["tier_counts"], {"confirm_required": 1, "warn": 1})
        self.assertEqual(report["p50_ms"], 20.0)

    def test_measure_latency_rejects_empty_rows(self) -> None:
        with self.assertRaises(ValueError):
            measure_onnx_latency.measure_latency([], lambda row: FakePrediction("allow"), warmup=0, repeat=1)


if __name__ == "__main__":
    unittest.main()
