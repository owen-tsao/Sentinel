from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "calibrate_thresholds.py"
SPEC = importlib.util.spec_from_file_location("calibrate_thresholds", MODULE_PATH)
assert SPEC is not None
calibrate_thresholds = importlib.util.module_from_spec(SPEC)
sys.modules["calibrate_thresholds"] = calibrate_thresholds
assert SPEC.loader is not None
SPEC.loader.exec_module(calibrate_thresholds)


class CalibrateThresholdsTests(unittest.TestCase):
    def test_threshold_rows_deduplicates_and_sorts_thresholds(self) -> None:
        rows = calibrate_thresholds.threshold_rows(
            {
                "threshold": 0.5,
                "accuracy": 0.8,
                "threshold_sweep": [
                    {"threshold": 0.2, "accuracy": 0.7},
                    {"threshold": 0.5, "accuracy": 0.81},
                ],
            }
        )

        self.assertEqual([row["threshold"] for row in rows], [0.2, 0.5])
        self.assertEqual(rows[1]["accuracy"], 0.81)

    def test_recommend_policy_bands_prefers_recall_then_bounded_fpr(self) -> None:
        rows = [
            {"threshold": 0.2, "dangerous_recall": 0.91, "false_positive_rate": 0.38, "accuracy": 0.71},
            {"threshold": 0.3, "dangerous_recall": 0.82, "false_positive_rate": 0.31, "accuracy": 0.73},
            {"threshold": 0.4, "dangerous_recall": 0.77, "false_positive_rate": 0.25, "accuracy": 0.76},
            {"threshold": 0.5, "dangerous_recall": 0.68, "false_positive_rate": 0.17, "accuracy": 0.79},
        ]

        bands = calibrate_thresholds.recommend_policy_bands(rows, min_recall=0.9, max_fpr=0.3)

        self.assertEqual(bands["warn_threshold"], 0.2)
        self.assertEqual(bands["confirm_threshold"], 0.4)
        self.assertFalse(bands["model_block"])

    def test_weakest_groups_reports_low_recall_and_high_fpr(self) -> None:
        eval_metrics = {
            "by_risk_category": {
                "credential_exfiltration": {
                    "total": 5,
                    "dangerous_recall": 1.0,
                    "false_positive_rate": 0.0,
                    "confusion": {"tp": 4, "fp": 0, "tn": 1, "fn": 0},
                },
                "policy_violation": {
                    "total": 4,
                    "dangerous_recall": 0.25,
                    "false_positive_rate": 0.5,
                    "confusion": {"tp": 1, "fp": 1, "tn": 1, "fn": 3},
                },
            }
        }

        groups = calibrate_thresholds.weakest_groups(eval_metrics, "by_risk_category", limit=1)

        self.assertEqual(groups["dangerous_recall"][0]["name"], "policy_violation")
        self.assertEqual(groups["false_positive_rate"][0]["name"], "policy_violation")

    def test_build_calibration_review_includes_policy_and_group_sections(self) -> None:
        report = {
            "model_name": "test-model",
            "device": "cpu",
            "eval_rows": 2,
            "eval": {
                "threshold": 0.5,
                "accuracy": 1.0,
                "dangerous_recall": 1.0,
                "false_positive_rate": 0.0,
                "confusion": {"tp": 1, "fp": 0, "tn": 1, "fn": 0},
                "by_source": {},
                "by_risk_category": {},
            },
        }

        review = calibrate_thresholds.build_calibration_review(report, min_recall=0.9, max_fpr=0.3, group_limit=3)

        self.assertEqual(review["eval_rows"], 2)
        self.assertEqual(review["policy_bands"]["warn_threshold"], 0.5)
        self.assertIn("weakest_by_source", review)


if __name__ == "__main__":
    unittest.main()
