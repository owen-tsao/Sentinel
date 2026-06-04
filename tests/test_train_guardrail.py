from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "train_guardrail.py"
SPEC = importlib.util.spec_from_file_location("train_guardrail", MODULE_PATH)
assert SPEC is not None
train_guardrail = importlib.util.module_from_spec(SPEC)
sys.modules["train_guardrail"] = train_guardrail
assert SPEC.loader is not None
SPEC.loader.exec_module(train_guardrail)


class TrainGuardrailTests(unittest.TestCase):
    def test_row_to_text_includes_context_history_environment_and_command(self) -> None:
        row = {
            "id": "example-1",
            "context": "Inspect pending production migrations without applying them.",
            "recent_actions": [
                {
                    "type": "command",
                    "summary": "Connected to production database metadata for migration inspection.",
                    "sensitive_resources": ["production_database"],
                }
            ],
            "environment": "production",
            "command": "alembic upgrade head",
            "label": 1,
            "source": "test",
            "risk_category": "policy_violation",
        }

        text = train_guardrail.row_to_text(row)

        self.assertIn("Context: Inspect pending production migrations", text)
        self.assertIn("Recent actions:", text)
        self.assertIn("sensitive_resources=production_database", text)
        self.assertIn("Environment: production", text)
        self.assertIn("Command: alembic upgrade head", text)

    def test_format_recent_actions_limits_to_last_five(self) -> None:
        actions = [
            {"type": "command", "summary": f"step {index}", "sensitive_resources": []}
            for index in range(7)
        ]

        formatted = train_guardrail.format_recent_actions(actions)

        self.assertNotIn("step 0", formatted)
        self.assertNotIn("step 1", formatted)
        self.assertIn("step 2", formatted)
        self.assertIn("step 6", formatted)

    def test_rows_to_examples_validates_binary_labels(self) -> None:
        row = {
            "id": "example-2",
            "context": "List files.",
            "recent_actions": [],
            "environment": "sandbox",
            "command": "ls -la",
            "label": 0,
            "source": "test",
            "risk_category": "safe_read_only",
        }

        examples = train_guardrail.rows_to_examples([row])

        self.assertEqual(len(examples), 1)
        self.assertEqual(examples[0].id, "example-2")
        self.assertEqual(examples[0].label, 0)
        self.assertIn("Command: ls -la", examples[0].text)

        bad_row = dict(row)
        bad_row["label"] = 2
        with self.assertRaises(ValueError):
            train_guardrail.rows_to_examples([bad_row])

    def test_compute_binary_metrics(self) -> None:
        metrics = train_guardrail.compute_binary_metrics(
            labels=[0, 0, 1, 1],
            probabilities=[0.1, 0.7, 0.8, 0.2],
            threshold=0.5,
        )

        self.assertEqual(metrics["confusion"], {"tp": 1, "fp": 1, "tn": 1, "fn": 1})
        self.assertEqual(metrics["accuracy"], 0.5)
        self.assertEqual(metrics["precision"], 0.5)
        self.assertEqual(metrics["dangerous_recall"], 0.5)
        self.assertEqual(metrics["false_positive_rate"], 0.5)

    def test_empty_metrics_are_safe(self) -> None:
        metrics = train_guardrail.compute_binary_metrics([], [])

        self.assertEqual(metrics["total"], 0)
        self.assertIsNone(metrics["accuracy"])
        self.assertEqual(metrics["confusion"], {"tp": 0, "fp": 0, "tn": 0, "fn": 0})


if __name__ == "__main__":
    unittest.main()
