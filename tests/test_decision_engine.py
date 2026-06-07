from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.decision.engine import evaluate_request  # noqa: E402
from sentinel.decision.policy import PolicyProfile, parse_policy_profile  # noqa: E402
from sentinel.ml.inference import RiskPrediction  # noqa: E402


class FakeRiskModel:
    def __init__(self, prediction: RiskPrediction) -> None:
        self.prediction = prediction
        self.rows: list[dict[str, object]] = []

    def predict_row(self, row: dict[str, object]) -> RiskPrediction:
        self.rows.append(row)
        return self.prediction


class FailingRiskModel:
    def predict_row(self, row: dict[str, object]) -> RiskPrediction:
        raise RuntimeError("inference unavailable")


def prediction(probability: float, tier: str) -> RiskPrediction:
    return RiskPrediction(
        risk_probability=probability,
        model_tier=tier,  # type: ignore[arg-type]
        threshold={"warn": 0.2, "confirm_required": 0.4},
        input_names=["attention_mask", "input_ids"],
        provider="CPUExecutionProvider",
        metadata={"serving_warning": "rules first"},
    )


def policy_profile() -> PolicyProfile:
    return parse_policy_profile(
        {
            "name": "test-policy",
            "version": 1,
            "default_environment": "sandbox",
            "environments": {
                "sandbox": {
                    "minimum_model_tier_for_confirmation": "confirm_required",
                    "warn_requires_confirmation": False,
                    "production_change_requires_confirmation": False,
                    "unmatched_requires_confirmation": False,
                    "allow_confirmation_for_verdicts": ["confirm_required"],
                },
                "production": {
                    "minimum_model_tier_for_confirmation": "warn",
                    "warn_requires_confirmation": True,
                    "production_change_requires_confirmation": True,
                    "unmatched_requires_confirmation": True,
                    "allow_confirmation_for_verdicts": ["confirm_required"],
                },
            },
        }
    )


class DecisionEngineTests(unittest.TestCase):
    def test_rule_block_short_circuits_model(self) -> None:
        model = FakeRiskModel(prediction(0.01, "allow"))

        decision = evaluate_request(
            context="Clean the machine.",
            command="rm -rf /",
            environment="sandbox",
            recent_actions=[],
            model=model,
            request_id_factory=lambda: "request-1",
        )

        self.assertEqual(decision.request_id, "request-1")
        self.assertEqual(decision.verdict, "block")
        self.assertEqual(decision.risk_tier, "critical")
        self.assertEqual(decision.routing_path, "rules")
        self.assertIn("rule:root_filesystem_deletion", decision.reasons)
        self.assertIn("shell_type:unknown", decision.reasons)
        self.assertEqual(model.rows, [])

    def test_safe_sandbox_read_only_command_short_circuits_model(self) -> None:
        model = FakeRiskModel(prediction(0.99, "confirm_required"))

        decision = evaluate_request(
            context="Show git status.",
            command="git status --short",
            environment="sandbox",
            recent_actions=[],
            model=model,
            request_id_factory=lambda: "request-2",
        )

        self.assertEqual(decision.verdict, "allow")
        self.assertEqual(decision.risk_score, 0.05)
        self.assertEqual(decision.routing_path, "rules")
        self.assertEqual(model.rows, [])

    def test_gray_area_command_uses_model_prediction(self) -> None:
        model = FakeRiskModel(prediction(0.31, "warn"))

        decision = evaluate_request(
            context="Inspect the repository and make a small change if needed.",
            command="python scripts/custom_cleanup.py",
            environment="dev",
            shell_type="python",
            recent_actions=[{"type": "command", "summary": "Listed project files.", "sensitive_resources": []}],
            model=model,
            request_id_factory=lambda: "request-3",
        )

        self.assertEqual(decision.verdict, "warn")
        self.assertEqual(decision.risk_score, 0.31)
        self.assertEqual(decision.risk_tier, "medium")
        self.assertEqual(decision.routing_path, "model")
        self.assertIn("rule:unmatched_ambiguous_command", decision.reasons)
        self.assertIn("model:warn", decision.reasons)
        self.assertIn("shell_type:python", decision.reasons)
        self.assertEqual(model.rows[0]["command"], "python scripts/custom_cleanup.py")
        self.assertEqual(model.rows[0]["environment"], "dev")
        self.assertNotIn("shell_type", model.rows[0])

    def test_model_high_risk_requires_confirmation_but_never_blocks(self) -> None:
        model = FakeRiskModel(prediction(0.93, "confirm_required"))

        decision = evaluate_request(
            context="Investigate an unknown operational issue.",
            command="python scripts/repair_state.py --target prod-cache",
            environment="production",
            recent_actions=[],
            model=model,
            request_id_factory=lambda: "request-4",
        )

        self.assertEqual(decision.verdict, "confirm_required")
        self.assertEqual(decision.risk_tier, "high")
        self.assertNotEqual(decision.verdict, "block")
        self.assertIn("model:confirm_required", decision.reasons)

    def test_gray_area_without_model_falls_back_to_confirmation(self) -> None:
        decision = evaluate_request(
            context="Run an unfamiliar project helper.",
            command="python scripts/custom_cleanup.py",
            environment="dev",
            recent_actions=[],
            model=None,
            request_id_factory=lambda: "request-5",
        )

        self.assertEqual(decision.verdict, "confirm_required")
        self.assertEqual(decision.routing_path, "rules")
        self.assertIn("model:unavailable", decision.reasons)
        self.assertIn("policy:confirmation_required_without_model", decision.reasons)

    def test_model_error_falls_back_to_confirmation(self) -> None:
        decision = evaluate_request(
            context="Run an unfamiliar project helper.",
            command="python scripts/custom_cleanup.py",
            environment="dev",
            recent_actions=[],
            model=FailingRiskModel(),
            request_id_factory=lambda: "request-6",
        )

        self.assertEqual(decision.verdict, "confirm_required")
        self.assertEqual(decision.routing_path, "rules")
        self.assertIn("model:error", decision.reasons)
        self.assertIn("policy:confirmation_required_without_model", decision.reasons)

    def test_policy_escalates_same_model_warning_in_production_only(self) -> None:
        profile = policy_profile()

        sandbox_decision = evaluate_request(
            context="Inspect the repository and make a small change if needed.",
            command="python scripts/custom_cleanup.py",
            environment="sandbox",
            recent_actions=[],
            model=FakeRiskModel(prediction(0.31, "warn")),
            policy_profile=profile,
            request_id_factory=lambda: "request-7",
        )
        production_decision = evaluate_request(
            context="Inspect the repository and make a small change if needed.",
            command="python scripts/custom_cleanup.py",
            environment="production",
            recent_actions=[],
            model=FakeRiskModel(prediction(0.31, "warn")),
            policy_profile=profile,
            request_id_factory=lambda: "request-8",
        )

        self.assertEqual(sandbox_decision.verdict, "warn")
        self.assertEqual(sandbox_decision.routing_path, "model")
        self.assertEqual(production_decision.verdict, "confirm_required")
        self.assertEqual(production_decision.routing_path, "policy")
        self.assertIn("policy:production_minimum_model_tier_for_confirmation", production_decision.reasons)
        self.assertIn("policy:production_unmatched_requires_confirmation", production_decision.reasons)

    def test_policy_can_escalate_rule_warning_without_model(self) -> None:
        model = FakeRiskModel(prediction(0.01, "allow"))

        decision = evaluate_request(
            context="Install project dependencies.",
            command="npm install",
            environment="production",
            recent_actions=[],
            model=model,
            policy_profile=policy_profile(),
            request_id_factory=lambda: "request-9",
        )

        self.assertEqual(decision.verdict, "confirm_required")
        self.assertEqual(decision.routing_path, "policy")
        self.assertIn("rule:package_install_or_update", decision.reasons)
        self.assertIn("policy:production_warn_requires_confirmation", decision.reasons)
        self.assertEqual(model.rows, [])

    def test_policy_never_downgrades_rule_block(self) -> None:
        model = FakeRiskModel(prediction(0.01, "allow"))

        decision = evaluate_request(
            context="Clean disk space.",
            command="rm -rf /",
            environment="production",
            recent_actions=[],
            model=model,
            policy_profile=policy_profile(),
            request_id_factory=lambda: "request-10",
        )

        self.assertEqual(decision.verdict, "block")
        self.assertEqual(decision.routing_path, "rules")
        self.assertIn("rule:root_filesystem_deletion", decision.reasons)
        self.assertEqual(model.rows, [])


if __name__ == "__main__":
    unittest.main()

