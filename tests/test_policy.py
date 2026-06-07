from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.decision.policy import DEFAULT_POLICY_PATH, load_policy_profile, parse_policy_profile  # noqa: E402


def minimal_policy() -> dict[str, object]:
    return {
        "name": "test-policy",
        "version": 1,
        "default_environment": "sandbox",
        "environments": {
            "sandbox": {
                "minimum_model_tier_for_confirmation": "confirm_required",
                "warn_requires_confirmation": False,
                "production_change_requires_confirmation": False,
                "unmatched_requires_confirmation": True,
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


class PolicyProfileTests(unittest.TestCase):
    def test_load_default_policy_profile(self) -> None:
        profile = load_policy_profile(DEFAULT_POLICY_PATH)

        self.assertEqual(profile.name, "default-local")
        self.assertEqual(profile.default_environment, "sandbox")
        self.assertFalse(profile.policy_for("sandbox").warn_requires_confirmation)
        self.assertFalse(profile.policy_for("sandbox").unmatched_requires_confirmation)
        self.assertTrue(profile.policy_for("production").warn_requires_confirmation)
        self.assertTrue(profile.policy_for("production").unmatched_requires_confirmation)
        self.assertTrue(profile.policy_for("production").production_change_requires_confirmation)

    def test_parse_policy_profile_normalizes_environment_names(self) -> None:
        raw = minimal_policy()
        raw["default_environment"] = " Sandbox "

        profile = parse_policy_profile(raw)

        self.assertEqual(profile.default_environment, "sandbox")
        self.assertEqual(profile.policy_for(" PRODUCTION ").minimum_model_tier_for_confirmation, "warn")

    def test_policy_for_uses_default_environment_when_input_is_empty(self) -> None:
        profile = parse_policy_profile(minimal_policy())

        self.assertEqual(profile.policy_for("").name, "sandbox")

    def test_parse_policy_rejects_missing_default_environment(self) -> None:
        raw = minimal_policy()
        raw["default_environment"] = "staging"

        with self.assertRaisesRegex(ValueError, "default_environment"):
            parse_policy_profile(raw)

    def test_parse_policy_rejects_invalid_model_tier(self) -> None:
        raw = minimal_policy()
        raw["environments"]["sandbox"]["minimum_model_tier_for_confirmation"] = "critical"  # type: ignore[index]

        with self.assertRaisesRegex(ValueError, "minimum_model_tier_for_confirmation"):
            parse_policy_profile(raw)

    def test_parse_policy_rejects_block_confirmation_verdict_typo(self) -> None:
        raw = minimal_policy()
        raw["environments"]["sandbox"]["allow_confirmation_for_verdicts"] = ["confirm_required", "deny"]  # type: ignore[index]

        with self.assertRaisesRegex(ValueError, "allow_confirmation_for_verdicts"):
            parse_policy_profile(raw)

    def test_parse_policy_rejects_block_as_confirmable(self) -> None:
        raw = minimal_policy()
        raw["environments"]["sandbox"]["allow_confirmation_for_verdicts"] = ["block"]  # type: ignore[index]

        with self.assertRaisesRegex(ValueError, "allow_confirmation_for_verdicts"):
            parse_policy_profile(raw)

    def test_load_policy_profile_reads_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.json"
            path.write_text(
                """
                {
                  "name": "file-policy",
                  "version": 1,
                  "default_environment": "sandbox",
                  "environments": {
                    "sandbox": {
                      "minimum_model_tier_for_confirmation": "confirm_required",
                      "warn_requires_confirmation": false,
                      "production_change_requires_confirmation": false,
                      "unmatched_requires_confirmation": true,
                      "allow_confirmation_for_verdicts": ["confirm_required"]
                    }
                  }
                }
                """,
                encoding="utf-8",
            )

            profile = load_policy_profile(path)

        self.assertEqual(profile.name, "file-policy")
        self.assertEqual(profile.policy_for("sandbox").allow_confirmation_for_verdicts, ("confirm_required",))


if __name__ == "__main__":
    unittest.main()

