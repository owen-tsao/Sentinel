from __future__ import annotations

import importlib.util
import sys
import unittest
from collections import Counter
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "build_contract_golden_candidates.py"
)
SPEC = importlib.util.spec_from_file_location(
    "build_contract_golden_candidates",
    MODULE_PATH,
)
assert SPEC is not None
builder = importlib.util.module_from_spec(SPEC)
sys.modules["build_contract_golden_candidates"] = builder
assert SPEC.loader is not None
SPEC.loader.exec_module(builder)


class ContractGoldenCandidateTests(unittest.TestCase):
    def test_candidates_are_large_grouped_and_never_self_reviewed(self) -> None:
        rows = builder.build_cases()
        summary = builder.validate_cases(rows)

        self.assertGreaterEqual(summary["rows"], 30)
        self.assertGreaterEqual(summary["contract_groups"], 5)
        self.assertGreaterEqual(summary["template_families"], 3)
        self.assertGreaterEqual(summary["known_gap_hypotheses"], 1)
        self.assertGreaterEqual(summary["critical_canary_candidates"], 1)
        self.assertTrue(all(row["review_status"] == "unreviewed" for row in rows))
        self.assertTrue(all("reviewer_id" not in row for row in rows))
        self.assertTrue(all("review_content_sha256" not in row for row in rows))

    def test_every_category_and_outcome_has_reviewable_coverage(self) -> None:
        rows = builder.build_cases()
        category_counts = Counter(row["category"] for row in rows)
        outcome_counts = Counter(row["expected_outcome"] for row in rows)

        self.assertTrue(all(count >= 2 for count in category_counts.values()))
        self.assertGreaterEqual(outcome_counts["compliant"], 2)
        self.assertGreaterEqual(outcome_counts["contract_overstep"], 2)
        self.assertGreaterEqual(outcome_counts["insufficient_contract"], 2)

    def test_provenance_is_explicit_and_no_benchmark_row_is_copied(self) -> None:
        rows = builder.build_cases()

        for row in rows:
            source = row["source_provenance"]
            self.assertTrue(source["benchmark"])
            self.assertTrue(source["version"])
            self.assertTrue(source["source_id"])
            self.assertTrue(source["conversion_note"])
            self.assertFalse(source["direct_row_copy"])
        scopejudge_rows = [
            row for row in rows
            if row["source_provenance"]["benchmark"] == "ScopeJudge"
        ]
        self.assertTrue(scopejudge_rows)
        self.assertTrue(
            all(
                row["source_provenance"].get("source_review_votes")
                for row in scopejudge_rows
            )
        )

    def test_review_packet_is_explicitly_non_authoritative(self) -> None:
        rows = builder.build_cases()
        packet = builder.build_review_packet(rows)

        self.assertIn("review aid, not approval evidence", packet)
        self.assertEqual(packet.count("\n## "), len(rows))
        self.assertEqual(
            packet.count("Source evidence supports this contract"),
            len(rows),
        )

    def test_critical_candidates_include_expected_reason_codes(self) -> None:
        rows = builder.build_cases()
        critical = [row for row in rows if row["critical_canary_candidate"]]

        self.assertTrue(critical)
        self.assertTrue(
            all(row["candidate_required_reason_codes"] for row in critical)
        )
        for row in critical:
            self.assertTrue(
                all(
                    isinstance(reason, str) and reason
                    for reason in row["candidate_required_reason_codes"]
                )
            )

    def test_labels_are_review_inputs_not_policy_predictions(self) -> None:
        rows = builder.build_cases()

        for row in rows:
            self.assertIn(
                row["expected_outcome"],
                {"compliant", "contract_overstep", "insufficient_contract"},
            )
            self.assertNotIn("predicted_outcome", row)


if __name__ == "__main__":
    unittest.main()
