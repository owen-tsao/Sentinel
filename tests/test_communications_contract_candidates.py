from __future__ import annotations

import json
import sys
import unittest
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from scripts.build_communications_contract_candidates import (  # noqa: E402
    build_cases,
    build_review_packet,
)


class CommunicationsCandidateTests(unittest.TestCase):
    def test_pack_has_expected_size_balance_and_provider_coverage(self) -> None:
        rows = build_cases()
        outcomes = Counter(row["expected_outcome"] for row in rows)
        providers = Counter(
            row["proposed_action"]["resolved_evidence"]["provider_context"]["provider"]
            for row in rows
        )

        self.assertEqual(len(rows), 30)
        self.assertGreaterEqual(outcomes["compliant"], 5)
        self.assertGreaterEqual(outcomes["contract_overstep"], 15)
        self.assertGreaterEqual(outcomes["insufficient_contract"], 5)
        self.assertEqual(providers["slack"], 10)
        self.assertEqual(providers["gmail"], 7)
        self.assertEqual(providers["google_calendar"], 3)
        self.assertEqual(providers["google_drive"], 10)
        self.assertGreaterEqual(
            sum(row["critical_canary_candidate"] for row in rows),
            12,
        )

    def test_every_row_is_unreviewed_and_uses_official_fixture_provenance(self) -> None:
        for row in build_cases():
            source = row["source_provenance"]
            evidence = row["proposed_action"]["resolved_evidence"]

            self.assertEqual(row["review_status"], "unreviewed")
            self.assertNotIn("review_content_sha256", row)
            self.assertEqual(
                source["metadata_fixture_status"],
                "official_schema_fixture",
            )
            self.assertTrue(source["source_endpoints"])
            self.assertTrue(source["source_fields"])
            self.assertTrue(source["url"].startswith("https://"))
            self.assertEqual(
                evidence["provenance"]["source_type"],
                "official_schema_fixture",
            )
            self.assertTrue(
                evidence["provenance"]["documentation_url"].startswith("https://")
            )

    def test_minimal_pair_groups_contain_different_expected_outcomes(self) -> None:
        grouped: dict[str, set[str]] = defaultdict(set)
        for row in build_cases():
            grouped[row["contract_group_id"]].add(row["expected_outcome"])

        for group in (
            "communications-slack-channel-exposure",
            "communications-slack-thread-broadcast",
            "communications-gmail-draft-send",
            "communications-drive-basic-share",
        ):
            self.assertGreaterEqual(len(grouped[group]), 2, group)

    def test_candidate_labels_and_reasons_are_review_inputs(self) -> None:
        for row in build_cases():
            self.assertIn(
                row["expected_outcome"],
                {"compliant", "contract_overstep", "insufficient_contract"},
            )
            reasons = row["candidate_required_reason_codes"]
            self.assertIsInstance(reasons, list)
            self.assertTrue(all(isinstance(reason, str) and reason for reason in reasons))
            self.assertNotIn("predicted_outcome", row)

    def test_builder_output_contains_no_credentials_and_review_is_non_authoritative(
        self,
    ) -> None:
        rows = build_cases()
        review_packet = build_review_packet(rows).replace(
            "# Contract Golden Candidate Review",
            "# Communications Contract Candidate Review",
            1,
        )
        serialized = json.dumps(
            {"rows": rows, "review_packet": review_packet},
            sort_keys=True,
        ).lower()

        self.assertIn("review aid, not approval evidence", review_packet)
        self.assertEqual(review_packet.count("\n## "), len(rows))
        for credential_marker in (
            "authorization: bearer",
            "xoxb-",
            "xoxp-",
            "ya29.",
            "private_key",
            "client_secret",
        ):
            self.assertNotIn(credential_marker, serialized)


if __name__ == "__main__":
    unittest.main()
