from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.integrations.cursor import (  # noqa: E402
    CURSOR_CAPABILITY_MATRIX,
    cursor_authority_boundary_passes,
)


class CursorCapabilityTests(unittest.TestCase):
    def test_cursor_does_not_claim_a_mandatory_authority_boundary(self) -> None:
        by_family = {
            capability.action_family: capability
            for capability in CURSOR_CAPABILITY_MATRIX
        }

        self.assertEqual(
            set(by_family),
            {"prompt", "shell", "file", "mcp", "subagent"},
        )
        self.assertFalse(by_family["prompt"].can_update_authority)
        self.assertFalse(by_family["shell"].mediated_execution)
        self.assertFalse(cursor_authority_boundary_passes())

    def test_every_supported_family_has_an_explicit_status_and_limitation(self) -> None:
        for capability in CURSOR_CAPABILITY_MATRIX:
            with self.subTest(action_family=capability.action_family):
                self.assertIn(
                    capability.status,
                    {"mandatory", "advisory", "unsupported"},
                )
                self.assertTrue(capability.limitation)


if __name__ == "__main__":
    unittest.main()
