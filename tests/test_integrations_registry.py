from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.integrations import (  # noqa: E402
    CURSOR_WEEK12_PROFILE,
    AdapterSessionError,
    AdapterSessionRegistry,
)

NOW = datetime(2026, 9, 9, 12, 0, tzinfo=timezone.utc)


class AdapterSessionRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = AdapterSessionRegistry(supervision_session_id="session-1")
        self.issued = self.registry.issue(
            adapter_kind="cursor_mcp", tool_family="sentinel_issue_fixture", now=NOW
        )

    def test_capability_authenticates_and_only_its_hash_is_stored(self) -> None:
        session = self.registry.authenticate(self.issued.capability, now=NOW)
        self.assertEqual(session.adapter_session_id, self.issued.session.adapter_session_id)
        self.assertEqual(session.supervision_session_id, "session-1")
        self.assertNotIn(self.issued.capability, repr(session))
        self.assertEqual(len(session.capability_sha256), 64)

    def test_missing_unknown_expired_and_revoked_capabilities_fail_closed(self) -> None:
        with self.assertRaises(AdapterSessionError) as missing:
            self.registry.authenticate(None, now=NOW)
        with self.assertRaises(AdapterSessionError) as unknown:
            self.registry.authenticate("not-the-capability", now=NOW)
        with self.assertRaises(AdapterSessionError) as expired:
            self.registry.authenticate(self.issued.capability, now=NOW + timedelta(hours=9))
        self.registry.revoke("cursor_mcp", now=NOW)
        with self.assertRaises(AdapterSessionError) as revoked:
            self.registry.authenticate(self.issued.capability, now=NOW)
        self.assertEqual(missing.exception.reason_code, "adapter:capability_missing")
        self.assertEqual(unknown.exception.reason_code, "adapter:capability_unknown")
        self.assertEqual(expired.exception.reason_code, "adapter:capability_expired")
        self.assertEqual(revoked.exception.reason_code, "adapter:capability_revoked")
        self.assertEqual(self.registry.connection.rejected_calls, 4)

    def test_rotation_invalidates_the_previous_capability(self) -> None:
        rotated = self.registry.issue(
            adapter_kind="cursor_mcp", tool_family="sentinel_issue_fixture", now=NOW
        )
        with self.assertRaises(AdapterSessionError) as raised:
            self.registry.authenticate(self.issued.capability, now=NOW)
        self.assertEqual(raised.exception.reason_code, "adapter:capability_revoked")
        self.assertEqual(
            self.registry.authenticate(rotated.capability, now=NOW).adapter_session_id,
            rotated.session.adapter_session_id,
        )

    def test_registry_is_process_local(self) -> None:
        fresh = AdapterSessionRegistry(supervision_session_id="session-1")
        with self.assertRaises(AdapterSessionError):
            fresh.authenticate(self.issued.capability, now=NOW)

    def test_connection_state_is_derived_from_authenticated_calls(self) -> None:
        self.assertEqual(self.registry.connection.status, "never_connected")
        self.registry.record_call(tool="sentinel_issue_read", verdict="allow", now=NOW)
        connection = self.registry.connection
        self.assertEqual(connection.status, "connected")
        self.assertEqual(connection.last_tool, "sentinel_issue_read")
        self.assertEqual(connection.mediated_calls, 1)


class CapabilityProfileTests(unittest.TestCase):
    def test_cursor_profile_never_claims_blanket_protection(self) -> None:
        statuses = {entry.status for entry in CURSOR_WEEK12_PROFILE.families}
        self.assertEqual(statuses, {"mandatory", "advisory", "unsupported"})
        mandatory = [entry for entry in CURSOR_WEEK12_PROFILE.families if entry.status == "mandatory"]
        self.assertEqual([entry.family for entry in mandatory], ["sentinel_issue_fixture"])
        self.assertTrue(mandatory[0].conditions, "mandatory coverage must state its conditions")
        for family in ("shell", "file_edit", "prompt"):
            self.assertEqual(CURSOR_WEEK12_PROFILE.family(family).status, "advisory")
        for family in ("browser", "network", "subagents", "other_mcp_servers"):
            self.assertEqual(CURSOR_WEEK12_PROFILE.family(family).status, "unsupported")


if __name__ == "__main__":
    unittest.main()
