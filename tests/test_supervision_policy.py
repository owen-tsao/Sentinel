from __future__ import annotations

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.api.main import create_app  # noqa: E402
from sentinel.control import (  # noqa: E402
    ControlConfig,
    InMemoryWorkspaceBindingStore,
    review_workspace,
)
from sentinel.execution import DockerExecutor  # noqa: E402
from sentinel.supervision import (  # noqa: E402
    InMemorySupervisionPolicyStore,
    SQLiteSupervisionPolicyStore,
    SupervisionPolicy,
    SupervisionPolicyError,
    week12_fixture_policy,
)

CAPABILITY = "phase-one-pairing-" + ("a" * 32)


def make_repository(parent: Path, name: str = "repository") -> Path:
    repository = parent / name
    repository.mkdir()
    (repository / ".git").mkdir()
    return repository


def classify(policy: SupervisionPolicy, **overrides: object):
    values: dict[str, object] = {
        "adapter_kind": "cursor_mcp",
        "tool_family": "sentinel_issue_fixture",
        "operation": "issue_read",
        "issue_id": "SPIKE-1",
        "environment": "sandbox",
    }
    values.update(overrides)
    return policy.classify(**values)  # type: ignore[arg-type]


class SupervisionPolicyCeilingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = week12_fixture_policy()

    def test_ceiling_never_returns_allow(self) -> None:
        verdicts = {
            classify(self.policy).verdict,
            classify(self.policy, operation="issue_add_note", note_bytes=10).verdict,
            classify(self.policy, operation="issue_delete").verdict,
        }
        self.assertEqual(verdicts, {"ordinary", "confirm_required", "forbidden"})
        self.assertNotIn("allow", verdicts)

    def test_read_is_ordinary_and_note_requires_confirmation(self) -> None:
        self.assertEqual(classify(self.policy).reason_code, "supervision:ordinary_operation")
        note = classify(self.policy, operation="issue_add_note", note_bytes=12)
        self.assertEqual(note.verdict, "confirm_required")

    def test_forbidden_operations_and_unknown_operations_fail_closed(self) -> None:
        for operation in ("issue_delete", "fixture_admin", "network_access", "issue_rename"):
            with self.subTest(operation=operation):
                decision = classify(self.policy, operation=operation)
                self.assertEqual(decision.verdict, "forbidden")
                self.assertEqual(decision.reason_code, "supervision:operation_forbidden")

    def test_scope_boundaries_are_forbidden(self) -> None:
        cases = [
            ("supervision:outside_tool_family", {"tool_family": "github_issues"}),
            ("supervision:outside_tool_family", {"adapter_kind": "cursor_shell"}),
            ("supervision:environment_mismatch", {"environment": "production"}),
            ("supervision:issue_out_of_scope", {"issue_id": "PROD-1"}),
            ("supervision:issue_out_of_scope", {"issue_id": "SPIKE-01"}),
            ("supervision:issue_out_of_scope", {"issue_id": "SPIKE-1 "}),
            ("supervision:note_too_large", {"operation": "issue_add_note", "note_bytes": 2_001}),
        ]
        for expected, overrides in cases:
            with self.subTest(overrides=overrides):
                decision = classify(self.policy, **overrides)
                self.assertEqual(decision.verdict, "forbidden")
                self.assertEqual(decision.reason_code, expected)

    def test_content_hash_is_stable_and_sensitive(self) -> None:
        same = week12_fixture_policy(
            ordinary_operations=frozenset({"issue_read"}),
        )
        wider = week12_fixture_policy(
            ordinary_operations=frozenset({"issue_read", "issue_add_note"}),
            confirm_operations=frozenset(),
        )
        self.assertEqual(same.content_sha256, self.policy.content_sha256)
        self.assertNotEqual(wider.content_sha256, self.policy.content_sha256)

    def test_invalid_ceilings_are_rejected_at_construction(self) -> None:
        cases = {
            "supervision:overlapping_operations": {
                "confirm_operations": frozenset({"issue_read"}),
            },
            "supervision:forbidden_baseline_weakened": {
                "forbidden_operations": frozenset({"issue_delete"}),
            },
            "supervision:issue_pattern_unanchored": {"issue_id_pattern": r"SPIKE-\d+"},
            "supervision:issue_pattern_too_broad": {"issue_id_pattern": r"^.*$"},
            "supervision:issue_pattern_invalid": {"issue_id_pattern": r"^SPIKE-(\d+$"},
            "supervision:unsupported_environment": {"environment": "production"},
            "supervision:invalid_lifetime": {"max_process_lifetime": timedelta(0)},
            "supervision:invalid_note_limit": {"max_note_bytes": 0},
            "supervision:no_operations": {
                "ordinary_operations": frozenset(),
                "confirm_operations": frozenset(),
            },
        }
        for expected, overrides in cases.items():
            with self.subTest(expected=expected):
                with self.assertRaises(SupervisionPolicyError) as raised:
                    week12_fixture_policy(**overrides)
                self.assertEqual(raised.exception.reason_code, expected)


class SupervisionPolicyBindingTests(unittest.TestCase):
    def test_sqlite_binding_accepts_the_same_ceiling_and_rejects_a_weaker_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = review_workspace(make_repository(root))
            session = InMemoryWorkspaceBindingStore().bind(workspace)
            database = root / "sentinel.sqlite3"

            first = SQLiteSupervisionPolicyStore(database)
            bound = first.bind(week12_fixture_policy(), session)
            first.close()

            second = SQLiteSupervisionPolicyStore(database)
            rebound = second.bind(week12_fixture_policy(), session)
            weaker = week12_fixture_policy(
                ordinary_operations=frozenset({"issue_read", "issue_add_note"}),
                confirm_operations=frozenset(),
            )
            with self.assertRaises(SupervisionPolicyError) as raised:
                second.bind(weaker, session)
            second.close()

        self.assertEqual(rebound.content_sha256, bound.content_sha256)
        self.assertEqual(raised.exception.reason_code, "supervision:policy_binding_mismatch")

    def test_binding_is_tied_to_the_session_and_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_session = InMemoryWorkspaceBindingStore().bind(
                review_workspace(make_repository(root, "one"))
            )
            second_session = InMemoryWorkspaceBindingStore().bind(
                review_workspace(make_repository(root, "two"))
            )
            store = InMemorySupervisionPolicyStore()
            store.bind(week12_fixture_policy(), first_session)
            with self.assertRaises(SupervisionPolicyError) as raised:
                store.bind(week12_fixture_policy(), second_session)
        self.assertEqual(raised.exception.reason_code, "supervision:policy_binding_mismatch")

    def test_binding_expires_after_the_process_lifetime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            session = InMemoryWorkspaceBindingStore().bind(
                review_workspace(make_repository(Path(directory)))
            )
            binding = InMemorySupervisionPolicyStore().bind(
                week12_fixture_policy(max_process_lifetime=timedelta(minutes=30)),
                session,
            )
        self.assertFalse(binding.is_expired(binding.bound_at))
        self.assertFalse(binding.is_expired(binding.bound_at + timedelta(minutes=29)))
        self.assertTrue(binding.is_expired(binding.bound_at + timedelta(minutes=30)))
        self.assertLess(binding.bound_at, datetime.now(timezone.utc) + timedelta(seconds=1))


class SupervisionPolicyStartupTests(unittest.TestCase):
    def _config(self, repository: Path) -> ControlConfig:
        return ControlConfig(workspace=repository, pairing_capability=CAPABILITY)

    def test_control_startup_binds_the_ceiling_and_rejects_a_changed_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = make_repository(root)
            database = root / "sentinel.sqlite3"
            with patch.dict(os.environ, {"SENTINEL_STATE_DB": str(database)}, clear=False):
                app = create_app(
                    load_policy=False,
                    executor=DockerExecutor(workspace=repository, runner=Mock()),
                    control_config=self._config(repository),
                    supervision_policy=week12_fixture_policy(),
                )
                with TestClient(app):
                    binding = app.state.supervision_policy_binding
                    self.assertIsNotNone(binding)
                    self.assertEqual(binding.content_sha256, week12_fixture_policy().content_sha256)
                    self.assertEqual(binding.session_id, app.state.supervision_binding.session_id)

                weaker = week12_fixture_policy(
                    ordinary_operations=frozenset({"issue_read", "issue_add_note"}),
                    confirm_operations=frozenset(),
                )
                with self.assertRaises(SupervisionPolicyError) as raised:
                    create_app(
                        load_policy=False,
                        executor=DockerExecutor(workspace=repository, runner=Mock()),
                        control_config=self._config(repository),
                        supervision_policy=weaker,
                    )
        self.assertEqual(raised.exception.reason_code, "supervision:policy_binding_mismatch")

    def test_control_startup_without_a_ceiling_keeps_week_11_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = make_repository(root)
            with patch.dict(
                os.environ, {"SENTINEL_STATE_DB": str(root / "sentinel.sqlite3")}, clear=False
            ):
                app = create_app(
                    load_policy=False,
                    executor=DockerExecutor(workspace=repository, runner=Mock()),
                    control_config=self._config(repository),
                )
                with TestClient(app):
                    self.assertIsNone(app.state.supervision_policy_binding)

    def test_ceiling_requires_control_mode(self) -> None:
        with self.assertRaises(SupervisionPolicyError) as raised:
            create_app(load_policy=False, supervision_policy=week12_fixture_policy())
        self.assertEqual(raised.exception.reason_code, "supervision:control_config_required")


if __name__ == "__main__":
    unittest.main()
