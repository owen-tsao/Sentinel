from __future__ import annotations

import os
import sys
import subprocess
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.session import (  # noqa: E402
    ExecutionAttemptBinding,
    ExecutionAttemptConflictError,
    InMemorySessionStore,
    SessionAction,
    SessionStore,
    SQLiteSessionStore,
)
from pydantic import ValidationError  # noqa: E402


class SessionStoreContractTests(unittest.TestCase):
    def test_in_memory_store_supports_bounded_history(self) -> None:
        store = InMemorySessionStore(max_history=3)
        self._assert_store_contract(store)

    def test_sqlite_store_supports_bounded_history(self) -> None:
        with TemporaryDirectory() as directory:
            store = SQLiteSessionStore(Path(directory) / "sessions.db", max_history=3)
            try:
                self._assert_store_contract(store)
            finally:
                store.close()

    def _assert_store_contract(self, store: SessionStore) -> None:
        self.assertIsInstance(store, SessionStore)

        for index in range(5):
            store.append_action(
                "session-1",
                SessionAction(
                    action_id=f"action-{index}",
                    action_type="shell.execute",
                    summary=f"Action {index}",
                    task_id=f"task-{index}",
                ),
            )

        history = store.get_recent_actions("session-1")
        self.assertEqual([action.action_id for action in history], ["action-2", "action-3", "action-4"])
        self.assertEqual(
            [action.task_id for action in history],
            ["task-2", "task-3", "task-4"],
        )
        self.assertEqual(
            [action.action_id for action in store.get_recent_actions("session-1", limit=2)],
            ["action-3", "action-4"],
        )

    def test_store_persists_supplied_task_without_independent_active_state(self) -> None:
        store = InMemorySessionStore()
        store.append_action(
            "session-1",
            SessionAction(
                action_type="file.write",
                summary="Write a file",
                task_id="server-derived-task",
            ),
        )

        self.assertEqual(
            store.get_recent_actions("session-1")[0].task_id,
            "server-derived-task",
        )
        self.assertFalse(hasattr(store, "get_active_task"))
        self.assertFalse(hasattr(store, "compare_and_swap_active_task"))

    def test_action_requires_nonempty_task_and_rejects_unknown_fields(self) -> None:
        with self.assertRaises(ValidationError):
            SessionAction(action_type="file.read", summary="Read", task_id="")
        with self.assertRaises(ValidationError):
            SessionAction(
                action_type="file.read",
                summary="Read",
                task_id="task-a",
                task_iid="typo",
            )

    def test_returned_history_cannot_replace_or_mutate_server_history(self) -> None:
        store = InMemorySessionStore()
        original = SessionAction(
            action_id="action-1",
            action_type="file.read",
            summary="Read config",
            task_id="task-a",
            metadata={"path": "settings.json"},
        )
        store.append_action("session-1", original)

        caller_copy = store.get_recent_actions("session-1")
        caller_copy.clear()
        original.metadata["path"] = ".env"

        server_history = store.get_recent_actions("session-1")
        self.assertEqual(len(server_history), 1)
        self.assertEqual(server_history[0].metadata, {"path": "settings.json"})
        self.assertFalse(hasattr(store, "set_recent_actions"))
        self.assertFalse(hasattr(store, "replace_history"))

    def test_sqlite_history_persists_without_creating_session_state(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "sessions.db"
            first = SQLiteSessionStore(database, max_history=4)
            first.append_action(
                "session-1",
                SessionAction(
                    action_id="action-1",
                    action_type="shell.execute",
                    summary="Run tests",
                    task_id="task-a",
                ),
            )
            first.close()

            reopened = SQLiteSessionStore(database, max_history=4)
            history = reopened.get_recent_actions("session-1")
            reopened.close()

            self.assertEqual([action.action_id for action in history], ["action-1"])
            self.assertEqual(history[0].task_id, "task-a")
            import sqlite3

            with sqlite3.connect(database) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
            self.assertNotIn("session_state", tables)

    def test_concurrent_appends_retain_bounded_history(self) -> None:
        for make_store in self._store_factories():
            with self.subTest(store=make_store.__name__):
                store, cleanup = make_store()
                try:
                    barrier = threading.Barrier(4)

                    def append(index: int) -> None:
                        barrier.wait()
                        store.append_action(
                            "session-1",
                            SessionAction(
                                action_id=f"action-{index}",
                                action_type="shell.execute",
                                summary=f"Action {index}",
                                task_id=f"task-{index}",
                            ),
                        )

                    threads = [
                        threading.Thread(target=append, args=(index,))
                        for index in range(4)
                    ]
                    for thread in threads:
                        thread.start()
                    for thread in threads:
                        thread.join()

                    history = store.get_recent_actions("session-1")
                    self.assertEqual(len(history), 4)
                    self.assertEqual(
                        {action.task_id for action in history},
                        {"task-0", "task-1", "task-2", "task-3"},
                    )
                finally:
                    cleanup()

    def test_existing_session_state_table_is_left_unused(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "sessions.db"
            import sqlite3

            with sqlite3.connect(database) as connection:
                connection.execute(
                    """
                    CREATE TABLE session_state (
                        session_id TEXT PRIMARY KEY,
                        active_task_id TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    "INSERT INTO session_state VALUES (?, ?, ?)",
                    ("session-1", "legacy-task", "2026-01-01T00:00:00+00:00"),
                )
            store = SQLiteSessionStore(database)
            store.append_action(
                "session-1",
                SessionAction(
                    action_type="shell.execute",
                    summary="Run tests",
                    task_id="current-task",
                ),
            )
            store.close()
            with sqlite3.connect(database) as connection:
                legacy = connection.execute(
                    "SELECT active_task_id FROM session_state WHERE session_id = ?",
                    ("session-1",),
                ).fetchone()
            self.assertEqual(legacy, ("legacy-task",))

    def test_attempt_reservation_is_idempotent_and_binding_conflicts_are_stable(self) -> None:
        for make_store in self._store_factories():
            with self.subTest(store=make_store.__name__):
                store, cleanup = make_store()
                try:
                    binding = self._attempt_binding()
                    first = store.reserve_attempt(binding)
                    duplicate = store.reserve_attempt(binding)
                    self.assertEqual(first, duplicate)
                    self.assertEqual(first.state, "reserved")

                    changed = ExecutionAttemptBinding(
                        **{
                            **self._model_data(binding),
                            "action_fingerprint": "b" * 64,
                        }
                    )
                    with self.assertRaisesRegex(
                        ExecutionAttemptConflictError,
                        "attempt:binding_conflict",
                    ):
                        store.reserve_attempt(changed)
                finally:
                    cleanup()

    def test_attempt_transitions_use_compare_and_swap_and_persist_response(self) -> None:
        for make_store in self._store_factories():
            with self.subTest(store=make_store.__name__):
                store, cleanup = make_store()
                try:
                    binding = self._attempt_binding()
                    store.reserve_attempt(binding)
                    running = store.transition_attempt(
                        binding.attempt_id,
                        expected_state="reserved",
                        new_state="running",
                    )
                    self.assertEqual(running.state, "running")
                    completed = store.transition_attempt(
                        binding.attempt_id,
                        expected_state="running",
                        new_state="completed",
                        response_payload={"request_id": "request-1", "verdict": "allow"},
                    )
                    self.assertEqual(completed.response_payload["verdict"], "allow")
                    self.assertIsNotNone(completed.finished_at)
                    with self.assertRaisesRegex(
                        ExecutionAttemptConflictError,
                        "attempt:state_conflict",
                    ):
                        store.transition_attempt(
                            binding.attempt_id,
                            expected_state="running",
                            new_state="failed",
                            response_payload={"request_id": "request-2"},
                        )
                finally:
                    cleanup()

    def test_attempt_response_payload_must_be_bounded_json(self) -> None:
        store = InMemorySessionStore()
        binding = self._attempt_binding()
        store.reserve_attempt(binding)
        store.transition_attempt(
            binding.attempt_id,
            expected_state="reserved",
            new_state="running",
        )

        with self.assertRaises(ValidationError):
            store.transition_attempt(
                binding.attempt_id,
                expected_state="running",
                new_state="completed",
                response_payload={"stdout": "x" * (257 * 1024)},
            )
        self.assertEqual(
            store.get_attempt(binding.attempt_id).state,  # type: ignore[union-attr]
            "running",
        )

    def test_sqlite_reopen_marks_running_attempt_unknown(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "sessions.db"
            first = SQLiteSessionStore(database)
            binding = self._attempt_binding()
            first.reserve_attempt(binding)
            first.transition_attempt(
                binding.attempt_id,
                expected_state="reserved",
                new_state="running",
            )
            first.close()

            reopened = SQLiteSessionStore(database)
            try:
                attempt = reopened.get_attempt(binding.attempt_id)
                assert attempt is not None
                self.assertEqual(attempt.state, "unknown")
                with self.assertRaisesRegex(
                    ExecutionAttemptConflictError,
                    "attempt:state_conflict",
                ):
                    reopened.transition_attempt(
                        binding.attempt_id,
                        expected_state="reserved",
                        new_state="running",
                    )
            finally:
                reopened.close()

    def test_second_live_sqlite_store_does_not_orphan_active_attempt(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "sessions.db"
            first = SQLiteSessionStore(database)
            binding = self._attempt_binding()
            first.reserve_attempt(binding)
            first.transition_attempt(
                binding.attempt_id,
                expected_state="reserved",
                new_state="running",
            )
            second = SQLiteSessionStore(database)
            try:
                attempt = second.get_attempt(binding.attempt_id)
                assert attempt is not None
                self.assertEqual(attempt.state, "running")
                completed = first.transition_attempt(
                    binding.attempt_id,
                    expected_state="running",
                    new_state="completed",
                    response_payload={"request_id": "request-1"},
                )
                self.assertEqual(completed.state, "completed")
            finally:
                second.close()
                first.close()

    def test_second_process_does_not_orphan_live_sqlite_attempt(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "sessions.db"
            first = SQLiteSessionStore(database)
            binding = self._attempt_binding()
            first.reserve_attempt(binding)
            first.transition_attempt(
                binding.attempt_id,
                expected_state="reserved",
                new_state="running",
            )
            code = """
import sys
from sentinel.session import SQLiteSessionStore
store = SQLiteSessionStore(sys.argv[1])
attempt = store.get_attempt("attempt-1")
print(attempt.state if attempt else "missing")
store.close()
"""
            try:
                result = subprocess.run(
                    [sys.executable, "-c", code, str(database)],
                    cwd=Path(__file__).resolve().parents[1],
                    env={
                        **os.environ,
                        "PYTHONPATH": str(
                            Path(__file__).resolve().parents[1] / "src"
                        ),
                    },
                    text=True,
                    capture_output=True,
                    check=True,
                    timeout=3,
                )
                self.assertEqual(result.stdout.strip(), "running")
                completed = first.transition_attempt(
                    binding.attempt_id,
                    expected_state="running",
                    new_state="completed",
                    response_payload={"request_id": "request-1"},
                )
                self.assertEqual(completed.state, "completed")
            finally:
                first.close()

    def _store_factories(
        self,
    ) -> list[Callable[[], tuple[SessionStore, Callable[[], None]]]]:
        def memory() -> tuple[SessionStore, Callable[[], None]]:
            return InMemorySessionStore(), lambda: None

        def sqlite() -> tuple[SessionStore, Callable[[], None]]:
            temporary = TemporaryDirectory()
            store = SQLiteSessionStore(Path(temporary.name) / "sessions.db")

            def cleanup() -> None:
                store.close()
                temporary.cleanup()

            return store, cleanup

        return [memory, sqlite]

    @staticmethod
    def _attempt_binding() -> ExecutionAttemptBinding:
        return ExecutionAttemptBinding(
            attempt_id="attempt-1",
            session_id="session-1",
            task_id="task-1",
            contract_id="contract-1",
            contract_version=1,
            authority_epoch=1,
            action_fingerprint="a" * 64,
            environment="sandbox",
        )

    @staticmethod
    def _model_data(value: object) -> dict[str, object]:
        if hasattr(value, "model_dump"):
            return value.model_dump()  # type: ignore[no-any-return, union-attr]
        return value.dict()  # type: ignore[no-any-return, union-attr]


if __name__ == "__main__":
    unittest.main()
