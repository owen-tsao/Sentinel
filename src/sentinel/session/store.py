"""Server-owned bounded recent-action stores."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .models import (
    ExecutionAttempt,
    ExecutionAttemptBinding,
    ExecutionAttemptState,
    SessionAction,
    utc_now,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows uses process-local fallback.
    fcntl = None  # type: ignore[assignment]

_OPEN_SQLITE_DATABASES: dict[str, int] = {}
_OPEN_SQLITE_DATABASES_LOCK = threading.Lock()


class ExecutionAttemptConflictError(ValueError):
    """Stable replay or compare-and-swap conflict."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@runtime_checkable
class SessionStore(Protocol):
    """Storage contract with no caller-controlled history replacement."""

    def append_action(self, session_id: str, action: SessionAction) -> None:
        ...

    def get_recent_actions(self, session_id: str, limit: int | None = None) -> list[SessionAction]:
        ...

    def reserve_attempt(self, binding: ExecutionAttemptBinding) -> ExecutionAttempt:
        ...

    def get_attempt(self, attempt_id: str) -> ExecutionAttempt | None:
        ...

    def transition_attempt(
        self,
        attempt_id: str,
        *,
        expected_state: ExecutionAttemptState,
        new_state: ExecutionAttemptState,
        response_payload: dict[str, Any] | None = None,
    ) -> ExecutionAttempt:
        ...


class InMemorySessionStore:
    """Thread-safe process-local history for tests and small deployments."""

    def __init__(self, *, max_history: int = 5) -> None:
        _validate_history_limit(max_history)
        self._max_history = max_history
        self._actions: dict[str, deque[SessionAction]] = {}
        self._attempts: dict[str, ExecutionAttempt] = {}
        self._lock = threading.RLock()

    def append_action(self, session_id: str, action: SessionAction) -> None:
        _validate_identifier("session_id", session_id)
        with self._lock:
            history = self._actions.setdefault(session_id, deque(maxlen=self._max_history))
            history.append(_copy_action(action))

    def get_recent_actions(self, session_id: str, limit: int | None = None) -> list[SessionAction]:
        _validate_identifier("session_id", session_id)
        selected_limit = _selected_limit(limit, self._max_history)
        with self._lock:
            history = list(self._actions.get(session_id, ()))
            return [_copy_action(action) for action in history[-selected_limit:]]

    def record_action(self, session_id: str, action: SessionAction) -> None:
        """Alias emphasizing that adapters append reports, never replace history."""

        self.append_action(session_id, action)

    def reserve_attempt(self, binding: ExecutionAttemptBinding) -> ExecutionAttempt:
        checked = _copy_binding(binding)
        with self._lock:
            existing = self._attempts.get(checked.attempt_id)
            if existing is not None:
                _require_same_binding(existing.binding, checked)
                return _copy_attempt(existing)
            now = utc_now()
            attempt = ExecutionAttempt(
                binding=checked,
                state="reserved",
                reserved_at=now,
                updated_at=now,
            )
            self._attempts[checked.attempt_id] = attempt
            return _copy_attempt(attempt)

    def get_attempt(self, attempt_id: str) -> ExecutionAttempt | None:
        _validate_identifier("attempt_id", attempt_id)
        with self._lock:
            attempt = self._attempts.get(attempt_id)
            return _copy_attempt(attempt) if attempt is not None else None

    def transition_attempt(
        self,
        attempt_id: str,
        *,
        expected_state: ExecutionAttemptState,
        new_state: ExecutionAttemptState,
        response_payload: dict[str, Any] | None = None,
    ) -> ExecutionAttempt:
        _validate_identifier("attempt_id", attempt_id)
        _validate_attempt_transition(expected_state, new_state)
        with self._lock:
            existing = self._attempts.get(attempt_id)
            if existing is None:
                raise ExecutionAttemptConflictError("attempt:not_found")
            if existing.state != expected_state:
                raise ExecutionAttemptConflictError("attempt:state_conflict")
            replacement = _transitioned_attempt(
                existing,
                new_state=new_state,
                response_payload=response_payload,
            )
            self._attempts[attempt_id] = replacement
            return _copy_attempt(replacement)


class SQLiteSessionStore:
    """Persistent SQLite WAL bounded recent-action history."""

    def __init__(
        self,
        database: str | Path,
        *,
        max_history: int = 5,
        timeout_seconds: float = 5.0,
    ) -> None:
        _validate_history_limit(max_history)
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

        self._max_history = max_history
        self._lock = threading.RLock()
        self._database_key = (
            None
            if str(database) == ":memory:"
            else str(Path(database).expanduser().resolve())
        )
        self._registered_database = False
        self._attempt_lock_file = None
        self._connection = sqlite3.connect(
            str(database),
            timeout=timeout_seconds,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(f"PRAGMA busy_timeout={int(timeout_seconds * 1_000)}")
        self._create_schema()
        self._initialize_attempt_recovery()

    def append_action(self, session_id: str, action: SessionAction) -> None:
        _validate_identifier("session_id", session_id)
        stored = _copy_action(action)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    """
                    INSERT INTO session_actions (
                        action_id, session_id, task_id, timestamp, action_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        stored.action_id,
                        session_id,
                        stored.task_id,
                        _timestamp_text(stored.timestamp),
                        json.dumps(_action_json_dict(stored), sort_keys=True, ensure_ascii=False),
                    ),
                )
                self._connection.execute(
                    """
                    DELETE FROM session_actions
                    WHERE session_id = ?
                      AND sequence_id NOT IN (
                          SELECT sequence_id
                          FROM session_actions
                          WHERE session_id = ?
                          ORDER BY sequence_id DESC
                          LIMIT ?
                      )
                    """,
                    (session_id, session_id, self._max_history),
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    def get_recent_actions(self, session_id: str, limit: int | None = None) -> list[SessionAction]:
        _validate_identifier("session_id", session_id)
        selected_limit = _selected_limit(limit, self._max_history)
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT action_json
                FROM session_actions
                WHERE session_id = ?
                ORDER BY sequence_id DESC
                LIMIT ?
                """,
                (session_id, selected_limit),
            ).fetchall()
        return [SessionAction(**json.loads(row["action_json"])) for row in reversed(rows)]

    def record_action(self, session_id: str, action: SessionAction) -> None:
        self.append_action(session_id, action)

    def reserve_attempt(self, binding: ExecutionAttemptBinding) -> ExecutionAttempt:
        checked = _copy_binding(binding)
        now = utc_now()
        attempt = ExecutionAttempt(
            binding=checked,
            state="reserved",
            reserved_at=now,
            updated_at=now,
        )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    """
                    SELECT attempt_json
                    FROM execution_attempts
                    WHERE attempt_id = ?
                    """,
                    (checked.attempt_id,),
                ).fetchone()
                if row is not None:
                    existing = _attempt_from_row(row)
                    _require_same_binding(existing.binding, checked)
                    self._connection.commit()
                    return existing
                self._connection.execute(
                    """
                    INSERT INTO execution_attempts (
                        attempt_id, session_id, state, updated_at, attempt_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        checked.attempt_id,
                        checked.session_id,
                        attempt.state,
                        _timestamp_text(attempt.updated_at),
                        _attempt_json(attempt),
                    ),
                )
                self._connection.commit()
                return _copy_attempt(attempt)
            except Exception:
                self._connection.rollback()
                raise

    def get_attempt(self, attempt_id: str) -> ExecutionAttempt | None:
        _validate_identifier("attempt_id", attempt_id)
        with self._lock:
            row = self._connection.execute(
                """
                SELECT attempt_json
                FROM execution_attempts
                WHERE attempt_id = ?
                """,
                (attempt_id,),
            ).fetchone()
        return _attempt_from_row(row) if row is not None else None

    def transition_attempt(
        self,
        attempt_id: str,
        *,
        expected_state: ExecutionAttemptState,
        new_state: ExecutionAttemptState,
        response_payload: dict[str, Any] | None = None,
    ) -> ExecutionAttempt:
        _validate_identifier("attempt_id", attempt_id)
        _validate_attempt_transition(expected_state, new_state)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    """
                    SELECT attempt_json
                    FROM execution_attempts
                    WHERE attempt_id = ?
                    """,
                    (attempt_id,),
                ).fetchone()
                if row is None:
                    raise ExecutionAttemptConflictError("attempt:not_found")
                existing = _attempt_from_row(row)
                if existing.state != expected_state:
                    raise ExecutionAttemptConflictError("attempt:state_conflict")
                replacement = _transitioned_attempt(
                    existing,
                    new_state=new_state,
                    response_payload=response_payload,
                )
                updated = self._connection.execute(
                    """
                    UPDATE execution_attempts
                    SET state = ?, updated_at = ?, attempt_json = ?
                    WHERE attempt_id = ? AND state = ?
                    """,
                    (
                        replacement.state,
                        _timestamp_text(replacement.updated_at),
                        _attempt_json(replacement),
                        attempt_id,
                        expected_state,
                    ),
                )
                if updated.rowcount != 1:
                    raise ExecutionAttemptConflictError("attempt:state_conflict")
                self._connection.commit()
                return _copy_attempt(replacement)
            except Exception:
                self._connection.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            self._connection.close()
            if self._attempt_lock_file is not None:
                if fcntl is not None:
                    fcntl.flock(self._attempt_lock_file.fileno(), fcntl.LOCK_UN)
                self._attempt_lock_file.close()
                self._attempt_lock_file = None
            if self._registered_database and self._database_key is not None:
                with _OPEN_SQLITE_DATABASES_LOCK:
                    remaining = _OPEN_SQLITE_DATABASES[self._database_key] - 1
                    if remaining == 0:
                        del _OPEN_SQLITE_DATABASES[self._database_key]
                    else:
                        _OPEN_SQLITE_DATABASES[self._database_key] = remaining
                self._registered_database = False

    def __enter__(self) -> SQLiteSessionStore:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _create_schema(self) -> None:
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS session_actions (
                    sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action_id TEXT NOT NULL UNIQUE,
                    session_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    action_json TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_session_actions_session_sequence
                ON session_actions (session_id, sequence_id)
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (
                        state IN ('reserved', 'running', 'completed', 'failed', 'unknown')
                    ),
                    updated_at TEXT NOT NULL,
                    attempt_json TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_execution_attempts_session_updated
                ON execution_attempts (session_id, updated_at)
                """
            )

    def _mark_orphaned_attempts_unknown(self) -> None:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                rows = self._connection.execute(
                    """
                    SELECT attempt_id, attempt_json
                    FROM execution_attempts
                    WHERE state = 'running'
                    """
                ).fetchall()
                for row in rows:
                    running = _attempt_from_row(row)
                    unknown = _transitioned_attempt(
                        running,
                        new_state="unknown",
                        response_payload=None,
                    )
                    self._connection.execute(
                        """
                        UPDATE execution_attempts
                        SET state = 'unknown', updated_at = ?, attempt_json = ?
                        WHERE attempt_id = ? AND state = 'running'
                        """,
                        (
                            _timestamp_text(unknown.updated_at),
                            _attempt_json(unknown),
                            running.attempt_id,
                        ),
                    )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    def _initialize_attempt_recovery(self) -> None:
        if self._database_key is None:
            self._mark_orphaned_attempts_unknown()
            return
        lock_path = Path(f"{self._database_key}.attempts.lock")
        self._attempt_lock_file = lock_path.open("a+b")
        with _OPEN_SQLITE_DATABASES_LOCK:
            local_store_open = _OPEN_SQLITE_DATABASES.get(
                self._database_key,
                0,
            ) > 0
            if fcntl is None:
                if not local_store_open:
                    self._mark_orphaned_attempts_unknown()
            elif local_store_open:
                fcntl.flock(self._attempt_lock_file.fileno(), fcntl.LOCK_SH)
            else:
                try:
                    fcntl.flock(
                        self._attempt_lock_file.fileno(),
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
                except BlockingIOError:
                    fcntl.flock(self._attempt_lock_file.fileno(), fcntl.LOCK_SH)
                else:
                    self._mark_orphaned_attempts_unknown()
                    fcntl.flock(self._attempt_lock_file.fileno(), fcntl.LOCK_SH)
            _OPEN_SQLITE_DATABASES[self._database_key] = (
                _OPEN_SQLITE_DATABASES.get(self._database_key, 0) + 1
            )
            self._registered_database = True

def _copy_action(action: SessionAction) -> SessionAction:
    if hasattr(action, "model_copy"):
        return action.model_copy(deep=True)
    return action.copy(deep=True)


def _copy_binding(binding: ExecutionAttemptBinding) -> ExecutionAttemptBinding:
    if hasattr(binding, "model_copy"):
        return binding.model_copy(deep=True)
    return binding.copy(deep=True)


def _copy_attempt(attempt: ExecutionAttempt) -> ExecutionAttempt:
    if hasattr(attempt, "model_copy"):
        return attempt.model_copy(deep=True)
    return attempt.copy(deep=True)


def _action_json_dict(action: SessionAction) -> dict[str, Any]:
    if hasattr(action, "model_dump"):
        return action.model_dump(mode="json", warnings=False)
    return json.loads(action.json())


def _attempt_json(attempt: ExecutionAttempt) -> str:
    if hasattr(attempt, "model_dump"):
        payload = attempt.model_dump(mode="json", warnings=False)
    else:
        payload = json.loads(attempt.json())
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _attempt_from_row(row: sqlite3.Row) -> ExecutionAttempt:
    return ExecutionAttempt(**json.loads(row["attempt_json"]))


def _require_same_binding(
    existing: ExecutionAttemptBinding,
    requested: ExecutionAttemptBinding,
) -> None:
    if existing != requested:
        raise ExecutionAttemptConflictError("attempt:binding_conflict")


def _validate_attempt_transition(
    expected_state: ExecutionAttemptState,
    new_state: ExecutionAttemptState,
) -> None:
    allowed = {
        "reserved": {"running", "unknown"},
        "running": {"completed", "failed", "unknown"},
        "completed": set(),
        "failed": set(),
        "unknown": set(),
    }
    if new_state not in allowed[expected_state]:
        raise ValueError(f"invalid attempt transition: {expected_state}->{new_state}")


def _transitioned_attempt(
    attempt: ExecutionAttempt,
    *,
    new_state: ExecutionAttemptState,
    response_payload: dict[str, Any] | None,
) -> ExecutionAttempt:
    now = utc_now()
    data = _attempt_model_dict(attempt)
    data.update(
        {
            "state": new_state,
            "updated_at": now,
            "started_at": (
                now
                if new_state == "running" and attempt.started_at is None
                else attempt.started_at
            ),
            "finished_at": (
                now if new_state in {"completed", "failed", "unknown"} else None
            ),
            "response_payload": response_payload,
        }
    )
    return ExecutionAttempt(**data)


def _attempt_model_dict(attempt: ExecutionAttempt) -> dict[str, Any]:
    if hasattr(attempt, "model_dump"):
        return attempt.model_dump(mode="python", warnings=False)
    return attempt.dict()


def _timestamp_text(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _selected_limit(requested: int | None, maximum: int) -> int:
    if requested is None:
        return maximum
    if requested <= 0:
        raise ValueError("limit must be positive")
    return min(requested, maximum)


def _validate_history_limit(max_history: int) -> None:
    if max_history <= 0:
        raise ValueError("max_history must be positive")


def _validate_identifier(name: str, value: str) -> None:
    if not value.strip():
        raise ValueError(f"{name} must not be empty")
