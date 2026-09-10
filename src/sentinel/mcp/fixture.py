"""Isolated, disposable local issue fixture with durable operation state.

The fixture is the only thing that can create a note, and it only does so for
an operation that Sentinel prepared, admitted, and bound to one exact payload.
State machine:

    prepared -> admitted -> applying -> succeeded | failed | unknown

`applying` is written in its own short transaction before the effect so that a
crash between the two leaves visible evidence. The effect and the terminal
result are written in one transaction, so a note and its record always appear
together. An `applying` row found at startup becomes `unknown` and is never
retried automatically.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal

OperationState = Literal["prepared", "admitted", "applying", "succeeded", "failed", "unknown"]
FixtureOperationKind = Literal["issue_read", "issue_add_note"]


class FixtureError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class OperationBinding:
    """Everything one fixture operation is bound to; any change is a new action."""

    attempt_id: str
    adapter_session_id: str
    supervision_session_id: str
    task_id: str
    contract_version: int
    authority_epoch: str
    policy_sha256: str
    tool: str
    operation: FixtureOperationKind
    issue_id: str
    note_body: str | None = None

    @property
    def payload_sha256(self) -> str:
        payload = {
            "operation": self.operation,
            "issue_id": self.issue_id,
            "note_body": self.note_body,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    @property
    def binding_sha256(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class FixtureOperation:
    attempt_id: str
    state: OperationState
    binding_sha256: str
    payload_sha256: str
    operation: str
    issue_id: str
    result: dict[str, Any] | None
    updated_at: datetime


@dataclass(frozen=True)
class FixtureIssue:
    issue_id: str
    title: str
    notes: tuple[str, ...]


class SQLiteIssueFixture:
    """Fixture state and operation records in one SQLite database."""

    def __init__(self, database: str | Path, *, timeout_seconds: float = 5.0) -> None:
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(str(database), timeout=timeout_seconds, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.isolation_level = None
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(f"PRAGMA busy_timeout={int(timeout_seconds * 1_000)}")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS fixture_issues (
                issue_id TEXT PRIMARY KEY,
                title TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS fixture_notes (
                note_id INTEGER PRIMARY KEY AUTOINCREMENT,
                issue_id TEXT NOT NULL REFERENCES fixture_issues(issue_id),
                body TEXT NOT NULL,
                attempt_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS fixture_operations (
                attempt_id TEXT PRIMARY KEY,
                binding_sha256 TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                adapter_session_id TEXT NOT NULL,
                supervision_session_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                contract_version INTEGER NOT NULL,
                authority_epoch TEXT NOT NULL,
                policy_sha256 TEXT NOT NULL,
                tool TEXT NOT NULL,
                operation TEXT NOT NULL,
                issue_id TEXT NOT NULL,
                state TEXT NOT NULL,
                result_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        self.recover()

    # -- trusted launcher operations -------------------------------------------------

    def seed(self, issues: dict[str, str]) -> None:
        """Seed issues from the trusted launcher; never reachable through MCP."""

        with self._lock, self._transaction():
            for issue_id, title in issues.items():
                self._connection.execute(
                    "INSERT OR IGNORE INTO fixture_issues (issue_id, title) VALUES (?, ?)",
                    (issue_id, title),
                )

    def recover(self) -> list[str]:
        """Mark interrupted applications unknown. Called at startup, never retried."""

        with self._lock, self._transaction():
            rows = self._connection.execute(
                "SELECT attempt_id FROM fixture_operations WHERE state = 'applying'"
            ).fetchall()
            for row in rows:
                self._connection.execute(
                    "UPDATE fixture_operations SET state = 'unknown', updated_at = ? WHERE attempt_id = ?",
                    (_now(), row["attempt_id"]),
                )
            return [row["attempt_id"] for row in rows]

    # -- mediated operations -----------------------------------------------------------

    def issue_exists(self, issue_id: str) -> bool:
        with self._lock:
            return (
                self._connection.execute(
                    "SELECT 1 FROM fixture_issues WHERE issue_id = ?", (issue_id,)
                ).fetchone()
                is not None
            )

    def prepare(self, binding: OperationBinding) -> FixtureOperation:
        """Record the exact bound action before any decision is acted on."""

        with self._lock, self._transaction():
            existing = self._row(binding.attempt_id)
            if existing is not None:
                if existing["binding_sha256"] != binding.binding_sha256:
                    raise FixtureError("fixture:attempt_binding_mismatch")
                return _operation(existing)
            if not self.issue_exists(binding.issue_id):
                raise FixtureError("fixture:unknown_issue")
            now = _now()
            self._connection.execute(
                """
                INSERT INTO fixture_operations (
                    attempt_id, binding_sha256, payload_sha256, adapter_session_id,
                    supervision_session_id, task_id, contract_version, authority_epoch,
                    policy_sha256, tool, operation, issue_id, state, result_json,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', NULL, ?, ?)
                """,
                (
                    binding.attempt_id, binding.binding_sha256, binding.payload_sha256,
                    binding.adapter_session_id, binding.supervision_session_id, binding.task_id,
                    binding.contract_version, binding.authority_epoch, binding.policy_sha256,
                    binding.tool, binding.operation, binding.issue_id, now, now,
                ),
            )
            return _operation(self._row(binding.attempt_id))

    def admit(self, attempt_id: str) -> FixtureOperation:
        """Move prepared -> admitted once durable audit admission has succeeded."""

        with self._lock, self._transaction():
            row = self._require(attempt_id)
            if row["state"] == "admitted":
                return _operation(row)
            if row["state"] != "prepared":
                raise FixtureError(f"fixture:cannot_admit_from_{row['state']}")
            self._connection.execute(
                "UPDATE fixture_operations SET state = 'admitted', updated_at = ? WHERE attempt_id = ?",
                (_now(), attempt_id),
            )
            return _operation(self._row(attempt_id))

    def apply(
        self,
        binding: OperationBinding,
        *,
        fault_between_applying_and_effect: Callable[[], None] | None = None,
        fault_inside_effect: Callable[[], None] | None = None,
    ) -> FixtureOperation:
        """Perform the bound effect exactly once and store its terminal result atomically.

        The two fault hooks exist only for crash tests. The first simulates a
        crash after `applying` is durable but before the effect; the second
        simulates a crash inside the effect transaction, which must roll back
        both the note and the state change together.
        """

        with self._lock:
            with self._transaction():
                row = self._require(binding.attempt_id)
                if row["binding_sha256"] != binding.binding_sha256:
                    raise FixtureError("fixture:attempt_binding_mismatch")
                state = row["state"]
                if state in {"succeeded", "failed", "unknown"}:
                    return _operation(row, duplicate_suppressed=state == "succeeded")
                if state != "admitted":
                    raise FixtureError(f"fixture:cannot_apply_from_{state}")
                self._connection.execute(
                    "UPDATE fixture_operations SET state = 'applying', updated_at = ? WHERE attempt_id = ?",
                    (_now(), binding.attempt_id),
                )
            if fault_between_applying_and_effect is not None:
                fault_between_applying_and_effect()
            try:
                with self._transaction():
                    result = self._effect(binding)
                    if fault_inside_effect is not None:
                        fault_inside_effect()
                    self._connection.execute(
                        "UPDATE fixture_operations SET state = 'succeeded', result_json = ?, updated_at = ? "
                        "WHERE attempt_id = ?",
                        (json.dumps(result, sort_keys=True), _now(), binding.attempt_id),
                    )
            except FixtureError:
                with self._transaction():
                    self._connection.execute(
                        "UPDATE fixture_operations SET state = 'failed', updated_at = ? WHERE attempt_id = ?",
                        (_now(), binding.attempt_id),
                    )
                raise
            return _operation(self._row(binding.attempt_id))

    def fail(self, attempt_id: str, *, reason: str) -> FixtureOperation:
        """Close a prepared or admitted operation without an effect (denial, invalidation)."""

        with self._lock, self._transaction():
            row = self._require(attempt_id)
            if row["state"] in {"succeeded", "failed", "unknown"}:
                return _operation(row)
            if row["state"] == "applying":
                raise FixtureError("fixture:cannot_fail_while_applying")
            self._connection.execute(
                "UPDATE fixture_operations SET state = 'failed', result_json = ?, updated_at = ? "
                "WHERE attempt_id = ?",
                (json.dumps({"failed_reason": reason}, sort_keys=True), _now(), attempt_id),
            )
            return _operation(self._row(attempt_id))

    def get(self, attempt_id: str) -> FixtureOperation | None:
        with self._lock:
            row = self._row(attempt_id)
            return _operation(row) if row is not None else None

    def issue(self, issue_id: str) -> FixtureIssue | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT title FROM fixture_issues WHERE issue_id = ?", (issue_id,)
            ).fetchone()
            if row is None:
                return None
            notes = self._connection.execute(
                "SELECT body FROM fixture_notes WHERE issue_id = ? ORDER BY note_id", (issue_id,)
            ).fetchall()
            return FixtureIssue(issue_id=issue_id, title=row["title"], notes=tuple(n["body"] for n in notes))

    def note_count(self) -> int:
        with self._lock:
            return int(self._connection.execute("SELECT COUNT(*) FROM fixture_notes").fetchone()[0])

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    # -- internals --------------------------------------------------------------------

    def _effect(self, binding: OperationBinding) -> dict[str, Any]:
        issue = self.issue(binding.issue_id)
        if issue is None:
            raise FixtureError("fixture:unknown_issue")
        if binding.operation == "issue_read":
            return {"issue_id": issue.issue_id, "title": issue.title, "notes": list(issue.notes), "note_added": False}
        if binding.operation == "issue_add_note":
            if not binding.note_body:
                raise FixtureError("fixture:note_body_required")
            self._connection.execute(
                "INSERT INTO fixture_notes (issue_id, body, attempt_id, created_at) VALUES (?, ?, ?, ?)",
                (binding.issue_id, binding.note_body, binding.attempt_id, _now()),
            )
            return {"issue_id": issue.issue_id, "note_added": True, "note_sha256": _sha(binding.note_body)}
        raise FixtureError("fixture:unsupported_operation")

    def _transaction(self) -> "_Transaction":
        return _Transaction(self._connection)

    def _row(self, attempt_id: str) -> sqlite3.Row | None:
        return self._connection.execute(
            "SELECT * FROM fixture_operations WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()

    def _require(self, attempt_id: str) -> sqlite3.Row:
        row = self._row(attempt_id)
        if row is None:
            raise FixtureError("fixture:unknown_attempt")
        return row


class _Transaction:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def __enter__(self) -> None:
        self._connection.execute("BEGIN IMMEDIATE")

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if exc_type is None:
            self._connection.execute("COMMIT")
        else:
            self._connection.execute("ROLLBACK")


def _operation(row: sqlite3.Row, *, duplicate_suppressed: bool = False) -> FixtureOperation:
    result = json.loads(row["result_json"]) if row["result_json"] else None
    if result is not None and duplicate_suppressed:
        result = {**result, "note_added": False, "duplicate_suppressed": True}
    return FixtureOperation(
        attempt_id=row["attempt_id"],
        state=row["state"],
        binding_sha256=row["binding_sha256"],
        payload_sha256=row["payload_sha256"],
        operation=row["operation"],
        issue_id=row["issue_id"],
        result=result,
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
