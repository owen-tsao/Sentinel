"""SQLite WAL audit backend with a bounded failure fallback."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO, Union, cast

from .base import AuditFallbackFullError, AuditStoreError
from .models import AuditEvent, AuditHealth, AuditQuery
from .redaction import redact

_FILTER_COLUMNS = {
    "event_type": "event_type",
    "verdict": "verdict",
    "environment": "environment",
    "agent_id": "agent_id",
    "contract_id": "contract_id",
}


class SQLiteAuditStore:
    """Append-only local audit storage.

    Failed writes are retained in memory up to ``fallback_capacity``. A later
    successful write flushes that backlog in the same transaction as the new
    event, so callers can inspect degraded health without losing evidence.
    """

    def __init__(
        self,
        database: str | Path,
        *,
        fallback_capacity: int = 1_000,
        timeout_seconds: float = 5.0,
    ) -> None:
        if fallback_capacity < 0:
            raise ValueError("fallback_capacity must be non-negative")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

        self._database = str(database)
        self._fallback_capacity = fallback_capacity
        self._fallback: list[AuditEvent] = []
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        self._degraded_detail: str | None = None
        try:
            connection = sqlite3.connect(
                self._database,
                timeout=timeout_seconds,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA secure_delete=ON")
            connection.execute(f"PRAGMA busy_timeout={int(timeout_seconds * 1_000)}")
            self._connection = connection
            self._create_schema()
        except sqlite3.Error as exc:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
            self._degraded_detail = f"SQLite unavailable: {exc}"

    @property
    def health(self) -> AuditHealth:
        with self._lock:
            return AuditHealth(
                status="degraded" if self._degraded_detail is not None else "ok",
                detail=self._degraded_detail,
                fallback_event_count=len(self._fallback),
                fallback_capacity=self._fallback_capacity,
            )

    def write(self, event: AuditEvent) -> None:
        safe_event = _redacted_event(event)
        with self._lock:
            pending = [*self._fallback, safe_event]
            try:
                self._write_to_sqlite(pending)
            except sqlite3.IntegrityError as exc:
                raise AuditStoreError(
                    "audit event could not be appended because its event_id already exists"
                ) from exc
            except sqlite3.Error as exc:
                self._degraded_detail = f"SQLite write failed: {exc}"
                if len(self._fallback) >= self._fallback_capacity:
                    raise AuditFallbackFullError(
                        "audit evidence could not be persisted: SQLite failed and the fallback is full"
                    ) from exc
                self._fallback.append(safe_event)
                return

            self._fallback.clear()
            self._degraded_detail = None

    def write_required(self, event: AuditEvent) -> None:
        """Commit required evidence and any backlog, never buffer success."""

        safe_event = _redacted_event(event)
        with self._lock:
            pending = [*self._fallback, safe_event]
            try:
                self._write_to_sqlite(pending)
            except sqlite3.IntegrityError as exc:
                self._degraded_detail = f"SQLite required write failed: {exc}"
                raise AuditStoreError(
                    "required audit evidence could not be persisted because an event_id already exists"
                ) from exc
            except sqlite3.Error as exc:
                self._degraded_detail = f"SQLite required write failed: {exc}"
                raise AuditStoreError(
                    "required audit evidence could not be persisted"
                ) from exc
            self._fallback.clear()
            self._degraded_detail = None

    def query(self, filters: AuditQuery | None = None, **filter_values: object) -> list[AuditEvent]:
        selected = _coerce_query(filters, filter_values)
        with self._lock:
            persisted = self._query_sqlite(selected)
            buffered = [event for event in self._fallback if _matches(event, selected)]

        combined = [*persisted, *buffered]
        if selected.limit is not None:
            return combined[: selected.limit]
        return combined

    def export_jsonl(
        self,
        destination: str | Path | TextIO,
        filters: AuditQuery | None = None,
        **filter_values: object,
    ) -> int:
        events = self.query(filters, **filter_values)
        should_close = not hasattr(destination, "write")
        stream: TextIO
        if should_close:
            stream = Path(cast(Union[str, Path], destination)).open("w", encoding="utf-8")
        else:
            stream = cast(TextIO, destination)

        try:
            for event in events:
                stream.write(json.dumps(_event_json_dict(event), sort_keys=True, ensure_ascii=False) + "\n")
        finally:
            if should_close:
                stream.close()
        return len(events)

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def __enter__(self) -> SQLiteAuditStore:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _create_schema(self) -> None:
        connection = self._require_connection()
        with connection:
            table_exists = connection.execute(
                """
                SELECT 1
                FROM sqlite_master
                WHERE type = 'table' AND name = 'audit_events'
                """
            ).fetchone()
            if table_exists is not None:
                columns = {
                    row["name"]
                    for row in connection.execute(
                        "PRAGMA table_info('audit_events')"
                    ).fetchall()
                }
                if "sequence_id" not in columns:
                    legacy_rows = connection.execute(
                        """
                        SELECT
                            event_id, event_type, timestamp, verdict, environment,
                            agent_id, contract_id, event_json
                        FROM audit_events
                        ORDER BY rowid
                        """
                    ).fetchall()
                    connection.execute(
                        "ALTER TABLE audit_events RENAME TO audit_events_legacy"
                    )
                    self._create_events_table(connection)
                    connection.executemany(
                        """
                        INSERT INTO audit_events (
                            event_id, event_type, timestamp, verdict, environment,
                            agent_id, contract_id, event_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        [
                            (
                                row["event_id"],
                                row["event_type"],
                                row["timestamp"],
                                row["verdict"],
                                row["environment"],
                                row["agent_id"],
                                row["contract_id"],
                                json.dumps(
                                    redact(json.loads(row["event_json"])),
                                    sort_keys=True,
                                    ensure_ascii=False,
                                ),
                            )
                            for row in legacy_rows
                        ],
                    )
                    connection.execute("DROP TABLE audit_events_legacy")
            else:
                self._create_events_table(connection)
            for column in (
                "event_type",
                "verdict",
                "environment",
                "agent_id",
                "contract_id",
                "timestamp",
                "sequence_id",
            ):
                connection.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_audit_events_{column} ON audit_events ({column})"
                )

    @staticmethod
    def _create_events_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                verdict TEXT,
                environment TEXT,
                agent_id TEXT,
                contract_id TEXT,
                event_json TEXT NOT NULL
            )
            """
        )

    def _write_to_sqlite(self, events: list[AuditEvent]) -> None:
        connection = self._require_connection()
        rows = [
            (
                event.event_id,
                event.event_type,
                _timestamp_text(event.timestamp),
                event.verdict,
                event.environment,
                event.agent_id,
                event.contract_id,
                json.dumps(_event_json_dict(event), sort_keys=True, ensure_ascii=False),
            )
            for event in events
        ]
        with connection:
            connection.executemany(
                """
                INSERT INTO audit_events (
                    event_id, event_type, timestamp, verdict, environment,
                    agent_id, contract_id, event_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def _query_sqlite(self, filters: AuditQuery) -> list[AuditEvent]:
        if self._connection is None:
            return []

        clauses: list[str] = []
        parameters: list[object] = []
        data = _model_data(filters)
        for field, column in _FILTER_COLUMNS.items():
            value = data.get(field)
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        if filters.start_time is not None:
            clauses.append("timestamp >= ?")
            parameters.append(_timestamp_text(filters.start_time))
        if filters.end_time is not None:
            clauses.append("timestamp <= ?")
            parameters.append(_timestamp_text(filters.end_time))

        statement = "SELECT sequence_id, event_json FROM audit_events"
        if clauses:
            statement += " WHERE " + " AND ".join(clauses)
        statement += " ORDER BY sequence_id ASC"
        rows = self._connection.execute(statement, parameters).fetchall()
        events = []
        for row in rows:
            payload = json.loads(row["event_json"])
            payload["sequence_id"] = row["sequence_id"]
            events.append(AuditEvent(**payload))
        matching = [event for event in events if _matches(event, filters)]
        if filters.limit is not None:
            return matching[-filters.limit :]
        return matching

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise sqlite3.OperationalError("SQLite connection is unavailable")
        return self._connection


def _redacted_event(event: AuditEvent) -> AuditEvent:
    payload = redact(_event_json_dict(event))
    payload["sequence_id"] = None
    return AuditEvent(**payload)


def _event_json_dict(event: AuditEvent) -> dict[str, Any]:
    if hasattr(event, "model_dump"):
        return event.model_dump(mode="json", warnings=False)
    return json.loads(event.json())


def _model_data(model: AuditQuery) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="python", warnings=False)
    return model.dict()


def _coerce_query(filters: AuditQuery | None, values: dict[str, object]) -> AuditQuery:
    if filters is not None and values:
        raise ValueError("pass either an AuditQuery or keyword filters, not both")
    if filters is not None:
        return filters
    return AuditQuery(**values)


def _timestamp_text(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _matches(event: AuditEvent, filters: AuditQuery) -> bool:
    for field in (*_FILTER_COLUMNS, "session_id", "task_id"):
        expected = getattr(filters, field)
        if expected is not None and getattr(event, field) != expected:
            return False
    event_time = event.timestamp
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)
    if filters.start_time is not None and event_time < _as_utc(filters.start_time):
        return False
    if filters.end_time is not None and event_time > _as_utc(filters.end_time):
        return False
    return True


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
