from __future__ import annotations

import json
import sqlite3
import sys
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock

from pydantic import ValidationError


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.audit import (  # noqa: E402
    AuditEvent,
    AuditFallbackFullError,
    AuditHealth,
    AuditQuery,
    AuditStore,
    SQLiteAuditStore,
)


class AuditStoreTests(unittest.TestCase):
    def test_audit_models_reject_unknown_fields(self) -> None:
        with self.assertRaises(ValidationError):
            AuditEvent(event_type="decision", event_typo="ignored")
        with self.assertRaises(ValidationError):
            AuditQuery(contract_iid="contract-1")
        with self.assertRaises(ValidationError):
            AuditHealth(
                status="ok",
                fallback_event_count=0,
                fallback_capacity=10,
                fallback_capcity=10,
            )

    def test_events_persist_across_reopen_and_support_indexed_filters(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "audit.db"
            first = SQLiteAuditStore(database)
            self.assertIsInstance(first, AuditStore)
            first.write(
                AuditEvent(
                    event_id="event-1",
                    sequence_id=99,
                    event_type="decision",
                    contract_id="contract-1",
                    agent_id="agent-1",
                    environment="sandbox",
                    verdict="allow",
                )
            )
            first.write(
                AuditEvent(
                    event_id="event-2",
                    event_type="decision",
                    contract_id="contract-2",
                    agent_id="agent-2",
                    environment="production",
                    verdict="block",
                )
            )
            first.close()

            reopened = SQLiteAuditStore(database)
            blocked = reopened.query(
                event_type="decision",
                verdict="block",
                environment="production",
                agent_id="agent-2",
                contract_id="contract-2",
            )
            all_events = reopened.query()
            reopened.close()

            self.assertEqual([event.event_id for event in blocked], ["event-2"])
            self.assertEqual(blocked[0].sequence_id, 2)
            self.assertEqual(
                [event.sequence_id for event in all_events],
                [1, 2],
            )

            with sqlite3.connect(database) as connection:
                indexes = {
                    row[1]
                    for row in connection.execute("PRAGMA index_list('audit_events')").fetchall()
                }
            for field in ("event_type", "verdict", "environment", "agent_id", "contract_id", "timestamp"):
                self.assertIn(f"idx_audit_events_{field}", indexes)

    def test_query_supports_timestamp_range(self) -> None:
        with TemporaryDirectory() as directory:
            store = SQLiteAuditStore(Path(directory) / "audit.db")
            base = datetime(2026, 8, 31, tzinfo=timezone.utc)
            for offset in range(3):
                store.write(
                    AuditEvent(
                        event_id=f"event-{offset}",
                        event_type="contract",
                        timestamp=base + timedelta(minutes=offset),
                    )
                )

            selected = store.query(
                start_time=base + timedelta(seconds=30),
                end_time=base + timedelta(minutes=1, seconds=30),
            )
            store.close()

            self.assertEqual([event.event_id for event in selected], ["event-1"])

    def test_query_supports_server_owned_session_and_task_filters(self) -> None:
        with TemporaryDirectory() as directory:
            store = SQLiteAuditStore(Path(directory) / "audit.db")
            for event_id, session_id, task_id in (
                ("event-1", "session-1", "task-1"),
                ("event-2", "session-1", "task-2"),
                ("event-3", "session-2", "task-1"),
            ):
                store.write(
                    AuditEvent(
                        event_id=event_id,
                        event_type="decision",
                        session_id=session_id,
                        task_id=task_id,
                    )
                )

            selected = store.query(
                session_id="session-1",
                task_id="task-1",
            )
            store.close()

        self.assertEqual(
            [event.event_id for event in selected],
            ["event-1"],
        )

    def test_query_limit_keeps_the_newest_matching_events_in_order(self) -> None:
        with TemporaryDirectory() as directory:
            store = SQLiteAuditStore(Path(directory) / "audit.db")
            for index in range(205):
                store.write(
                    AuditEvent(
                        event_id=f"event-{index + 1}",
                        event_type="decision",
                        session_id="session-1",
                    )
                )

            selected = store.query(session_id="session-1", limit=200)
            store.close()

        self.assertEqual(len(selected), 200)
        self.assertEqual(selected[0].event_id, "event-6")
        self.assertEqual(selected[-1].event_id, "event-205")

    def test_redacts_secrets_env_content_and_private_keys_before_persistence(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "audit.db"
            store = SQLiteAuditStore(database)
            store.write(
                AuditEvent(
                    event_id="secret-event",
                    event_type="decision",
                    reason_codes=["rule:credential_exfiltration", "contract:target_mismatch"],
                    details={
                        "password": "do-not-store",
                        "headers": {"Authorization": "Bearer do-not-store-token"},
                        "authorization_source": "protected_local_ui",
                        "env_file": {
                            "path": "/workspace/.env",
                            "content": "PUBLIC_NAME=sentinel\nAPI_KEY=do-not-store",
                        },
                        "key_material": (
                            "-----BEGIN PRIVATE KEY-----\n"
                            "do-not-store-private-material\n"
                            "-----END PRIVATE KEY-----"
                        ),
                    },
                )
            )
            event = store.query()[0]
            store.close()

            serialized = json.dumps(
                event.model_dump(mode="json") if hasattr(event, "model_dump") else json.loads(event.json())
            )
            self.assertNotIn("do-not-store", serialized)
            self.assertIn("[REDACTED]", serialized)
            self.assertEqual(
                event.details["authorization_source"],
                "protected_local_ui",
            )
            self.assertEqual(event.details["headers"]["Authorization"], "[REDACTED]")
            self.assertEqual(
                event.reason_codes,
                ["rule:credential_exfiltration", "contract:target_mismatch"],
            )

            raw_database = database.read_bytes()
            self.assertNotIn(b"do-not-store", raw_database)

    def test_concurrent_writes_are_not_lost(self) -> None:
        with TemporaryDirectory() as directory:
            store = SQLiteAuditStore(Path(directory) / "audit.db")
            barrier = threading.Barrier(8)
            errors: list[Exception] = []

            def write_batch(worker: int) -> None:
                try:
                    barrier.wait()
                    for item in range(20):
                        store.write(
                            AuditEvent(
                                event_id=f"{worker}-{item}",
                                event_type="execution",
                                agent_id=f"agent-{worker}",
                            )
                        )
                except Exception as exc:  # pragma: no cover - asserted on the main thread
                    errors.append(exc)

            threads = [threading.Thread(target=write_batch, args=(worker,)) for worker in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            events = store.query()
            health = store.health
            store.close()

            self.assertEqual(len(events), 160)
            self.assertEqual(len({event.event_id for event in events}), 160)
            self.assertEqual(errors, [])
            self.assertEqual(health.status, "ok")

    def test_jsonl_export_is_filtered_and_redacted(self) -> None:
        with TemporaryDirectory() as directory:
            store = SQLiteAuditStore(Path(directory) / "audit.db")
            store.write(
                AuditEvent(
                    event_id="allowed",
                    event_type="decision",
                    verdict="allow",
                    details={"api_key": "do-not-export"},
                )
            )
            store.write(AuditEvent(event_id="blocked", event_type="decision", verdict="block"))
            export_path = Path(directory) / "blocked.jsonl"

            count = store.export_jsonl(export_path, verdict="block")
            store.close()

            lines = export_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(count, 1)
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["event_id"], "blocked")
            self.assertNotIn("do-not-export", export_path.read_text(encoding="utf-8"))

    def test_failed_writes_degrade_then_explicitly_fail_when_fallback_is_full(self) -> None:
        with TemporaryDirectory() as directory:
            store = SQLiteAuditStore(Path(directory) / "audit.db", fallback_capacity=2)
            store._write_to_sqlite = Mock(  # type: ignore[method-assign]
                side_effect=sqlite3.OperationalError("simulated disk failure")
            )

            store.write(AuditEvent(event_id="fallback-1", event_type="failure"))
            store.write(AuditEvent(event_id="fallback-2", event_type="failure"))

            self.assertEqual(store.health.status, "degraded")
            self.assertEqual(store.health.fallback_event_count, 2)
            self.assertEqual(
                [event.event_id for event in store.query()],
                ["fallback-1", "fallback-2"],
            )
            with self.assertRaises(AuditFallbackFullError):
                store.write(AuditEvent(event_id="not-retained", event_type="failure"))
            self.assertEqual(store.health.fallback_event_count, 2)
            store.close()

    def test_successful_write_flushes_buffered_fallback_evidence(self) -> None:
        with TemporaryDirectory() as directory:
            store = SQLiteAuditStore(Path(directory) / "audit.db", fallback_capacity=2)
            sqlite_writer = store._write_to_sqlite
            store._write_to_sqlite = Mock(  # type: ignore[method-assign]
                side_effect=sqlite3.OperationalError("simulated transient failure")
            )
            store.write(AuditEvent(event_id="buffered", event_type="failure"))

            store._write_to_sqlite = sqlite_writer  # type: ignore[method-assign]
            store.write(AuditEvent(event_id="current", event_type="recovery"))

            self.assertEqual(
                {event.event_id for event in store.query()},
                {"buffered", "current"},
            )
            self.assertEqual(store.health.status, "ok")
            self.assertEqual(store.health.fallback_event_count, 0)
            store.close()

    def test_required_write_raises_instead_of_buffering_when_sqlite_is_degraded(self) -> None:
        with TemporaryDirectory() as directory:
            store = SQLiteAuditStore(Path(directory) / "audit.db", fallback_capacity=2)
            store.write(AuditEvent(event_id="buffered", event_type="ordinary"))
            store._write_to_sqlite = Mock(  # type: ignore[method-assign]
                side_effect=sqlite3.OperationalError("simulated disk failure")
            )

            with self.assertRaisesRegex(
                Exception,
                "required audit evidence could not be persisted",
            ):
                store.write_required(
                    AuditEvent(event_id="required", event_type="execution_admitted")
                )

            self.assertEqual(
                [event.event_id for event in store.query()],
                ["buffered"],
            )
            self.assertEqual(store.health.fallback_event_count, 0)
            store.close()

    def test_queries_use_monotonic_insert_sequence_for_equal_timestamps(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "audit.db"
            timestamp = datetime(2026, 9, 8, tzinfo=timezone.utc)
            store = SQLiteAuditStore(database)
            for event_id in ("z-last-lexically", "a-first-lexically", "m-middle"):
                store.write(
                    AuditEvent(
                        event_id=event_id,
                        event_type="ordered",
                        timestamp=timestamp,
                    )
                )
            self.assertEqual(
                [event.event_id for event in store.query()],
                ["z-last-lexically", "a-first-lexically", "m-middle"],
            )
            store.close()

            with sqlite3.connect(database) as connection:
                columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info('audit_events')"
                    ).fetchall()
                }
            self.assertIn("sequence_id", columns)

    def test_required_write_flushes_existing_fallback_in_same_commit(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "audit.db"
            store = SQLiteAuditStore(database, fallback_capacity=2)
            sqlite_writer = store._write_to_sqlite
            store._write_to_sqlite = Mock(  # type: ignore[method-assign]
                side_effect=sqlite3.OperationalError("simulated transient failure")
            )
            store.write(AuditEvent(event_id="buffered", event_type="ordinary"))
            store._write_to_sqlite = sqlite_writer  # type: ignore[method-assign]

            store.write_required(
                AuditEvent(event_id="required", event_type="execution_admitted")
            )

            self.assertEqual(
                [event.event_id for event in store.query()],
                ["buffered", "required"],
            )
            self.assertEqual(store.health.fallback_event_count, 0)
            store.close()

    def test_legacy_audit_table_migrates_without_reordering_events(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "audit.db"
            timestamp = "2026-09-08T00:00:00.000000+00:00"
            with sqlite3.connect(database) as connection:
                connection.execute(
                    """
                    CREATE TABLE audit_events (
                        event_id TEXT PRIMARY KEY,
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
                for event_id in ("z-first", "a-second"):
                    event = AuditEvent(
                        event_id=event_id,
                        event_type="legacy",
                        timestamp=datetime.fromisoformat(timestamp),
                        details=(
                            {"api_key": "legacy-secret"}
                            if event_id == "a-second"
                            else {}
                        ),
                    )
                    payload = (
                        event.model_dump(mode="json")
                        if hasattr(event, "model_dump")
                        else json.loads(event.json())
                    )
                    connection.execute(
                        """
                        INSERT INTO audit_events (
                            event_id, event_type, timestamp, verdict, environment,
                            agent_id, contract_id, event_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            event_id,
                            "legacy",
                            timestamp,
                            None,
                            None,
                            None,
                            None,
                            json.dumps(payload),
                        ),
                    )

            store = SQLiteAuditStore(database)
            try:
                migrated = store.query()
                self.assertEqual(
                    [event.event_id for event in migrated],
                    ["z-first", "a-second"],
                )
                self.assertEqual(
                    migrated[1].details["api_key"],
                    "[REDACTED]",
                )
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
