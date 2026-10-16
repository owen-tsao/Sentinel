"""Decision record storage: columns, filters, migration race, lenient read."""

from __future__ import annotations

import json
import sqlite3
import sys
import unittest
from unittest import mock
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sentinel.audit import AuditEvent, AuditQuery, SQLiteAuditStore  # noqa: E402
from sentinel.audit.sqlite_store import _redacted_event  # noqa: E402

from test_decision_record import fs_target, home_wipe_record, judgment, shell_action  # noqa: E402
from sentinel.decisions import DecisionRecord  # noqa: E402


def credential_read_record() -> DecisionRecord:
    return DecisionRecord(
        action=shell_action("cat ~/.aws/credentials", [
            fs_target("~/.aws/credentials", "/Users/dev/.aws/credentials", "credential", kind="read"),
        ]),
        judgment=judgment("block", rule_id="F3.credential_read", reason="Reads a credential store."),
    )


def benign_record() -> DecisionRecord:
    return DecisionRecord(
        action=shell_action("rm -rf node_modules", [fs_target("node_modules", "/Users/dev/proj/node_modules", "inside")]),
        judgment=judgment("allow", reason="Inside the working directory."),
    )


class DecisionStorageTests(unittest.TestCase):
    def test_rule_and_zone_filters_in_sql_and_in_fallback(self) -> None:
        with TemporaryDirectory() as directory:
            store = SQLiteAuditStore(Path(directory) / "audit.db")
            store.write(AuditEvent(event_id="e-home", event_type="decision", decision=home_wipe_record()))
            store.write(AuditEvent(event_id="e-cred", event_type="decision", decision=credential_read_record()))
            store.write(AuditEvent(event_id="e-ok", event_type="decision", decision=benign_record()))
            store.write(AuditEvent(event_id="e-legacy", event_type="decision", verdict="allow", details={"tool": "x"}))

            self.assertEqual([e.event_id for e in store.query(zone="root")], ["e-home"])
            self.assertEqual([e.event_id for e in store.query(zone="credential")], ["e-cred"])
            self.assertEqual([e.event_id for e in store.query(rule_id="F3.credential_read")], ["e-cred"])
            self.assertEqual([e.event_id for e in store.query(AuditQuery(zone="inside", verdict="allow"))], ["e-ok"])
            self.assertEqual(store.query(zone="home"), [])
            # Legacy rows have NULL decision_zones and are excluded, not errors.
            self.assertEqual(len(store.query(event_type="decision")), 4)

            # Force the fallback path: a failed write buffers the event in memory,
            # and the in-memory matcher must answer the same filters as SQL.
            with mock.patch.object(store, "_write_to_sqlite", side_effect=sqlite3.OperationalError("simulated")):
                store.write(AuditEvent(event_id="e-buffered", event_type="decision", decision=home_wipe_record()))
            self.assertEqual(store.health.status, "degraded")
            self.assertEqual([e.event_id for e in store.query(zone="root")], ["e-home", "e-buffered"])
            self.assertEqual([e.event_id for e in store.query(rule_id="F1.delete_root")], ["e-home", "e-buffered"])
            self.assertEqual([e.event_id for e in store.query(zone="credential")], ["e-cred"])
            self.assertEqual(store.query(rule_id="nope"), [])
            store.close()

    def test_existing_database_gains_the_columns_without_rewriting_rows(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "audit.db"
            raw = sqlite3.connect(database)
            raw.execute(
                "CREATE TABLE audit_events (sequence_id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,"
                " event_type TEXT NOT NULL, timestamp TEXT NOT NULL, verdict TEXT, environment TEXT, agent_id TEXT,"
                " contract_id TEXT, event_json TEXT NOT NULL)"
            )
            legacy = {"event_id": "old-1", "event_type": "decision", "timestamp": "2026-01-01T00:00:00+00:00",
                      "verdict": "allow", "reason_codes": [], "details": {"tool": "legacy"}}
            raw.execute("INSERT INTO audit_events (event_id, event_type, timestamp, verdict, event_json) VALUES (?,?,?,?,?)",
                        ("old-1", "decision", legacy["timestamp"], "allow", json.dumps(legacy)))
            raw.commit()
            raw.close()

            store = SQLiteAuditStore(database)
            self.assertEqual(store.health.status, "ok")
            columns = {r[1] for r in store._connection.execute("PRAGMA table_info('audit_events')")}  # noqa: SLF001
            self.assertTrue({"decision_rule_id", "decision_zones"} <= columns)
            old = store.query(event_type="decision")
            self.assertEqual([e.event_id for e in old], ["old-1"])
            self.assertIsNone(old[0].decision)
            store.write(AuditEvent(event_id="new-1", event_type="decision", decision=home_wipe_record()))
            self.assertEqual([e.event_id for e in store.query(zone="root")], ["new-1"])
            store.close()

    def test_two_openers_racing_on_the_column_add_do_not_degrade(self) -> None:
        """Simulate the loser of the ALTER TABLE race: the column already exists
        by the time this opener's ALTER runs."""
        with TemporaryDirectory() as directory:
            database = Path(directory) / "audit.db"
            raw = sqlite3.connect(database)
            raw.execute(
                "CREATE TABLE audit_events (sequence_id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,"
                " event_type TEXT NOT NULL, timestamp TEXT NOT NULL, verdict TEXT, environment TEXT, agent_id TEXT,"
                " contract_id TEXT, event_json TEXT NOT NULL)"
            )
            raw.commit()

            class RacingConnection(sqlite3.Connection):
                def execute(self, sql, *args):  # type: ignore[no-untyped-def]
                    if isinstance(sql, str) and sql.startswith("ALTER TABLE audit_events ADD COLUMN"):
                        raw.execute(sql)  # the other process wins first
                        raw.commit()
                    return super().execute(sql, *args)

            real_connect = sqlite3.connect
            with mock.patch("sentinel.audit.sqlite_store.sqlite3.connect",
                            lambda *a, **k: real_connect(*a, factory=RacingConnection, **k)):
                store = SQLiteAuditStore(database)
            raw.close()
            self.assertEqual(store.health.status, "ok", store.health.detail)
            store.write_required(AuditEvent(event_id="n", event_type="decision", decision=home_wipe_record()))
            self.assertEqual(len(store.query(zone="root")), 1)
            store.close()

    def test_unparseable_decision_block_degrades_the_row_not_the_query(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "audit.db"
            store = SQLiteAuditStore(database)
            store.write(AuditEvent(event_id="good", event_type="decision", decision=home_wipe_record()))
            store.close()
            raw = sqlite3.connect(database)
            future = {"event_id": "future", "event_type": "decision", "timestamp": "2026-01-02T00:00:00+00:00",
                      "verdict": "block", "reason_codes": [], "details": {},
                      "decision": {"schema_version": 2, "action": {"brand_new_field": True}, "judgment": {}}}
            raw.execute("INSERT INTO audit_events (event_id, event_type, timestamp, verdict, event_json) VALUES (?,?,?,?,?)",
                        ("future", "decision", future["timestamp"], "block", json.dumps(future)))
            raw.commit()
            raw.close()

            store = SQLiteAuditStore(database)
            events = store.query(event_type="decision")
            store.close()
        by_id = {e.event_id: e for e in events}
        self.assertEqual(set(by_id), {"good", "future"})
        self.assertIsNotNone(by_id["good"].decision)
        self.assertIsNone(by_id["future"].decision)
        self.assertEqual(by_id["future"].details["decision_unparsed"]["schema_version"], 2)
        self.assertIn("validation error", by_id["future"].details["decision_unparsed_error"])

    def test_content_hash_matches_between_writer_and_reader(self) -> None:
        """The hash must be over what is persisted (the redacted record)."""
        record = DecisionRecord(
            action=shell_action("export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123 && git push", []),
            judgment=judgment("allow"),
        )
        event = AuditEvent(event_type="decision", decision=record)
        pre_write_hash = record.content_sha256()
        redacted_hash = _redacted_event(event).decision.content_sha256()
        with TemporaryDirectory() as directory:
            store = SQLiteAuditStore(Path(directory) / "audit.db")
            store.write(event)
            stored = store.query(event_type="decision")[0].decision
            store.close()
        self.assertNotEqual(pre_write_hash, redacted_hash)  # redaction changed raw
        self.assertEqual(stored.content_sha256(), redacted_hash)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz0123", stored.action.raw)

    def test_redaction_growth_cannot_demote_the_record(self) -> None:
        """`TOKEN=x` lines grow under redaction; the record must stay typed."""
        raw = "\n".join(f"export TOKEN{i}=x" for i in range(2_000))  # ~32k, grows ~2x when redacted
        record = DecisionRecord(action=shell_action(raw, [fs_target("~", "/Users/dev", "home")]),
                                judgment=judgment("block"))
        with TemporaryDirectory() as directory:
            store = SQLiteAuditStore(Path(directory) / "audit.db")
            store.write(AuditEvent(event_id="grown", event_type="decision", decision=record))
            rows = store.query(zone="home")
            store.close()
        self.assertEqual([e.event_id for e in rows], ["grown"])
        self.assertIsNotNone(rows[0].decision)
        self.assertLessEqual(len(rows[0].decision.action.raw), 32_000)
        self.assertNotIn("=x", rows[0].decision.action.raw)

    def test_redaction_growth_on_any_bounded_field_is_clamped_not_demoted(self) -> None:
        reason = "a" * 1_985 + "\nPASSWORD=x"  # grows past 2,000 under redaction
        record = DecisionRecord(
            action=shell_action("rm -rf ~", [fs_target("~", "/Users/dev", "home")],
                                opaque=["o" * 190 + "\nTOKEN=x"]),
            judgment=judgment("block", reason=reason, agent_guidance="g" * 1_990 + "\nSECRET=x",
                              history_facts=["session:" + "h" * 180 + "\nAPIKEY=x"]),
        )
        with TemporaryDirectory() as directory:
            store = SQLiteAuditStore(Path(directory) / "audit.db")
            store.write(AuditEvent(event_id="grown", event_type="decision", decision=record))
            rows = store.query(rule_id="F1.delete_home")
            store.close()
        self.assertEqual([e.event_id for e in rows], ["grown"])
        self.assertIsNotNone(rows[0].decision)
        self.assertNotIn("decision_unparsed", rows[0].details)
        self.assertLessEqual(len(rows[0].decision.judgment.reason), 2_000)

    def test_malformed_decision_zones_column_is_excluded_not_an_error(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "audit.db"
            store = SQLiteAuditStore(database)
            store.write(AuditEvent(event_id="good", event_type="decision", decision=home_wipe_record()))
            store.write(AuditEvent(event_id="edited", event_type="decision", decision=home_wipe_record()))
            store._connection.execute("UPDATE audit_events SET decision_zones = 'not json' WHERE event_id = 'edited'")  # noqa: SLF001
            store._connection.commit()  # noqa: SLF001
            self.assertEqual([e.event_id for e in store.query(zone="root")], ["good"])
            self.assertEqual(len(store.query(event_type="decision")), 2)
            store.close()

    def test_jsonl_export_carries_the_record(self) -> None:
        with TemporaryDirectory() as directory:
            store = SQLiteAuditStore(Path(directory) / "audit.db")
            store.write(AuditEvent(event_id="e", event_type="decision", decision=home_wipe_record()))
            out = Path(directory) / "export.jsonl"
            self.assertEqual(store.export_jsonl(out), 1)
            store.close()
            line = json.loads(out.read_text().splitlines()[0])
        self.assertEqual(line["decision"]["action"]["targets"][0]["filesystem"]["zone"], "root")
        self.assertEqual(line["verdict"], "block")


if __name__ == "__main__":
    unittest.main()
