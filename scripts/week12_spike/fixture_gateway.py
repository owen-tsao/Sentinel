#!/usr/bin/env python3
"""Disposable Week 12 Phase 0 fixture gateway.

This is spike code, not product code. It stands in for the FastAPI integration
route so the mediation mechanics can be probed before any MCP dependency or
shared schema exists. It owns the only copy of the issue fixture, so a note can
exist only if this process wrote it. Policy here is deliberately trivial:
reads are allowed, one add-note requires an out-of-band approval, everything
else fails closed. Real policy stays in the Sentinel services.

Stdlib only. Run with Python 3.11+.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import sys
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

MAX_BODY_BYTES = 64 * 1024
ALLOWED_CALL_FIELDS = {"tool", "arguments", "attempt_id"}
SUPPORTED_TOOLS = {"sentinel_issue_read", "sentinel_issue_add_note"}
SEED_ISSUES = [
    ("SPIKE-1", "Login page returns 500 after password reset"),
    ("SPIKE-2", "Export job silently drops rows with unicode titles"),
]


def sha256_hex(value: str | bytes) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


class Fixture:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS issues(id TEXT PRIMARY KEY, title TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS notes(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, issue_id TEXT NOT NULL,
                    body TEXT NOT NULL, attempt_id TEXT NOT NULL UNIQUE);
                CREATE TABLE IF NOT EXISTS operations(
                    attempt_id TEXT PRIMARY KEY, tool TEXT NOT NULL, issue_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL, state TEXT NOT NULL, approval_id TEXT);
                CREATE TABLE IF NOT EXISTS approvals(
                    id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL, issue_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL, decision TEXT NOT NULL, consumed INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS audit(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
                    kind TEXT NOT NULL, detail TEXT NOT NULL);
                """
            )
            for issue_id, title in SEED_ISSUES:
                conn.execute("INSERT OR IGNORE INTO issues(id, title) VALUES (?, ?)", (issue_id, title))

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, isolation_level=None, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _audit(self, conn: sqlite3.Connection, kind: str, detail: dict[str, Any]) -> None:
        conn.execute(
            "INSERT INTO audit(ts, kind, detail) VALUES (?, ?, ?)",
            (time.time(), kind, json.dumps(detail, sort_keys=True)),
        )

    def call(self, tool: str, arguments: dict[str, Any], attempt_id: str) -> dict[str, Any]:
        with self._connect() as conn:
            if tool not in SUPPORTED_TOOLS:
                self._audit(conn, "block", {"tool": tool, "reason": "unsupported_tool"})
                return _verdict("block", "unsupported_tool", "Sentinel does not mediate this tool.")
            issue_id = arguments.get("issue_id")
            if not isinstance(issue_id, str) or not issue_id.startswith("SPIKE-"):
                self._audit(conn, "block", {"tool": tool, "reason": "issue_out_of_scope"})
                return _verdict("block", "issue_out_of_scope", "Issue is outside the fixture scope.")
            row = conn.execute("SELECT title FROM issues WHERE id = ?", (issue_id,)).fetchone()
            if row is None:
                self._audit(conn, "block", {"tool": tool, "reason": "unknown_issue"})
                return _verdict("block", "unknown_issue", "Issue does not exist.")

            if tool == "sentinel_issue_read":
                if set(arguments) != {"issue_id"}:
                    return _verdict("block", "unknown_argument", "Unexpected arguments for read.")
                notes = conn.execute(
                    "SELECT body FROM notes WHERE issue_id = ? ORDER BY id", (issue_id,)
                ).fetchall()
                conn.execute(
                    "INSERT OR REPLACE INTO operations VALUES (?, ?, ?, ?, 'succeeded', NULL)",
                    (attempt_id, tool, issue_id, sha256_hex(issue_id)),
                )
                self._audit(conn, "allow", {"tool": tool, "issue_id": issue_id, "attempt_id": attempt_id})
                return _verdict(
                    "allow", "matching_read", "Read admitted.",
                    result={"issue_id": issue_id, "title": row[0], "notes": [n[0] for n in notes]},
                )

            body = arguments.get("body")
            if set(arguments) != {"issue_id", "body"} or not isinstance(body, str) or not body:
                return _verdict("block", "unknown_argument", "add_note requires exactly issue_id and body.")
            payload_hash = sha256_hex(json.dumps({"issue_id": issue_id, "body": body}, sort_keys=True))
            return self._add_note(conn, attempt_id, issue_id, body, payload_hash)

    def _add_note(self, conn: sqlite3.Connection, attempt_id: str, issue_id: str, body: str, payload_hash: str) -> dict[str, Any]:
        # BEGIN IMMEDIATE serialises concurrent retries so approval consumption is at-most-once.
        conn.execute("BEGIN IMMEDIATE")
        try:
            op = conn.execute(
                "SELECT payload_hash, state, approval_id FROM operations WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if op is None:
                approval_id = secrets.token_hex(8)
                conn.execute(
                    "INSERT INTO operations VALUES (?, 'sentinel_issue_add_note', ?, ?, 'prepared', ?)",
                    (attempt_id, issue_id, payload_hash, approval_id),
                )
                conn.execute(
                    "INSERT INTO approvals VALUES (?, ?, ?, ?, 'pending', 0)",
                    (approval_id, attempt_id, issue_id, payload_hash),
                )
                self._audit(conn, "confirm_required", {"attempt_id": attempt_id, "approval_id": approval_id})
                conn.execute("COMMIT")
                return _verdict(
                    "confirm_required", "write_requires_exact_approval",
                    "A human must approve this exact note in the protected surface.",
                    approval_id=approval_id,
                )
            stored_hash, state, approval_id = op
            if stored_hash != payload_hash:
                self._audit(conn, "block", {"attempt_id": attempt_id, "reason": "changed_action"})
                conn.execute("COMMIT")
                return _verdict("block", "changed_action", "Payload differs from the reviewed action.")
            if state == "succeeded":
                conn.execute("COMMIT")
                return _verdict("allow", "already_applied", "Terminal result replayed; no new effect.",
                                result={"note_added": False, "duplicate_suppressed": True})
            approval = conn.execute(
                "SELECT decision, consumed FROM approvals WHERE id = ?", (approval_id,)
            ).fetchone()
            decision, consumed = approval
            if decision == "denied":
                self._audit(conn, "block", {"attempt_id": attempt_id, "reason": "denied"})
                conn.execute("COMMIT")
                return _verdict("block", "denied", "A human denied this exact action.")
            if decision != "approved":
                conn.execute("COMMIT")
                return _verdict("confirm_required", "approval_pending", "Approval still pending.",
                                approval_id=approval_id)
            if consumed:
                self._audit(conn, "block", {"attempt_id": attempt_id, "reason": "approval_replay"})
                conn.execute("COMMIT")
                return _verdict("block", "approval_replay", "Approval already consumed.")
            updated = conn.execute(
                "UPDATE approvals SET consumed = 1 WHERE id = ? AND consumed = 0", (approval_id,)
            ).rowcount
            if updated != 1:
                conn.execute("ROLLBACK")
                return _verdict("block", "approval_replay", "Approval already consumed.")
            conn.execute("UPDATE operations SET state = 'applying' WHERE attempt_id = ?", (attempt_id,))
            conn.execute("INSERT INTO notes(issue_id, body, attempt_id) VALUES (?, ?, ?)", (issue_id, body, attempt_id))
            conn.execute("UPDATE operations SET state = 'succeeded' WHERE attempt_id = ?", (attempt_id,))
            self._audit(conn, "effect", {"attempt_id": attempt_id, "issue_id": issue_id, "payload_hash": payload_hash})
            conn.execute("COMMIT")
            return _verdict("allow", "approved_write_applied", "Exactly one note added.",
                            result={"note_added": True})
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def decide(self, approval_id: str, decision: str) -> dict[str, Any]:
        with self._connect() as conn:
            updated = conn.execute(
                "UPDATE approvals SET decision = ? WHERE id = ? AND decision = 'pending'", (decision, approval_id)
            ).rowcount
            self._audit(conn, f"human_{decision}", {"approval_id": approval_id, "applied": updated == 1})
            return {"approval_id": approval_id, "decision": decision, "applied": updated == 1}

    def snapshot(self) -> dict[str, Any]:
        with self._connect() as conn:
            notes = conn.execute("SELECT issue_id, body, attempt_id FROM notes ORDER BY id").fetchall()
            ops = conn.execute("SELECT attempt_id, tool, state FROM operations ORDER BY rowid").fetchall()
            audit = conn.execute("SELECT seq, kind, detail FROM audit ORDER BY seq").fetchall()
            return {
                "notes": [{"issue_id": n[0], "body": n[1], "attempt_id": n[2]} for n in notes],
                "operations": [{"attempt_id": o[0], "tool": o[1], "state": o[2]} for o in ops],
                "audit": [{"seq": a[0], "kind": a[1], "detail": json.loads(a[2])} for a in audit],
            }


def _verdict(verdict: str, reason_code: str, reason: str, **extra: Any) -> dict[str, Any]:
    return {"verdict": verdict, "reason_code": reason_code, "reason": reason, **extra}


def make_handler(fixture: Fixture, adapter_hash: str, approver_hash: str, mode: str, delay: float):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SentinelSpikeGateway/0"

        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stderr.write("gateway: " + fmt % args + "\n")

        def _authorized(self, expected_hash: str) -> bool:
            header = self.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return False
            return hmac.compare_digest(sha256_hex(header[7:].strip()), expected_hash)

        def _json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _read_body(self) -> dict[str, Any] | None:
            length = int(self.headers.get("Content-Length", "0"))
            if length > MAX_BODY_BYTES:
                return None
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return None
            return body if isinstance(body, dict) else None

        def do_GET(self) -> None:
            if self.path == "/health":
                self._json(HTTPStatus.OK, {"ok": True})
            elif self.path == "/spike/state" and self._authorized(approver_hash):
                self._json(HTTPStatus.OK, fixture.snapshot())
            else:
                self._json(HTTPStatus.UNAUTHORIZED if self.path.startswith("/spike") else HTTPStatus.NOT_FOUND,
                           {"error": "unauthorized_or_unknown"})

        def do_POST(self) -> None:
            if self.path == "/integration/mcp/call":
                if not self._authorized(adapter_hash):
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "adapter_unauthorized"})
                    return
                if mode == "delayed":
                    time.sleep(delay)
                if mode == "malformed":
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", "9")
                    self.end_headers()
                    self.wfile.write(b"{not json")
                    return
                body = self._read_body()
                if body is None or set(body) - ALLOWED_CALL_FIELDS or not ALLOWED_CALL_FIELDS <= set(body):
                    self._json(HTTPStatus.BAD_REQUEST, _verdict("block", "unknown_field", "Request has unknown or missing fields."))
                    return
                if not isinstance(body["arguments"], dict) or not isinstance(body["attempt_id"], str):
                    self._json(HTTPStatus.BAD_REQUEST, _verdict("block", "unknown_field", "Malformed call."))
                    return
                self._json(HTTPStatus.OK, fixture.call(str(body["tool"]), body["arguments"], body["attempt_id"]))
                return
            if self.path.startswith("/spike/approvals/"):
                if not self._authorized(approver_hash):
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "approver_unauthorized"})
                    return
                _, _, _, approval_id, action = self.path.split("/", 4)
                if action not in {"approve", "deny"}:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "unknown_action"})
                    return
                self._json(HTTPStatus.OK, fixture.decide(approval_id, "approved" if action == "approve" else "denied"))
                return
            self._json(HTTPStatus.NOT_FOUND, {"error": "unknown_route"})

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--adapter-hash-file", type=Path, required=True)
    parser.add_argument("--approver-hash-file", type=Path, required=True)
    parser.add_argument("--mode", choices=["normal", "malformed", "delayed"], default="normal")
    parser.add_argument("--delay-seconds", type=float, default=10.0)
    args = parser.parse_args()

    args.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(args.state_dir, 0o700)
    fixture = Fixture(args.state_dir / "fixture.sqlite3")
    handler = make_handler(
        fixture,
        args.adapter_hash_file.read_text().strip(),
        args.approver_hash_file.read_text().strip(),
        args.mode,
        args.delay_seconds,
    )
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler)
    sys.stderr.write(f"gateway: listening on 127.0.0.1:{args.port} mode={args.mode}\n")
    sys.stderr.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
