#!/usr/bin/env python3
"""Automated Week 12 Phase 0 harness.

Drives the disposable shim over real stdio JSON-RPC (the same protocol Cursor
speaks) and the gateway over real HTTP, then inspects fixture state through a
separate approver capability to verify that denied, replayed, changed,
concurrent, malformed, delayed, and gateway-down paths produce zero effects.

This proves the shim/gateway mechanics repeatably. It does not prove Cursor
integration; that requires the live Cursor run recorded separately.

Usage: /opt/homebrew/bin/python3.12 scripts/week12_spike/harness.py
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PYTHON = sys.executable
EVIDENCE_DIR = ROOT / "data" / "spikes" / "local" / "week12"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Gateway:
    def __init__(self, state_dir: Path, adapter_hash_file: Path, approver_hash_file: Path, port: int) -> None:
        self.state_dir, self.adapter_hash_file, self.approver_hash_file, self.port = (
            state_dir, adapter_hash_file, approver_hash_file, port)
        self.proc: subprocess.Popen[bytes] | None = None

    def start(self, mode: str = "normal", delay: float = 10.0) -> None:
        self.proc = subprocess.Popen(
            [PYTHON, str(HERE / "fixture_gateway.py"), "--port", str(self.port), "--state-dir", str(self.state_dir),
             "--adapter-hash-file", str(self.adapter_hash_file), "--approver-hash-file", str(self.approver_hash_file),
             "--mode", mode, "--delay-seconds", str(delay)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=0.5).read()
                return
            except (urllib.error.URLError, OSError):
                time.sleep(0.05)
        raise RuntimeError("gateway did not start")

    def stop(self) -> None:
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=5)
            self.proc = None


class Shim:
    def __init__(self, env: dict[str, str]) -> None:
        self.proc = subprocess.Popen(
            [PYTHON, str(HERE / "mcp_shim.py")], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env={**os.environ, **env},
        )
        self.next_id = 0

    def rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        assert self.proc.stdin and self.proc.stdout
        self.next_id += 1
        message = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}}
        self.proc.stdin.write(json.dumps(message).encode() + b"\n")
        self.proc.stdin.flush()
        return json.loads(self.proc.stdout.readline())

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.rpc("tools/call", {"name": name, "arguments": arguments})["result"]

    def close(self) -> None:
        self.proc.terminate()
        self.proc.wait(timeout=5)


def http(url: str, bearer: str | None, body: dict[str, Any] | None = None) -> tuple[int, Any]:
    headers = {"Content-Type": "application/json"}
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    request = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                     headers=headers, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, raw.decode(errors="replace")


def structured(result: dict[str, Any]) -> dict[str, Any]:
    return result.get("structuredContent") or {}


def main() -> int:
    results: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: Any = None) -> None:
        results.append({"case": name, "passed": passed, "detail": detail})
        print(f"{'PASS' if passed else 'FAIL'}  {name}" + (f"  -- {detail}" if not passed else ""))

    with tempfile.TemporaryDirectory(prefix="sentinel-week12-spike-") as tmp:
        private = Path(tmp)
        os.chmod(private, 0o700)
        adapter_cap, approver_cap = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        cap_file = private / "adapter.capability"
        cap_file.write_text(adapter_cap)
        os.chmod(cap_file, 0o600)
        adapter_hash_file = private / "adapter.sha256"
        adapter_hash_file.write_text(hashlib.sha256(adapter_cap.encode()).hexdigest())
        approver_hash_file = private / "approver.sha256"
        approver_hash_file.write_text(hashlib.sha256(approver_cap.encode()).hexdigest())

        port = free_port()
        base = f"http://127.0.0.1:{port}"
        gateway = Gateway(private / "state", adapter_hash_file, approver_hash_file, port)
        gateway.start()
        shim_env = {"SENTINEL_SPIKE_GATEWAY_URL": base, "SENTINEL_SPIKE_ADAPTER_CAPABILITY_FILE": str(cap_file),
                    "SENTINEL_SPIKE_TIMEOUT_SECONDS": "1"}
        shim = Shim(shim_env)

        def notes() -> list[dict[str, Any]]:
            return http(f"{base}/spike/state", approver_cap)[1]["notes"]

        def decide(approval_id: str, action: str) -> Any:
            return http(f"{base}/spike/approvals/{approval_id}/{action}", approver_cap, {})[1]

        try:
            init = shim.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "harness", "version": "0"}})
            record("initialize handshake", init["result"]["protocolVersion"] == "2025-06-18", init)
            tools = shim.rpc("tools/list")["result"]["tools"]
            record("tools/list exposes exactly two fixture tools", [t["name"] for t in tools] == ["sentinel_issue_read", "sentinel_issue_add_note"])

            latencies = []
            for _ in range(20):
                start = time.perf_counter()
                read = shim.call("sentinel_issue_read", {"issue_id": "SPIKE-1"})
                latencies.append((time.perf_counter() - start) * 1000)
            record("repeated matching reads allowed", structured(read).get("verdict") == "allow" and not read["isError"], read)
            p50, p95 = statistics.median(latencies), sorted(latencies)[int(len(latencies) * 0.95) - 1]
            record(f"read latency p50={p50:.1f}ms p95={p95:.1f}ms (shim+gateway, local)", True)

            record("unknown issue blocked", structured(shim.call("sentinel_issue_read", {"issue_id": "SPIKE-999"})).get("reason_code") == "unknown_issue")
            record("out-of-scope issue blocked", structured(shim.call("sentinel_issue_read", {"issue_id": "PROD-1"})).get("reason_code") == "issue_out_of_scope")
            record("unknown tool fails closed", shim.call("sentinel_issue_delete", {"issue_id": "SPIKE-1"})["isError"])
            record("unknown argument blocked", structured(shim.call("sentinel_issue_read", {"issue_id": "SPIKE-1", "extra": 1})).get("reason_code") == "unknown_argument")

            first = shim.call("sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note A"})
            first_s = structured(first)
            record("write requires confirmation, zero effect", first_s.get("verdict") == "confirm_required" and notes() == [], first_s)
            decide(first_s["approval_id"], "deny")
            retry = structured(shim.call("sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note A", "attempt_id": first_s["attempt_id"]}))
            record("denied retry blocked, zero effect", retry.get("reason_code") == "denied" and notes() == [], retry)

            second = structured(shim.call("sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note B"}))
            decide(second["approval_id"], "approve")
            applied = structured(shim.call("sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note B", "attempt_id": second["attempt_id"]}))
            record("approved retry applies exactly one note", applied.get("reason_code") == "approved_write_applied" and len(notes()) == 1, applied)
            replay = structured(shim.call("sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note B", "attempt_id": second["attempt_id"]}))
            record("replay of approved attempt adds nothing", replay.get("reason_code") == "already_applied" and len(notes()) == 1, replay)
            changed = structured(shim.call("sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note B tampered", "attempt_id": second["attempt_id"]}))
            record("changed payload on approved attempt blocked", changed.get("reason_code") == "changed_action" and len(notes()) == 1, changed)
            hidden = structured(shim.call("sentinel_issue_add_note", {"issue_id": "SPIKE-2", "body": "note B", "attempt_id": second["attempt_id"]}))
            record("hidden second target blocked", hidden.get("reason_code") == "changed_action" and len(notes()) == 1, hidden)

            third = structured(shim.call("sentinel_issue_add_note", {"issue_id": "SPIKE-2", "body": "note C"}))
            decide(third["approval_id"], "approve")
            outcomes: list[Any] = []
            payload = {"tool": "sentinel_issue_add_note", "arguments": {"issue_id": "SPIKE-2", "body": "note C"}, "attempt_id": third["attempt_id"]}
            threads = [threading.Thread(target=lambda: outcomes.append(http(f"{base}/integration/mcp/call", adapter_cap, payload)[1])) for _ in range(8)]
            [t.start() for t in threads]
            [t.join() for t in threads]
            applied_count = sum(1 for o in outcomes if o.get("reason_code") == "approved_write_applied")
            record("8 concurrent approved retries produce exactly one note", applied_count == 1 and len(notes()) == 2, [o.get("reason_code") for o in outcomes])

            record("missing bearer rejected", http(f"{base}/integration/mcp/call", None, payload)[0] == 401)
            record("wrong bearer rejected", http(f"{base}/integration/mcp/call", "forged", payload)[0] == 401)
            record("adapter bearer cannot approve", http(f"{base}/spike/approvals/{third['approval_id']}/approve", adapter_cap, {})[0] == 401)
            record("adapter bearer cannot read fixture state", http(f"{base}/spike/state", adapter_cap)[0] == 401)
            forged = http(f"{base}/integration/mcp/call", adapter_cap, {**payload, "verdict": "allow"})
            record("caller-selected verdict rejected", forged[0] == 400 and forged[1].get("reason_code") == "unknown_field", forged)

            gateway.stop()
            down_read = shim.call("sentinel_issue_read", {"issue_id": "SPIKE-1"})
            down_write = shim.call("sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note while down"})
            record("gateway down: read fails closed", down_read["isError"] and "NOT performed" in down_read["content"][0]["text"])
            record("gateway down: write fails closed", down_write["isError"] and "NOT performed" in down_write["content"][0]["text"])
            gateway.start(mode="malformed")
            bad = shim.call("sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note malformed"})
            record("malformed gateway response fails closed", bad["isError"] and "malformed" in bad["content"][0]["text"])
            gateway.stop()
            gateway.start(mode="delayed", delay=3.0)
            slow = shim.call("sentinel_issue_add_note", {"issue_id": "SPIKE-1", "body": "note delayed"})
            record("delayed gateway (3s) vs 1s shim timeout fails closed", slow["isError"] and "timed out" in slow["content"][0]["text"])
            gateway.stop()
            gateway.start()
            record("no effects while gateway was down/malformed/delayed", len(notes()) == 2, notes())
            snapshot = http(f"{base}/spike/state", approver_cap)[1]
            record("audit is ordered and records every effect", [a["seq"] for a in snapshot["audit"]] == list(range(1, len(snapshot["audit"]) + 1)) and sum(1 for a in snapshot["audit"] if a["kind"] == "effect") == 2)
        finally:
            shim.close()
            gateway.stop()

    passed = sum(1 for r in results if r["passed"])
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    out = EVIDENCE_DIR / f"harness-{time.strftime('%Y%m%dT%H%M%S')}.json"
    out.write_text(json.dumps({"python": sys.version, "passed": passed, "total": len(results), "results": results}, indent=2, default=str))
    print(f"\n{passed}/{len(results)} passed. Evidence: {out.relative_to(ROOT)}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
