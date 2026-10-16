"""Week 18 step E: the forwarder as a subprocess, and install/doctor on a
temporary Cursor directory.

docs/Week 18 Plan.md §7 "Forwarder" and "Install/doctor". The forwarder is
run the way Cursor runs it (a fresh interpreter, JSON on stdin) against a
throwaway HTTP server that plays Sentinel: answering, refusing, hanging,
returning 500, returning junk.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from sentinel.hosts.cursor import forwarder as forwarder_module
from sentinel.hosts.cursor import install as cursor_install

FORWARDER = Path(forwarder_module.__file__)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeSentinel:
    """Answers `/hooks/cursor/<event>` according to `mode`; records requests."""

    def __init__(self) -> None:
        self.port = _free_port()
        self.mode = "ok"
        self.requests: list[dict[str, Any]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_: Any) -> None:
                pass

            def do_GET(self) -> None:  # noqa: N802
                body = b'{"status":"ok"}' if self.path == "/health" and outer.mode != "hang" else b"{}"
                self.send_response(200 if self.path == "/health" else 404)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:  # noqa: N802
                raw = self.rfile.read(int(self.headers.get("content-length", "0")))
                outer.requests.append({"path": self.path, "headers": dict(self.headers), "body": json.loads(raw or b"{}")})
                if outer.mode == "hang":
                    time.sleep(6)
                    return
                if outer.mode == "500":
                    self.send_response(500)
                    self.end_headers()
                    return
                body = b"not json" if outer.mode == "junk" else json.dumps(outer.answer(self.path)).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = HTTPServer(("127.0.0.1", self.port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def answer(self, path: str) -> dict[str, Any]:
        if self.mode == "deny":
            return {"permission": "deny", "user_message": "Sentinel: nope", "agent_message": "nope"}
        if self.mode == "allow-field":
            return {"permission": "allow", "additional_context": "ctx"}
        if path.endswith("beforeSubmitPrompt"):
            return {"continue": True, "additional_context": "Sentinel boundary: `/x` (dev)."}
        return {}

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def run_forwarder(event: str, payload: dict[str, Any] | str, *, port: int, cwd: str | None = None) -> tuple[int, Any, str]:
    text = payload if isinstance(payload, str) else json.dumps(payload)
    run = subprocess.run([sys.executable, str(FORWARDER), "--port", str(port), event], input=text, capture_output=True,
                         text=True, timeout=15, cwd=cwd)
    try:
        body = json.loads(run.stdout) if run.stdout else None
    except ValueError:
        body = run.stdout
    return run.returncode, body, run.stderr


PAYLOAD = {"conversation_id": "c1", "session_id": "c1", "hook_event_name": "preToolUse", "tool_name": "Shell",
           "tool_input": {"command": "ls", "cwd": "", "timeout": 30000}, "tool_use_id": "t1", "workspace_roots": ["/tmp"],
           "cursor_version": "3.24.12", "user_email": "x@y"}


class Forwarder(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fake = FakeSentinel()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fake.close()

    def setUp(self) -> None:
        self.fake.mode = "ok"
        self.fake.requests.clear()

    def test_posts_payload_plus_launch_dir_and_prints_answer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code, body, err = run_forwarder("preToolUse", PAYLOAD, port=self.fake.port, cwd=tmp)
            self.assertEqual((code, body, err), (0, {}, ""))
            req = self.fake.requests[-1]
            self.assertEqual(req["path"], "/hooks/cursor/preToolUse")
            self.assertEqual(req["headers"]["Host"], f"127.0.0.1:{self.fake.port}")
            self.assertEqual(req["body"]["launch_dir"], os.path.realpath(tmp))
            self.assertEqual(req["body"]["launch_dir_source"], "forwarder_cwd")
            self.assertIsInstance(req["body"]["forwarder_ms"], float)
            self.assertEqual(req["body"]["tool_input"], PAYLOAD["tool_input"])   # untouched: the server translates
            self.assertEqual(req["body"]["forwarder_version"], forwarder_module.VERSION)

    def test_deny_and_prompt_answers_pass_through(self) -> None:
        self.fake.mode = "deny"
        code, body, _ = run_forwarder("preToolUse", PAYLOAD, port=self.fake.port)
        self.assertEqual((code, body["permission"], body["user_message"]), (0, "deny", "Sentinel: nope"))
        self.fake.mode = "ok"
        code, body, _ = run_forwarder("beforeSubmitPrompt", {**PAYLOAD, "hook_event_name": "beforeSubmitPrompt", "prompt": "hi"},
                                      port=self.fake.port)
        self.assertEqual((code, body["continue"]), (0, True))
        self.assertIn("Sentinel boundary", body["additional_context"])

    def test_allow_field_is_stripped_on_gating_events(self) -> None:
        self.fake.mode = "allow-field"
        code, body, _ = run_forwarder("preToolUse", PAYLOAD, port=self.fake.port)
        self.assertEqual((code, body), (0, {"additional_context": "ctx"}))

    def test_unreachable_server(self) -> None:
        dead = _free_port()
        code, body, err = run_forwarder("preToolUse", PAYLOAD, port=dead)
        self.assertEqual((code, body["permission"]), (0, "deny"))
        self.assertIn("not running", body["user_message"])
        self.assertIn("sentinel serve", body["user_message"])
        code, body, _ = run_forwarder("beforeMCPExecution", {**PAYLOAD, "hook_event_name": "beforeMCPExecution"}, port=dead)
        self.assertEqual(body["permission"], "deny")
        # Spike C2: the shell gate is gating too, so a stopped Sentinel denies there as well.
        code, body, _ = run_forwarder("beforeShellExecution", {**PAYLOAD, "hook_event_name": "beforeShellExecution",
                                                               "command": "ls"}, port=dead)
        self.assertEqual((code, body["permission"]), (0, "deny"))
        self.assertIn("not running", body["user_message"])
        for event, want in [("beforeSubmitPrompt", {"continue": True}), ("postToolUse", {}), ("postToolUseFailure", {})]:
            code, body, _ = run_forwarder(event, {**PAYLOAD, "hook_event_name": event}, port=dead)
            self.assertEqual((code, body), (0, want), event)

    def test_500_and_junk(self) -> None:
        self.fake.mode = "500"
        code, body, _ = run_forwarder("preToolUse", PAYLOAD, port=self.fake.port)
        self.assertEqual((code, body["permission"]), (0, "deny"))
        self.assertIn("HTTP 500", body["user_message"])
        self.fake.mode = "junk"
        code, body, _ = run_forwarder("preToolUse", PAYLOAD, port=self.fake.port)
        self.assertEqual((code, body["permission"]), (0, "deny"))
        self.assertIn("not JSON", body["user_message"])
        code, body, _ = run_forwarder("postToolUse", {**PAYLOAD, "hook_event_name": "postToolUse"}, port=self.fake.port)
        self.assertEqual(body, {})

    def test_slow_server_denies_within_the_hook_timeout(self) -> None:
        self.fake.mode = "hang"
        started = time.monotonic()
        code, body, _ = run_forwarder("preToolUse", PAYLOAD, port=self.fake.port)
        elapsed = time.monotonic() - started
        self.assertEqual((code, body["permission"]), (0, "deny"))
        self.assertLess(elapsed, 5.0, "must answer before Cursor's 5 s hook timeout")
        self.assertGreaterEqual(elapsed, forwarder_module.SOCKET_TIMEOUT_SECONDS - 0.5)

    def test_bad_stdin_still_reaches_the_server(self) -> None:
        """Invalid or empty stdin is the server's call (it denies gating events);
        the forwarder must not crash or decide."""
        for text in ["", "{not json", "[1,2]"]:
            with self.subTest(text=text):
                code, body, _ = run_forwarder("preToolUse", text, port=self.fake.port)
                self.assertEqual(code, 0)
                self.assertEqual(self.fake.requests[-1]["body"]["launch_dir_source"], "forwarder_cwd")

    def test_crash_exits_2_with_a_reason_on_stderr(self) -> None:
        run = subprocess.run([sys.executable, str(FORWARDER), "--port", "not-a-number", "preToolUse"], input="{}",
                             capture_output=True, text=True, timeout=15)
        self.assertEqual(run.returncode, 2)
        self.assertIn("Sentinel forwarder crashed", run.stderr)
        self.assertEqual(run.stdout, "")

    def test_mis_edited_command_line_never_fails_open(self) -> None:
        """A dangling `--port`, or an event name Sentinel does not register, is
        a mis-edited hooks file. Before this fix `--port` became the event name,
        the unknown event counted as non-gating, and the forwarder printed `{}`:
        every call allowed. Now it crashes (exit 2) and `failClosed` denies."""
        for argv in (["--port"], ["--port", str(self.fake.port), "afterShellExecution"], ["--port", str(self.fake.port), "--port"],
                     ["sessionStart"]):
            run = subprocess.run([sys.executable, str(FORWARDER), *argv], input=json.dumps(PAYLOAD),
                                 capture_output=True, text=True, timeout=15)
            self.assertEqual(run.returncode, 2, argv)
            self.assertEqual(run.stdout, "", argv)
            self.assertIn("crashed", run.stderr, argv)
        self.assertEqual(self.fake.requests, [])   # nothing reached the server
        # The known events still round-trip; the payload's own name is only a fallback when argv names none.
        code, body, _ = run_forwarder("postToolUse", {**PAYLOAD, "hook_event_name": "postToolUse"}, port=self.fake.port)
        self.assertEqual((code, body), (0, {}))
        run = subprocess.run([sys.executable, str(FORWARDER), "--port", str(self.fake.port)], input=json.dumps(PAYLOAD),
                             capture_output=True, text=True, timeout=15)
        self.assertEqual((run.returncode, json.loads(run.stdout)), (0, {}))
        self.assertEqual(self.fake.requests[-1]["path"], "/hooks/cursor/preToolUse")

    def test_proxy_environment_is_ignored(self) -> None:
        """Review G1: `http_proxy` in Cursor's environment must not divert the event."""
        dead = _free_port()
        env = {**os.environ, "http_proxy": f"http://127.0.0.1:{dead}", "HTTP_PROXY": f"http://127.0.0.1:{dead}",
               "no_proxy": "", "NO_PROXY": ""}
        run = subprocess.run([sys.executable, str(FORWARDER), "--port", str(self.fake.port), "preToolUse"],
                             input=json.dumps(PAYLOAD), capture_output=True, text=True, timeout=15, env=env)
        self.assertEqual((run.returncode, json.loads(run.stdout)), (0, {}))
        self.assertEqual(self.fake.requests[-1]["path"], "/hooks/cursor/preToolUse")

    def test_runs_under_isolated_mode(self) -> None:
        """The installed command uses `python3 -I`; the script must work there."""
        run = subprocess.run([sys.executable, "-I", str(FORWARDER), "--port", str(self.fake.port), "preToolUse"],
                             input=json.dumps(PAYLOAD), capture_output=True, text=True, timeout=15)
        self.assertEqual((run.returncode, json.loads(run.stdout)), (0, {}))

    def test_stdlib_only(self) -> None:
        source = FORWARDER.read_text()
        for forbidden in ["import requests", "import pydantic", "from sentinel", "import sentinel", "import httpx"]:
            self.assertNotIn(forbidden, source)


class Install(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.cursor_dir = Path(self.tmp.name) / ".cursor"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_fresh_install_then_idempotent(self) -> None:
        result = cursor_install.install(port=8000, python=sys.executable, cursor_dir=self.cursor_dir)
        self.assertTrue(result.changed)
        self.assertEqual(result.foreign_entries, 0)
        document = json.loads((self.cursor_dir / "hooks.json").read_text())
        self.assertEqual(document["version"], 1)
        self.assertEqual(set(document["hooks"]), set(cursor_install.EVENT_ORDER))
        self.assertIn("beforeShellExecution", document["hooks"])        # the ask-capable shell gate (spike C2)
        for gating in ("preToolUse", "beforeShellExecution", "beforeMCPExecution"):
            self.assertTrue(document["hooks"][gating][0]["failClosed"], gating)
            self.assertIn(f" {gating}", document["hooks"][gating][0]["command"])
        pre = document["hooks"]["preToolUse"][0]
        self.assertTrue(pre["failClosed"])
        self.assertEqual(pre["timeout"], 5)
        self.assertIn("--port 8000 preToolUse", pre["command"])
        self.assertIn(sys.executable, pre["command"])
        script = self.cursor_dir / "hooks" / "sentinel_forward.py"
        self.assertEqual(script.read_text(), FORWARDER.read_text())
        self.assertTrue(os.access(script, os.X_OK))
        again = cursor_install.install(port=8000, python=sys.executable, cursor_dir=self.cursor_dir)
        self.assertFalse(again.changed)
        self.assertEqual(json.loads((self.cursor_dir / "hooks.json").read_text()), document)

    def test_merge_keeps_foreign_hooks_in_order_and_replaces_stale_sentinel_entries(self) -> None:
        self.cursor_dir.mkdir(parents=True)
        existing = {"version": 1, "hooks": {
            "preToolUse": [{"command": "./audit.sh"}, {"command": "python3 /old/sentinel_forward.py --port 9999 preToolUse"}],
            "stop": [{"command": "./done.sh", "loop_limit": 3}],
            "postToolUse": [{"command": "./after.sh", "timeout": 2}],
        }}
        (self.cursor_dir / "hooks.json").write_text(json.dumps(existing))
        result = cursor_install.install(port=8000, python=sys.executable, cursor_dir=self.cursor_dir)
        document = json.loads((self.cursor_dir / "hooks.json").read_text())
        self.assertEqual(result.foreign_entries, 3)
        pre = document["hooks"]["preToolUse"]
        self.assertEqual(len(pre), 2)
        self.assertTrue(cursor_install.is_sentinel_entry(pre[0]))
        self.assertIn("--port 8000", pre[0]["command"])
        self.assertEqual(pre[1], {"command": "./audit.sh"})
        self.assertEqual(document["hooks"]["stop"], [{"command": "./done.sh", "loop_limit": 3}])
        post = document["hooks"]["postToolUse"]
        self.assertEqual(post[0], {"command": "./after.sh", "timeout": 2})
        self.assertTrue(cursor_install.is_sentinel_entry(post[1]))

    def test_refuses_malformed_file_and_symlink(self) -> None:
        self.cursor_dir.mkdir(parents=True)
        hooks = self.cursor_dir / "hooks.json"
        hooks.write_text("{not json")
        with self.assertRaises(cursor_install.InstallError):
            cursor_install.install(port=8000, python=sys.executable, cursor_dir=self.cursor_dir)
        self.assertEqual(hooks.read_text(), "{not json")
        hooks.write_text("[1, 2]")
        with self.assertRaises(cursor_install.InstallError):
            cursor_install.install(port=8000, python=sys.executable, cursor_dir=self.cursor_dir)
        hooks.unlink()
        target = Path(self.tmp.name) / "elsewhere.json"
        target.write_text("{}")
        hooks.symlink_to(target)
        with self.assertRaises(cursor_install.InstallError):
            cursor_install.install(port=8000, python=sys.executable, cursor_dir=self.cursor_dir)
        self.assertEqual(target.read_text(), "{}")

    def test_refuses_symlinked_hooks_directory(self) -> None:
        self.cursor_dir.mkdir(parents=True)
        elsewhere = Path(self.tmp.name) / "elsewhere"
        elsewhere.mkdir()
        (self.cursor_dir / "hooks").symlink_to(elsewhere)
        with self.assertRaises(cursor_install.InstallError):
            cursor_install.install(port=8000, python=sys.executable, cursor_dir=self.cursor_dir)
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_command_uses_isolated_mode_and_warns_on_venv_interpreter(self) -> None:
        result = cursor_install.install(port=8000, python=sys.executable, cursor_dir=self.cursor_dir)
        document = json.loads((self.cursor_dir / "hooks.json").read_text())
        self.assertIn(" -I ", document["hooks"]["preToolUse"][0]["command"])
        if cursor_install._looks_ephemeral(sys.executable):
            self.assertTrue(result.warnings and "virtual environment" in result.warnings[0])

    def test_which_python_avoids_virtual_environments(self) -> None:
        chosen = cursor_install.which_python()
        self.assertTrue(os.path.isabs(chosen))
        if chosen != sys.executable:
            self.assertFalse(cursor_install._looks_ephemeral(chosen), chosen)

    def test_installed_command_runs_end_to_end_against_a_fake_server(self) -> None:
        fake = FakeSentinel()
        try:
            cursor_install.install(port=fake.port, python=sys.executable, cursor_dir=self.cursor_dir)
            document = json.loads((self.cursor_dir / "hooks.json").read_text())
            command = document["hooks"]["preToolUse"][0]["command"]
            run = subprocess.run(command, shell=True, input=json.dumps(PAYLOAD), capture_output=True, text=True, timeout=15,
                                 cwd=self.tmp.name)
            self.assertEqual((run.returncode, json.loads(run.stdout)), (0, {}))
            self.assertEqual(fake.requests[-1]["body"]["launch_dir"], os.path.realpath(self.tmp.name))
        finally:
            fake.close()


class Doctor(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.cursor_dir = Path(self.tmp.name) / ".cursor"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_missing_everything_is_unsupported(self) -> None:
        result = cursor_install.doctor(port=8000, cursor_dir=self.cursor_dir, probe=False, version="3.24.12")
        self.assertEqual(result.state, "unsupported")
        self.assertFalse(result.ok)
        self.assertIn("hooks_file_missing", result.failed)
        self.assertIn("forwarder_missing", result.failed)
        self.assertIn("enforcement: unsupported", "\n".join(result.lines))

    def test_installed_is_advisory_and_exits_nonzero(self) -> None:
        cursor_install.install(port=8000, python=sys.executable, cursor_dir=self.cursor_dir)
        result = cursor_install.doctor(port=8000, cursor_dir=self.cursor_dir, probe=False, version="3.24.12")
        self.assertEqual((result.state, result.ok, result.failed), ("advisory", False, []))
        # Under `uv run` the test interpreter is the project venv, which doctor rightly warns about.
        unexpected = [w for w in result.warnings if "virtual environment" not in w]
        self.assertEqual(unexpected, [])

    def test_warnings_version_and_multiroot(self) -> None:
        cursor_install.install(port=8000, python=sys.executable, cursor_dir=self.cursor_dir)
        result = cursor_install.doctor(port=8000, cursor_dir=self.cursor_dir, probe=False, version="3.20.0",
                                       workspace_roots=["/a", "/b"])
        joined = "\n".join(result.warnings)
        self.assertIn("older than 3.24.12", joined)
        self.assertIn("multi-root", joined)
        result = cursor_install.doctor(port=8000, cursor_dir=self.cursor_dir, probe=False, version="")
        self.assertIn("version unknown", "\n".join(result.warnings))

    def test_empty_or_malformed_hooks_file_is_unsupported(self) -> None:
        """Review M2: an empty, `{}`, or unparseable hooks file registers nothing."""
        cursor_install.install(port=8000, python=sys.executable, cursor_dir=self.cursor_dir)   # forwarder present
        hooks = self.cursor_dir / "hooks.json"
        for text in ["", "{}", "   ", "{not json"]:
            with self.subTest(text=text):
                hooks.write_text(text)
                result = cursor_install.doctor(port=8000, cursor_dir=self.cursor_dir, probe=False, version="3.24.12")
                self.assertEqual(result.state, "unsupported")
                self.assertTrue(result.failed)

    def test_quoted_interpreter_path_is_parsed(self) -> None:
        spaced = Path(self.tmp.name) / "My Python"
        spaced.mkdir()
        interpreter = spaced / "python3"
        interpreter.symlink_to(sys.executable)
        cursor_install.install(port=8000, python=str(interpreter), cursor_dir=self.cursor_dir)
        result = cursor_install.doctor(port=8000, cursor_dir=self.cursor_dir, probe=False, version="3.24.12")
        self.assertFalse([f for f in result.failed if f.startswith("interpreter_missing")], result.failed)

    def test_port_mismatch_and_fail_closed_off(self) -> None:
        cursor_install.install(port=8000, python=sys.executable, cursor_dir=self.cursor_dir)
        hooks = self.cursor_dir / "hooks.json"
        document = json.loads(hooks.read_text())
        document["hooks"]["preToolUse"][0]["failClosed"] = False
        hooks.write_text(json.dumps(document))
        result = cursor_install.doctor(port=8001, cursor_dir=self.cursor_dir, probe=False, version="3.24.12")
        self.assertIn("fail_closed_off:preToolUse", result.failed)
        self.assertIn("port_mismatch:preToolUse", result.failed)

    def test_probe_with_server_up_and_down(self) -> None:
        fake = FakeSentinel()
        try:
            cursor_install.install(port=fake.port, python=sys.executable, cursor_dir=self.cursor_dir)
            up = cursor_install.doctor(port=fake.port, cursor_dir=self.cursor_dir, probe=True, version="3.24.12",
                                       latency_samples=2)
            self.assertNotIn("server_unreachable", up.failed)
            self.assertNotIn("synthetic_event_failed", up.failed, "\n".join(up.lines))
            # The round trip is timed from outside the hook process, so it includes
            # interpreter start-up, which the in-row `forwarder_ms` cannot see.
            trip = [line for line in up.lines if line.startswith("hook round trip")]
            self.assertEqual(len(trip), 1, "\n".join(up.lines))
            self.assertRegex(trip[0], r"\(2 samples\): median \d+ ms, max \d+ ms")
            median = int(trip[0].split("median ")[1].split(" ms")[0])
            self.assertGreater(median, 5)   # a real process start, not the ~0.1 ms the row field reports
        finally:
            fake.close()
        down = cursor_install.doctor(port=fake.port, cursor_dir=self.cursor_dir, probe=True, version="3.24.12",
                                     latency_samples=2)
        self.assertIn("server_unreachable", down.failed)
        self.assertNotIn("synthetic_event_failed", down.failed, "\n".join(down.lines))   # the deny-with-reason is the designed answer
        self.assertFalse([line for line in down.lines if line.startswith("hook round trip")])   # not timed against a dead server


if __name__ == "__main__":
    unittest.main()
