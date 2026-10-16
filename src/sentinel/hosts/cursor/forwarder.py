#!/usr/bin/env python3
"""Sentinel's Cursor hook forwarder. Installed by `sentinel cursor install`
as `~/.cursor/hooks/sentinel_forward.py`; standard library only, so it runs
with any Python 3.8+ and needs nothing from Sentinel's environment.

    sentinel_forward.py --port 8000 preToolUse

Reads the Cursor event from stdin, adds the two facts only this process
knows (its own working directory and how long it took to get here), POSTs
the event to `http://127.0.0.1:<port>/hooks/cursor/<event>`, and prints the
server's answer. Every decision is the server's; this script never judges a
command and never says `allow`.

Fail-closed, in two parts (docs/Week 18 Plan.md §2):
- Sentinel unreachable, slow (3 s), non-2xx, or non-JSON: a gating event
  (`preToolUse`, `beforeShellExecution`, `beforeMCPExecution`) prints a
  `deny` whose `user_message` says Sentinel is not running and exits 0, so
  Cursor shows the reason.
  A non-gating event prints its pass-through body: a stopped Sentinel must
  never block the person's prompt.
- This script itself crashing: one line to stderr and exit 2, which Cursor
  treats as deny on gating events (and `failClosed: true` covers a crash
  before even that).
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

VERSION = "18.2"
GATING_EVENTS = {"preToolUse", "beforeShellExecution", "beforeMCPExecution"}
# Every event `sentinel cursor install` registers. Anything else on the
# command line is a mis-edited hooks file; the forwarder must not guess
# whether it gates, so it crashes (exit 2) and `failClosed` denies.
KNOWN_EVENTS = GATING_EVENTS | {"beforeSubmitPrompt", "postToolUse", "postToolUseFailure"}
SOCKET_TIMEOUT_SECONDS = 3.0
NOT_RUNNING = ("Sentinel is not running, so this action cannot be checked and is not allowed. "
               "Start it with `sentinel serve` (or `sentinel cursor doctor` to see what is wrong).")
BAD_ANSWER = ("Sentinel answered in a way this hook could not read ({what}), so this action is not allowed. "
              "Run `sentinel cursor doctor`.")


def _deny(reason):
    return {"permission": "deny", "user_message": reason, "agent_message": reason}


def _pass(event):
    return {"continue": True} if event == "beforeSubmitPrompt" else {}


def _failure_body(event, reason):
    return _deny(reason) if event in GATING_EVENTS else _pass(event)


def parse_args(argv):
    """`--port N` and one positional event name. A dangling `--port` or a
    non-integer port is a usage error, raised so the crash path denies."""
    port = 8000
    event = None
    i = 0
    while i < len(argv):
        if argv[i] == "--port":
            if i + 1 >= len(argv):
                raise ValueError("--port needs a value")
            port = int(argv[i + 1])
            i += 2
            continue
        event = argv[i]
        i += 1
    return port, event


def forward(event, payload, port, started):
    """POST and parse. Returns the body to print; never raises.

    `forwarder_ms` is the time spent inside this script before the POST
    (stdin read, JSON parse, cwd). It excludes interpreter start-up and the
    `urllib` import, which dominate the real cost; `sentinel cursor doctor`
    measures the full round trip from outside the process."""
    payload["launch_dir"] = os.path.realpath(os.getcwd())
    payload["launch_dir_source"] = "forwarder_cwd"
    payload["forwarder_ms"] = round((time.monotonic() - started) * 1000.0, 3)
    payload["forwarder_version"] = VERSION
    data = json.dumps(payload).encode("utf-8")
    url = "http://127.0.0.1:%d/hooks/cursor/%s" % (port, event)
    request = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": "application/json", "Host": "127.0.0.1:%d" % port})
    # No proxies, ever: `urlopen` would otherwise honour `http_proxy` from
    # Cursor's environment and send the event (prompt, tool input) to the
    # proxy in plaintext and trust its answer (review G1). Loopback only.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=SOCKET_TIMEOUT_SECONDS) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        return _failure_body(event, BAD_ANSWER.format(what="HTTP %d" % exc.code))
    except Exception:  # noqa: BLE001 - connection refused, timeout, DNS: Sentinel is not there
        return _failure_body(event, NOT_RUNNING)
    try:
        body = json.loads(raw.decode("utf-8"))
    except ValueError:
        return _failure_body(event, BAD_ANSWER.format(what="not JSON"))
    if not isinstance(body, dict):
        return _failure_body(event, BAD_ANSWER.format(what="not an object"))
    if event in GATING_EVENTS and body.get("permission") == "allow":
        # Belt and braces: nothing on this path grants authority.
        body = {k: v for k, v in body.items() if k != "permission"}
    return body


def main(argv=None):
    started = time.monotonic()
    port, event = parse_args(sys.argv[1:] if argv is None else argv)
    raw = sys.stdin.read()
    payload = None
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    if event is None:
        event = payload.get("hook_event_name") or "preToolUse"
    if event not in KNOWN_EVENTS:
        # Unknown events must not be guessed as non-gating: `_failure_body`
        # would print `{}` and a mis-edited hooks file would allow everything.
        raise ValueError("unknown hook event %r" % (event,))
    body = forward(event, payload, port, started)
    sys.stdout.write(json.dumps(body))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - crash: say so where Cursor will show it, then exit 2 (deny)
        sys.stderr.write("Sentinel forwarder crashed (%s: %s); the action is not allowed. Run `sentinel cursor doctor`.\n"
                         % (type(exc).__name__, exc))
        sys.exit(2)
