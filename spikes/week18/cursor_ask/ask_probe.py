#!/usr/bin/env python3
"""Cursor spike C2: can `beforeShellExecution` ask the person, and how does it
line up with `preToolUse` for the same command?

Found during the Week 18 live gates (October 13): `permission: ask` on
`preToolUse` is "accepted by the schema but not enforced" (Cursor docs); live
it became *allow* for `Delete` and *deny* for `WebFetch`, with no popup either
way. The docs say `ask` works on `beforeShellExecution`. This probe checks:

  Q1  does `ask` + `user_message` on `beforeShellExecution` show a popup with
      our text? (kill condition for Option A)
  Q2  order and ids: does `preToolUse` (tool Shell) fire before
      `beforeShellExecution` for the same command, and do they share
      `tool_use_id`?
  Q3  does `beforeShellExecution` fire for a subagent's shell and for a
      background shell?
  Q4  after the person clicks Skip on the ask, which post events fire?
  Q5  under Run Mode = Run Everything, does the ask still show?

Dependency-free. Logs every raw payload to PROBE_LOG. Only commands containing
the token ASKME get `ask`; everything else is allowed. Install only in the
scratch project.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

PROBE_LOG = Path(os.environ.get("SENTINEL_PROBE_LOG", "/tmp/sentinel-cursor-probe/c2.jsonl"))
ASK_TOKEN = "ASKME"
USER_TEXT = "SENTINEL-ASK-MARKER: Sentinel wants your confirmation before this runs (spike C2)."
AGENT_TEXT = "SENTINEL-ASK-AGENT: this command was sent to the person for confirmation."


def main() -> int:
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        payload = {"_unparsed": raw[:2000]}
    event = payload.get("hook_event_name") or "unknown"

    PROBE_LOG.parent.mkdir(parents=True, exist_ok=True)
    with PROBE_LOG.open("a") as fh:
        fh.write(json.dumps({"ts": time.time(), "event": event, "cwd": os.getcwd(), "payload": payload}) + "\n")

    if event == "beforeSubmitPrompt":
        print(json.dumps({"continue": True}))
        return 0
    if event == "beforeShellExecution":
        command = payload.get("command") or ""
        if ASK_TOKEN in command:
            print(json.dumps({"permission": "ask", "user_message": USER_TEXT, "agent_message": AGENT_TEXT}))
        else:
            # Step 2 of the spike: say nothing. Verifies `{}` is accepted on this
            # event (neither denied nor suppressing Cursor's own approval).
            print(json.dumps({}))
        return 0
    # preToolUse and the post events: say nothing, decide nothing.
    print(json.dumps({}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
