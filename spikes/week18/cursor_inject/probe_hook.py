#!/usr/bin/env python3
"""Cursor spike C1: which hook events can put words in front of the agent?

Dependency-free. For every event it receives, this script:
  1. appends the raw stdin payload to PROBE_LOG (so we also capture Cursor's
     real payload shapes, the Cursor equivalent of Week 17's Spike S3), and
  2. returns every plausible context-carrying field at once, each with a
     distinct marker word, so the agent can be asked which markers it saw.

Nothing here denies anything. Install only in a scratch project.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

PROBE_LOG = Path(os.environ.get("SENTINEL_PROBE_LOG", "/tmp/sentinel-cursor-probe/events.jsonl"))

# One marker per candidate field. If the agent repeats a marker back, that
# field reaches it on that event.
MARKERS = {
    "additional_context": "MARKER-ALPHA",
    "additionalContext": "MARKER-BRAVO",
    "agent_message": "MARKER-CHARLIE",
    "context": "MARKER-DELTA",
    "system_message": "MARKER-ECHO",
}


def main() -> int:
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        payload = {"_unparsed": raw[:2000]}
    event = payload.get("hook_event_name") or payload.get("event") or "unknown"

    PROBE_LOG.parent.mkdir(parents=True, exist_ok=True)
    with PROBE_LOG.open("a") as fh:
        fh.write(json.dumps({"ts": time.time(), "event": event, "cwd": os.getcwd(), "payload": payload}) + "\n")

    response = {field: f"Sentinel probe on {event}: {marker}. If you can read this, say the marker word."
                for field, marker in MARKERS.items()}
    # Step A(4): PROBE_ALLOW_SHAPE=omit returns no `permission` on allow so we
    # can see whether an explicit `allow` suppresses Cursor's own approval.
    if os.environ.get("PROBE_ALLOW_SHAPE", "explicit") != "omit":
        response["permission"] = "allow"
    response["continue"] = True
    # user_message is person-facing: lets us see whether Cursor shows it on allow.
    response["user_message"] = f"Sentinel probe ({event}): user_message shown on allow."
    print(json.dumps(response))
    return 0


if __name__ == "__main__":
    sys.exit(main())
