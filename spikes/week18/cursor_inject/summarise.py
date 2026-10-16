#!/usr/bin/env python3
"""Summarise the Cursor probe log: which events fired, what fields each
payload carries, and (from the agent's own reply, pasted in) which markers
reached it. Run after the scratch session:

    python3 spikes/week18/cursor_inject/summarise.py [path/to/agent_reply.txt]
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

LOG = Path("/tmp/sentinel-cursor-probe/events.jsonl")
MARKERS = {"MARKER-ALPHA": "additional_context", "MARKER-BRAVO": "additionalContext",
           "MARKER-CHARLIE": "agent_message", "MARKER-DELTA": "context", "MARKER-ECHO": "system_message"}


def main() -> int:
    if not LOG.exists():
        print(f"no log at {LOG}: the hooks did not fire (check Cursor Settings > Hooks)")
        return 1
    events = Counter()
    fields: dict[str, set[str]] = defaultdict(set)
    samples: dict[str, dict] = {}
    tool_names: Counter = Counter()
    cwds: Counter = Counter()
    for line in LOG.read_text().splitlines():
        row = json.loads(line)
        ev = row["event"]
        events[ev] += 1
        payload = row["payload"]
        fields[ev].update(payload.keys())
        samples.setdefault(ev, payload)
        cwds[row.get("cwd", "?")] += 1
        if payload.get("tool_name"):
            tool_names[(ev, payload["tool_name"])] += 1
    print("events fired:")
    for ev, n in sorted(events.items()):
        print(f"  {ev:24s} x{n}   fields: {sorted(fields[ev])}")
    print("\nhook process cwd (step A3):", dict(cwds))
    print("\n(event, tool_name) pairs (step A1: does preToolUse carry MCP / Task / AwaitShell?):")
    for (ev, name), n in sorted(tool_names.items()):
        print(f"  {ev:24s} {name:28s} x{n}")
    prompts = events.get("beforeSubmitPrompt", 0)
    print(f"\nbeforeSubmitPrompt fired {prompts}x (step A2: expect one per message you sent)")
    print("\nfirst payload per event (values clipped):")
    for ev, payload in samples.items():
        clipped = {k: (str(v)[:80] + "…" if len(str(v)) > 80 else v) for k, v in payload.items()}
        print(f"  {ev}: {json.dumps(clipped)}")
    if len(sys.argv) > 1 and Path(sys.argv[1]).exists():
        reply = Path(sys.argv[1]).read_text()
        print("\nmarkers the agent repeated back:")
        for marker, field in MARKERS.items():
            print(f"  {marker:14s} ({field:18s}): {'SEEN' if marker in reply else 'not seen'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
