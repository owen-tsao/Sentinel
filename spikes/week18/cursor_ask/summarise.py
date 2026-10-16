#!/usr/bin/env python3
"""Summarise the spike C2 log: per shell command, which events fired, in what
order, with which ids. Run after the scratch session:

    python3 spikes/week18/cursor_ask/summarise.py
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

LOG = Path("/tmp/sentinel-cursor-probe/c2.jsonl")
SHELL_EVENTS = {"preToolUse", "beforeShellExecution", "afterShellExecution", "postToolUse", "postToolUseFailure"}


def main() -> int:
    if not LOG.exists():
        print(f"no log at {LOG}: the hooks did not fire (check Cursor Settings > Hooks in the probe window)")
        return 1
    rows = [json.loads(line) for line in LOG.read_text().splitlines() if line.strip()]
    print(f"{len(rows)} events logged\n")

    # Q2: group shell-related events by the command text, then show order, ids, and gaps.
    by_command: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        p = row["payload"]
        if row["event"] not in SHELL_EVENTS:
            continue
        if row["event"] == "preToolUse" and p.get("tool_name") != "Shell":
            continue
        ti = p.get("tool_input")
        if isinstance(ti, str):
            try:
                ti = json.loads(ti)
            except ValueError:
                ti = {}
        command = p.get("command")
        if not command and isinstance(ti, dict):
            command = ti.get("command")
        key = command or f"<no command: {row['event']} {p.get('tool_use_id')}>"
        by_command[key].append(row)

    print("Q2/Q3/Q4: per command, events in time order (ms from first), tool_use_id, parent_tool_call_id")
    for command, evs in by_command.items():
        evs.sort(key=lambda r: r["ts"])
        t0 = evs[0]["ts"]
        ids = {e["payload"].get("tool_use_id") for e in evs}
        print(f"\n  $ {command[:70]}")
        for e in evs:
            p = e["payload"]
            print(f"    +{(e['ts'] - t0) * 1000:7.1f} ms  {e['event']:22s} id={p.get('tool_use_id')}  parent={p.get('parent_tool_call_id')}")
        print(f"    shared tool_use_id across events: {'YES' if len(ids) == 1 and None not in ids else 'NO -> ' + str(ids)}")

    print("\nfield names per event:")
    fields: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        fields[row["event"]].update(row["payload"].keys())
    for ev, names in sorted(fields.items()):
        print(f"  {ev:22s} {sorted(names)}")

    asked = [r for r in rows if r["event"] == "beforeShellExecution" and "ASKME" in (r["payload"].get("command") or "")]
    print(f"\nQ1/Q5: beforeShellExecution returned `ask` {len(asked)}x; what the screen showed is yours to report.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
