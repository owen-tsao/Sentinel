"""Spike S2: replay local Cursor agent transcripts through the stuck
thresholds to bound the false-positive rate before any message is shown.

Transcripts carry ordered `tool_use` blocks but no tool results, so every
result fingerprint is treated as identical. That makes the measured rate an
UPPER BOUND on S1 (repeat, same result); S3 (alternation) is exact (it does not
use results); S2 (error loops) cannot be measured here.

Not product code. Writes only aggregate numbers to summary.json; identities
printed to the terminal are truncated and never saved.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import sys
from collections import Counter

ROOT = os.path.expanduser("~/.cursor/projects")
REPEAT_N = int(next((a for a in sys.argv[1:] if a.isdigit()), "4"))     # 4th identical attempt trips
ALT_LEN = 6                                                   # A B A B A B
VOLATILE = {"description", "timeout", "explanation", "block_until_ms", "working_directory"}


def identity(name: str, inp) -> str:
    # Some transcripts carry the input as a raw string (ApplyPatch, truncated
    # JSON). Hash the string as-is rather than collapsing it to {}; the first
    # run of this spike did collapse it and produced a false 10% trip rate.
    if not isinstance(inp, dict):
        inp = {"_raw": str(inp)}
    clean = {k: v for k, v in inp.items() if k not in VOLATILE}
    if name in {"Shell", "Bash"} and isinstance(clean.get("command"), str):
        clean["command"] = re.sub(r"\s+", " ", clean["command"]).strip()
    blob = json.dumps(clean, sort_keys=True, separators=(",", ":"), default=str)
    return name + ":" + hashlib.sha256(blob.encode()).hexdigest()[:16]


def actions(path: str) -> list[tuple[str, str]]:
    out = []
    with open(path, errors="replace") as fh:
        for line in fh:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            m = e.get("message")
            if not isinstance(m, dict) or not isinstance(m.get("content"), list):
                continue
            for c in m["content"]:
                if isinstance(c, dict) and c.get("type") == "tool_use":
                    name = c.get("name") or "?"
                    inp = c.get("input")
                    d = inp if isinstance(inp, dict) else {}
                    label = name + " " + (str(d.get("command") or d.get("path") or d.get("file_path") or d.get("pattern") or (inp if isinstance(inp, str) else ""))[:60]).replace("\n", " ")
                    out.append((identity(name, inp), label))
    return out


def evaluate(seq: list[str]) -> tuple[list[int], list[int]]:
    """Return indices where S1 (repeat) and S3 (alternation) would fire,
    evaluated at PreToolUse time: history = seq[:i], proposed = seq[i]."""
    s1, s3 = [], []
    for i, cur in enumerate(seq):
        hist = seq[:i]
        if len(hist) >= REPEAT_N - 1 and all(h == cur for h in hist[-(REPEAT_N - 1):]):
            s1.append(i)
        window = hist[-(ALT_LEN - 1):] + [cur]
        if len(window) == ALT_LEN:
            a, b = window[0], window[1]
            if a != b and all(window[k] == (a if k % 2 == 0 else b) for k in range(ALT_LEN)):
                s3.append(i)
    return s1, s3


def main() -> None:
    files = glob.glob(os.path.join(ROOT, "*", "agent-transcripts", "*", "*.jsonl"))
    # The only true-shape sample: live Claude Code sessions (same tool_use
    # block layout inside message.content). Small, but it is what the detector
    # will actually see.
    cc_files = glob.glob(os.path.expanduser("~/.claude/projects/*/*.jsonl"))
    if "--claude-code" in sys.argv:
        files = cc_files
    elif "--all" in sys.argv:
        files = files + cc_files
    sessions = 0
    sessions_with_actions = 0
    total_actions = 0
    s1_sessions = s3_sessions = any_sessions = 0
    s1_trips = s3_trips = 0
    # "distinct episodes": a run of consecutive trips on one identity counts once,
    # which is how the detector would speak (nudge at threshold, one message after).
    s1_episodes = 0
    tripping = Counter()
    for f in files:
        acts = actions(f)
        sessions += 1
        if not acts:
            continue
        sessions_with_actions += 1
        total_actions += len(acts)
        ids = [a for a, _ in acts]
        s1, s3 = evaluate(ids)
        if s1:
            s1_sessions += 1
            s1_trips += len(s1)
            last = None
            for i in s1:
                if last is None or i != last + 1 or ids[i] != ids[last]:
                    s1_episodes += 1
                    tripping[acts[i][1]] += 1
                last = i
        if s3:
            s3_sessions += 1
            s3_trips += len(s3)
        if s1 or s3:
            any_sessions += 1
    summary = {
        "repeat_threshold": REPEAT_N,
        "alternation_window": ALT_LEN,
        "sessions_scanned": sessions,
        "sessions_with_actions": sessions_with_actions,
        "total_actions": total_actions,
        "sessions_with_any_trip": any_sessions,
        "share_sessions_with_any_trip": round(any_sessions / max(sessions_with_actions, 1), 4),
        "s1_repeat_sessions": s1_sessions,
        "s1_repeat_trips": s1_trips,
        "s1_repeat_episodes": s1_episodes,
        "s3_alternation_sessions": s3_sessions,
        "s3_alternation_trips": s3_trips,
        "trips_per_100_actions": round(100 * (s1_trips + s3_trips) / max(total_actions, 1), 3),
        "note": "S1 is an upper bound (results assumed identical); S2 error loops unmeasured offline",
    }
    print(json.dumps(summary, indent=2))
    print("\nTop tripping identities (terminal only, truncated):")
    for label, n in tripping.most_common(12):
        print(f"  {n:3d}  {label}")
    with open(os.path.join(os.path.dirname(__file__), f"s2_summary_n{REPEAT_N}{'_cc' if '--claude-code' in sys.argv else ''}.json"), "w") as fh:
        json.dump(summary, fh, indent=2)


if __name__ == "__main__":
    main()
