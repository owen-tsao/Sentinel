#!/usr/bin/env python3
"""Sentinel's SessionStart hook for Claude Code. Standard library only.

Claude Code runs this at session start with the event JSON on stdin and
`CLAUDE_PROJECT_DIR` in the environment. It posts the launch directory and
version to the local Sentinel server so the boundary default is the directory
the person started in, not wherever the shell has since moved.

This script is a same-user process and the server treats what it says
accordingly: the report may narrow the boundary, never widen it (see
docs/Week 16 Plan.md §3.6). It prints nothing on success. It exits 0 even
when Sentinel is down, because SessionStart cannot block; the first
PreToolUse will, through the host's `onFailure: "block"`.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8000/hooks/claude-code/session"


def claude_version() -> str | None:
    try:
        out = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (out.stdout or out.stderr or "").strip()
    return text[:50] or None


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError):
        event = {}
    report = {
        "session_id": event.get("session_id"),
        "project_dir": os.environ.get("CLAUDE_PROJECT_DIR"),
        "cwd": event.get("cwd"),
        "source": event.get("source"),
        "claude_version": claude_version(),
    }
    if not report["session_id"]:
        return 0
    url = os.environ.get("SENTINEL_HOOK_SESSION_URL", DEFAULT_URL)
    body = json.dumps(report).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=3):  # noqa: S310 - loopback only
            pass
    except (urllib.error.URLError, OSError) as exc:
        print(f"Sentinel is not reachable at {url} ({exc}). Tool calls will be blocked until `sentinel serve` is running.",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
