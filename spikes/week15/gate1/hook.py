#!/usr/bin/env python3
"""Week 15, Gate 1: prove Claude Code's hooks can deny and inject under managed settings.

Standalone on purpose: this spike tests the host, not Sentinel. It logs every
hook event it receives, denies any `rm` whose target resolves outside the
working directory (or is home, root, or a system path), denies edits to hook
and settings files, and attaches one boundary line to each prompt.

Claude Code calls this with the event JSON on stdin. Deny = exit code 2 with the
reason on stderr (fed back to the agent). Context injection = JSON on stdout.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
import time
from pathlib import Path

LOG = Path(__file__).with_name("events.jsonl")
PROTECTED_PATHS = ("/", "/etc", "/usr", "/bin", "/sbin", "/var", "/System", "/Library")
PROTECTED_FILE_PARTS = (".claude/settings", "managed-settings.json", ".cursor/hooks.json", "requirements.toml")


def log(event: dict, verdict: str, reason: str = "") -> None:
    record = {"t": time.strftime("%H:%M:%S"), "event": event.get("hook_event_name"),
              "tool": event.get("tool_name"), "verdict": verdict, "reason": reason,
              "input": event.get("tool_input"), "prompt": event.get("prompt"),
              "transcript_path": event.get("transcript_path"), "cwd": event.get("cwd")}
    with LOG.open("a") as fh:
        fh.write(json.dumps(record) + "\n")


def outside_cwd(target: str, base: Path, root: Path) -> bool:
    """Resolve `target` from `base` (where the shell will be) and judge it against `root` (the real cwd)."""
    expanded = Path(os.path.expanduser(target))
    resolved = (base / expanded).resolve() if not expanded.is_absolute() else expanded.resolve()
    if resolved == Path.home() or str(resolved) in PROTECTED_PATHS or resolved == root.resolve():
        return True
    try:
        resolved.relative_to(root.resolve())
        return False
    except ValueError:
        return True


def rm_targets_outside(command: str, cwd: Path) -> list[str]:
    """Targets of any `rm` in the command that resolve outside cwd.

    Tracks `cd` across `&&`, `;`, and `||` so `cd .. && rm -rf x` is judged
    from where the shell will be. Crude on purpose; Gate 2a measures how far
    this kind of extraction gets on real commands.
    """
    try:
        tokens = shlex.split(command)
    except ValueError:
        return ["<unparseable command>"]
    bad: list[str] = []
    virtual = cwd
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "cd":
            dest = tokens[i + 1] if i + 1 < len(tokens) and tokens[i + 1] not in {"&&", "||", ";", "|"} else "~"
            dest_path = Path(os.path.expanduser(dest))
            virtual = dest_path if dest_path.is_absolute() else (virtual / dest_path)
        elif tok in {"rm", "rmdir"}:
            for arg in tokens[i + 1:]:
                if arg in {"&&", "||", ";", "|"}:
                    break
                if not arg.startswith("-") and outside_cwd(arg, virtual, cwd):
                    bad.append(arg)
        i += 1
    return bad


def touches_protected_file(tool_input: dict) -> str | None:
    for key in ("file_path", "path", "command"):
        value = str(tool_input.get(key, ""))
        for part in PROTECTED_FILE_PARTS:
            if part in value:
                return value
    return None


def main() -> int:
    event = json.load(sys.stdin)
    name = event.get("hook_event_name")
    cwd = Path(event.get("cwd") or os.getcwd())

    if name == "UserPromptSubmit":
        boundary = f"Boundary: {cwd}, dev environment. Ask before touching anything outside it."
        log(event, "inject", boundary)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit",
                                                 "additionalContext": boundary}}))
        return 0

    if name == "PreToolUse":
        tool_input = event.get("tool_input") or {}
        protected = touches_protected_file(tool_input)
        if protected:
            log(event, "deny", f"protected file: {protected}")
            print(f"Sentinel: editing hook or settings files is not allowed ({protected}).", file=sys.stderr)
            return 2
        if event.get("tool_name") == "Bash":
            bad = rm_targets_outside(str(tool_input.get("command", "")), cwd)
            if bad:
                log(event, "deny", f"rm outside cwd: {bad}")
                print(f"Sentinel: destructive operation outside the working directory is blocked "
                      f"({', '.join(bad)}). Stay inside {cwd} or ask the user.", file=sys.stderr)
                return 2
        log(event, "allow")
        return 0

    log(event, "observe")
    return 0


if __name__ == "__main__":
    sys.exit(main())
