"""Read-only inspection of the Cursor hooks profile installed for a workspace.

Sentinel cannot verify Cursor's sandbox setting or that Cursor honours hooks;
it can only report whether the fail-closed profile is present on disk. The
result is evidence for the human, never an input to authorization.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

REQUIRED_HOOK_EVENTS = (
    "beforeReadFile",
    "preToolUse",
    "beforeShellExecution",
    "beforeMCPExecution",
)
HookProfileStatus = Literal["installed", "partial", "missing", "invalid"]


@dataclass(frozen=True)
class HookProfileInspection:
    status: HookProfileStatus
    detail: str
    path: str


def inspect_hooks_profile(workspace: Path) -> HookProfileInspection:
    path = workspace / ".cursor" / "hooks.json"
    if not path.is_file():
        return HookProfileInspection("missing", "No .cursor/hooks.json in the workspace.", str(path))
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        hooks = document["hooks"]
        if not isinstance(hooks, dict):
            raise TypeError("hooks must be an object")
    except Exception:
        return HookProfileInspection("invalid", "hooks.json could not be parsed.", str(path))

    fail_closed: list[str] = []
    for event in REQUIRED_HOOK_EVENTS:
        entries = hooks.get(event) or []
        if any(
            isinstance(entry, dict)
            and "sentinel_hooks" in str(entry.get("command", ""))
            and entry.get("failClosed") is True
            for entry in entries
        ):
            fail_closed.append(event)
    if len(fail_closed) == len(REQUIRED_HOOK_EVENTS):
        return HookProfileInspection(
            "installed", "Sentinel fail-closed hooks cover read, edit, shell, and MCP events.", str(path)
        )
    if fail_closed:
        missing = sorted(set(REQUIRED_HOOK_EVENTS) - set(fail_closed))
        return HookProfileInspection(
            "partial", f"Sentinel hooks missing or not failClosed for: {', '.join(missing)}.", str(path)
        )
    return HookProfileInspection("missing", "hooks.json exists but has no Sentinel fail-closed hooks.", str(path))
