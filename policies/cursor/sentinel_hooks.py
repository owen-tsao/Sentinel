#!/usr/bin/env python3
"""Sentinel Week 12 Cursor hooks: second layer behind the agent sandbox.

Dependency-free. Denies the agent's own tools from touching Sentinel's private
state directory and Cursor's hook/MCP configuration, and refuses fixture tool
names served by any MCP server other than Sentinel's. Every rule is a string
or path check, so this layer is advisory on its own; the sandbox provides the
write boundary and Sentinel's server applies policy regardless.

Install alongside `hooks.json` from this directory into a project's `.cursor/`.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

SENTINEL_SERVER_NAMES = {"sentinel", "sentinel-spike"}
# Fixture tools and the Week 13 task-proposal tool are only valid from
# Sentinel's own MCP server; a lookalike server must not be able to spoof them.
SENTINEL_TOOL_PREFIXES = ("sentinel_issue_", "sentinel_task_")
FIXTURE_TOOL_PREFIX = SENTINEL_TOOL_PREFIXES[0]
PROTECTED_CONFIG_SUFFIXES = (
    ".cursor/hooks.json",
    ".cursor/mcp.json",
    ".cursor/sandbox.json",
    ".cursor/permissions.json",
)
PROTECTED_CONFIG_DIRS = (".cursor/hooks",)
MUTATING_TOOLS = {"write", "edit", "strreplace", "delete", "applypatch", "multiedit"}


def private_dir() -> Path:
    return Path(os.environ.get("SENTINEL_PRIVATE_DIR", Path.home() / ".sentinel")).expanduser()


def _deny(reason: str) -> dict[str, Any]:
    return {
        "permission": "deny",
        "user_message": f"Sentinel: {reason}",
        "agent_message": (
            f"Sentinel denied this action: {reason} Do not work around it through another "
            "tool or an obfuscated path; ask the user."
        ),
    }


def _allow() -> dict[str, Any]:
    return {"permission": "allow"}


def _is_protected_path(candidate: str) -> bool:
    try:
        path = Path(candidate).expanduser()
        resolved = path.resolve() if path.is_absolute() else (Path.cwd() / path).resolve()
    except (OSError, RuntimeError, ValueError):
        return True  # unresolvable paths are treated as protected
    private = private_dir().resolve()
    if resolved == private or private in resolved.parents:
        return True
    text = resolved.as_posix()
    if text.endswith(PROTECTED_CONFIG_SUFFIXES):
        return True
    return any(f"/{marker}/" in text + "/" for marker in PROTECTED_CONFIG_DIRS)


def _paths_in(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).lower() in {"path", "file_path", "filepath", "target_file", "target_path", "file"}:
                if isinstance(nested, str):
                    found.append(nested)
            found.extend(_paths_in(nested))
    elif isinstance(value, list):
        for nested in value:
            found.extend(_paths_in(nested))
    return found


def _text_mentions_protected(text: str) -> bool:
    private = private_dir()
    markers = [str(private), private.as_posix().replace(str(Path.home()), "~")]
    markers += [suffix for suffix in PROTECTED_CONFIG_SUFFIXES] + list(PROTECTED_CONFIG_DIRS)
    return any(marker and marker in text for marker in markers)


def handle_before_read_file(payload: dict[str, Any]) -> dict[str, Any]:
    if _is_protected_path(str(payload.get("file_path", ""))):
        return _deny("reading Sentinel private state or Cursor configuration is not allowed.")
    return _allow()


def handle_pre_tool_use(payload: dict[str, Any]) -> dict[str, Any]:
    tool = str(payload.get("tool_name", "")).replace("_", "").replace("-", "").lower()
    if tool not in MUTATING_TOOLS:
        return _allow()
    for candidate in _paths_in(payload.get("tool_input", {})):
        if _is_protected_path(candidate):
            return _deny("editing Sentinel private state or Cursor hook/MCP configuration is not allowed.")
    return _allow()


def handle_before_shell_execution(payload: dict[str, Any]) -> dict[str, Any]:
    command = str(payload.get("command", ""))
    if _text_mentions_protected(command):
        return _deny("this command references Sentinel private state or Cursor configuration.")
    return _allow()


def handle_before_mcp_execution(payload: dict[str, Any]) -> dict[str, Any]:
    tool_name = str(payload.get("tool_name", ""))
    server = str(payload.get("mcp_server_name", ""))
    if tool_name.startswith(SENTINEL_TOOL_PREFIXES) and server not in SENTINEL_SERVER_NAMES:
        return _deny(f"Sentinel tool '{tool_name}' is only valid from the Sentinel MCP server, not '{server or 'unknown'}'.")
    return _allow()


HANDLERS = {
    "beforeReadFile": handle_before_read_file,
    "preToolUse": handle_pre_tool_use,
    "beforeShellExecution": handle_before_shell_execution,
    "beforeMCPExecution": handle_before_mcp_execution,
}


def handle_event(payload: dict[str, Any]) -> dict[str, Any]:
    handler = HANDLERS.get(str(payload.get("hook_event_name", "")))
    if handler is None:
        return _deny("unsupported hook event.")
    return handler(payload)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        response = handle_event(payload) if isinstance(payload, dict) else _deny("hook input was not an object.")
    except Exception:  # fail closed: hooks.json also sets failClosed for the same reason
        response = _deny("hook could not inspect the action.")
    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
