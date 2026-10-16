"""Cursor payloads in, `HookEnvelope` dicts out; service bodies in, Cursor
responses out. Pure functions, no I/O, no authority.

The translator may rename and reshape; it may never decide. A deny stays a
deny, an ask stays an ask, and anything the service did not decide stays
undecided (review S1/C8: keyed on `permissionDecision`, never on the
advisory `systemMessage`, which on Cursor has no channel and is folded into
the deny text or dropped).
"""

from __future__ import annotations

import hashlib
import json
import posixpath
from dataclasses import dataclass
from typing import Any, Optional

from sentinel.floor.patch import parse_patch
from sentinel.hosts.cursor.schemas import ASK_CAPABLE_EVENTS, CursorHookPayload

EVENT_NAMES = {
    "preToolUse": "PreToolUse",
    "beforeShellExecution": "PreToolUse",
    "beforeMCPExecution": "PreToolUse",
    "postToolUse": "PostToolUse",
    "postToolUseFailure": "PostToolUseFailure",
    "beforeSubmitPrompt": "UserPromptSubmit",
}
# The host tool shapes whose confirm Cursor can put in front of the person:
# `Shell` via `beforeShellExecution`, and MCP calls that `preToolUse` names
# as `MCP:<tool>` via `beforeMCPExecution` (spike C2, step A1: verified to
# follow with the same `tool_use_id`). `CallMcpTool` / `CallDynamicTool` also
# translate to `mcp__*`, but no spike has shown a second event for that
# shape, so a confirm for it is a deny with guidance: a held ask that nothing
# delivers would be a silent allow. Every other tool's confirm is a deny with
# guidance too.
ASK_CAPABLE_HOST_TOOLS = frozenset({"Shell"})
MCP_TOOL_PREFIX = "mcp__"


def ask_capable(envelope: Any) -> bool:
    """Whether Cursor has a verified event that can show a confirm for this call.

    Takes the envelope (or a dict shaped like one) so the host's own tool
    name decides, not the translated `mcp__*` name, which hides the shape.
    """
    get = envelope.get if isinstance(envelope, dict) else lambda k, d=None: getattr(envelope, k, d)
    host_tool = get("host_tool") or ""
    tool_name = get("tool_name") or ""
    if host_tool in ASK_CAPABLE_HOST_TOOLS or host_tool.startswith(MCP_PREFIX):
        return True
    # No host name recorded (an envelope built elsewhere): fall back to the
    # verified translated shapes only.
    return not host_tool and (tool_name == "Bash" or tool_name.startswith(MCP_TOOL_PREFIX))


NO_ASK_ON_PRE_TOOL_USE = ("Sentinel needs the user's confirmation for this call and Cursor cannot ask on this event, "
                          "so it is not allowed. Ask the user in chat; do not retry until they have answered.")
# Cursor tool → the Claude Code tool name the shared floor already judges.
TOOL_NAMES = {
    "Shell": "Bash", "Read": "Read", "ReadFile": "Read", "Write": "Write", "StrReplace": "Edit",
    "Delete": "Delete", "EditNotebook": "NotebookEdit", "Glob": "Glob", "Grep": "Grep",
    "WebSearch": "WebSearch", "WebFetch": "WebFetch", "ApplyPatch": "ApplyPatch",
}
PATH_KEYS = ("path", "file_path", "notebook_path", "target_notebook")
# Cursor Shell fields that change between two identical runs or carry UI
# intent; stripped before the detector hashes the input (review C5).
SHELL_VOLATILE = {"cwd", "timeout", "block_until_ms", "working_directory", "notify_on_output", "description",
                  "request_smart_mode_approval", "smart_mode_block_reason"}
# Polling and bookkeeping tools: a retry streak must survive one of these
# between two identical commands, and four of them in a row is not a loop.
DETECTOR_EXEMPT_TOOLS = frozenset({"AwaitShell", "TodoWrite"})
MCP_PREFIX = "MCP:"
MAX_PATCH_SHA = 64


@dataclass(frozen=True)
class Translated:
    """The service payload plus how the Cursor service should route it."""

    envelope: dict[str, Any]
    failed: bool = False       # postToolUse whose shell exit code was non-zero → the failure path
    mcp_server: Optional[str] = None


def _absolute(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value.startswith("/") else None


def _shell_cwd(value: Any, launch_cwd: str, home: Optional[str]) -> Optional[str]:
    """A Shell `working_directory`/`cwd` as the floor's cwd: absolute as is,
    `~` expanded against the server's home, relative joined to the launch
    directory. Empty strings (Cursor's default) mean "not given"."""
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if value == "~" or value.startswith("~/"):
        if not home:
            return None
        value = home + value[1:]
    if value.startswith("/"):
        return posixpath.normpath(value)
    return posixpath.normpath(posixpath.join(launch_cwd, value))


def _as_dict(value: Any) -> dict[str, Any]:
    """Cursor sends MCP `tool_input` as a JSON string; ApplyPatch as the raw
    patch. The envelope needs a dict; non-dicts are wrapped, not coerced to
    `{}` (that made every such call identical to the detector, S2)."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return {"_raw": value}
        return parsed if isinstance(parsed, dict) else {"_raw": parsed}
    if value is None:
        return {}
    return {"_raw": value}


def _path_of(tool_input: dict[str, Any]) -> Optional[str]:
    for key in PATH_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _resolve(path: Optional[str], launch_cwd: str) -> Optional[str]:
    """Relative paths resolve against the server-owned launch directory,
    never against anything the payload says (review S6: a guard; 30,197 of
    30,197 real paths were absolute)."""
    if path is None:
        return None
    if path.startswith(("/", "~")):
        return path
    return posixpath.normpath(posixpath.join(launch_cwd, path))


def translate_tool(tool_name: Optional[str], tool_input: Any, *, launch_cwd: str,
                   mcp_server: Optional[str] = None, home: Optional[str] = None) -> tuple[str, dict[str, Any], Optional[str]]:
    """(envelope tool name, envelope tool_input, shell cwd if the call names one)."""
    name = tool_name or ""
    raw = _as_dict(tool_input)
    if mcp_server is not None or name.startswith(MCP_PREFIX):
        # A server was named (beforeMCPExecution) or Cursor's own MCP prefix is
        # present: always the MCP branch, even if the bare tool is called
        # `Read` or `Grep` (review F1: a built-in's name must not borrow the
        # built-in's judgment).
        bare = name[len(MCP_PREFIX):] if name.startswith(MCP_PREFIX) else name
        return f"mcp__{mcp_server or 'unknown'}__{bare or 'unknown'}", raw, None
    if name in {"CallMcpTool", "CallDynamicTool"}:
        server = raw.get("server") or raw.get("namespace") or "unknown"
        return f"mcp__{server}__{raw.get('toolName') or 'unknown'}", _as_dict(raw.get("arguments")), None
    if name == "Shell":
        command = raw.get("command")
        # The directory the command runs in is a floor fact. Relative and `~`
        # forms resolve against the server-owned launch directory (review C2);
        # `~` is left for the floor, which expands it against the server's home.
        shell_cwd = _shell_cwd(raw.get("working_directory"), launch_cwd, home) or _shell_cwd(raw.get("cwd"), launch_cwd, home)
        clean = {k: v for k, v in raw.items() if k not in SHELL_VOLATILE}
        if "command" not in clean and command is not None:
            clean["command"] = command
        return "Bash", clean, shell_cwd
    if name == "ApplyPatch":
        # The targets are header lines inside the patch text. Only the file
        # list leaves here: bodies stay out of the envelope and the audit
        # payload (Week 18 decision), paths are what the floor judges (Week
        # 19). Relative paths resolve against the launch directory exactly as
        # `Write`'s do; an empty path stays empty so the floor denies it.
        if isinstance(tool_input, str):
            text = tool_input
        elif isinstance(tool_input, dict) and isinstance(tool_input.get("patch") or tool_input.get("input"), str):
            text = tool_input.get("patch") or tool_input.get("input")
        else:
            text = json.dumps(tool_input, sort_keys=True, default=str)
        files = [{"op": f.op, "path": (_resolve(f.path, launch_cwd) or "") if f.path else ""} for f in parse_patch(text)]
        return "ApplyPatch", {"patch_sha256": hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest(),
                              "patch_length": len(text), "files": files}, None
    if name in {"Read", "ReadFile", "Write", "StrReplace", "Delete", "EditNotebook"}:
        path = _resolve(_path_of(raw), launch_cwd)
        out: dict[str, Any] = {k: v for k, v in raw.items() if k not in PATH_KEYS}
        if name == "Write" and "contents" in out:
            out["content"] = out.pop("contents")
        key = "notebook_path" if name == "EditNotebook" else "file_path"
        if path is not None:
            out[key] = path
        return TOOL_NAMES[name], out, None
    if name == "Glob":
        out = {"pattern": raw.get("glob_pattern") or raw.get("glob")}
        directory = _resolve(raw.get("target_directory") if isinstance(raw.get("target_directory"), str) else None, launch_cwd)
        if directory:
            out["path"] = directory
        return "Glob", out, None
    if name == "Grep":
        out = {"pattern": raw.get("pattern")}
        path = _resolve(raw.get("path") if isinstance(raw.get("path"), str) else None, launch_cwd)
        if path:
            out["path"] = path
        return "Grep", out, None
    if name == "WebSearch":
        return "WebSearch", {"query": raw.get("search_term") or raw.get("query")}, None
    if name == "WebFetch":
        return "WebFetch", {"url": raw.get("url")}, None
    return name, raw, None


def translate_output(tool_name: Optional[str], tool_output: Any) -> tuple[Any, Optional[str]]:
    """Cursor's `tool_output` into the response the detector fingerprints.
    Shell output `{output, exitCode}` becomes the Bash result shape so the
    fingerprint matches Claude Code's (review C4). Returns (response, error):
    `error` is set when a shell exit code was non-zero, in Claude Code's
    `Exit code N` first-line form, so the event takes the failure path."""
    parsed = tool_output
    if isinstance(tool_output, str):
        try:
            parsed = json.loads(tool_output)
        except ValueError:
            parsed = tool_output
    if tool_name == "Shell" and isinstance(parsed, dict) and ("output" in parsed or "exitCode" in parsed):
        output = parsed.get("output")
        output = output if isinstance(output, str) else ("" if output is None else json.dumps(output))
        code = parsed.get("exitCode")
        response = {"stdout": output, "stderr": "", "interrupted": False}
        if isinstance(code, int) and not isinstance(code, bool) and code != 0:
            return response, f"Exit code {code}\n{output}"
        return response, None
    return parsed, None


def to_envelope(payload: CursorHookPayload, *, launch_cwd: str, home: Optional[str] = None) -> Translated:
    """The Cursor event as the shared service's payload. `launch_cwd` is the
    server-owned session root, used only to resolve relative paths; `home` is
    the server's home, used only to expand `~` in a Shell working directory."""
    event = EVENT_NAMES.get(payload.hook_event_name, payload.hook_event_name)
    envelope: dict[str, Any] = {
        "session_id": payload.conversation or "",
        "hook_event_name": event,
        "cwd": launch_cwd,
        "agent_type": "subagent" if payload.parent_tool_call_id else None,
    }
    if event == "UserPromptSubmit":
        envelope["prompt"] = payload.prompt
        return Translated(envelope)
    mcp_server = None
    if payload.hook_event_name == "beforeMCPExecution":
        # This event is MCP by definition. If the server name is missing
        # (version drift, an unnamed server), the call must still be judged as
        # MCP rather than borrow a built-in's judgment because its bare tool
        # happens to be called `Read` (review F1).
        mcp_server = payload.mcp_server_name or "unknown"
    if payload.hook_event_name == "beforeShellExecution":
        # The same call `preToolUse` saw as tool `Shell`, now with the command
        # at top level (spike C2). Built as that Shell call so an unjudged one
        # gets the identical judgment.
        tool_name, tool_input = "Shell", {"command": payload.command, "cwd": payload.cwd or ""}
    else:
        tool_name, tool_input = payload.tool_name, payload.tool_input
    tool, tool_input, shell_cwd = translate_tool(tool_name, tool_input, launch_cwd=launch_cwd,
                                                mcp_server=mcp_server, home=home)
    # `host_tool` is the shape Cursor gave this call. On `beforeMCPExecution`
    # the bare name gets the `MCP:` prefix `preToolUse` would have used, so a
    # confirm judged on that event is recognised as deliverable there.
    host_tool = tool_name
    if mcp_server is not None and host_tool and not host_tool.startswith(MCP_PREFIX):
        host_tool = f"{MCP_PREFIX}{host_tool}"
    envelope.update({"tool_name": tool, "tool_input": tool_input, "tool_use_id": payload.tool_use_id,
                     "host_tool": host_tool})
    if shell_cwd:
        envelope["cwd"] = shell_cwd
    if mcp_server:
        envelope["mcp_server"] = {"name": mcp_server}
    failed = False
    if payload.hook_event_name == "postToolUse":
        response, error = translate_output(payload.tool_name, payload.tool_output)
        envelope["duration_ms"] = payload.duration
        if error is not None:
            envelope["hook_event_name"] = "PostToolUseFailure"
            envelope["error"] = error
            envelope["is_interrupt"] = False
            failed = True
        else:
            envelope["tool_response"] = response
    elif payload.hook_event_name == "postToolUseFailure":
        envelope["duration_ms"] = payload.duration
        envelope["error"] = payload.error_message or ""
        envelope["is_interrupt"] = bool(payload.is_interrupt)
        failed = True
    return Translated(envelope, failed=failed, mcp_server=mcp_server)


# ------------------------------------------------------------------ responses

def to_cursor(body: dict[str, Any], *, event: str) -> dict[str, Any]:
    """The service's Claude Code-shaped body as Cursor's response. Keyed on
    the decision first; nothing here can raise a verdict."""
    hook = body.get("hookSpecificOutput") or {}
    context = hook.get("additionalContext")
    if event == "beforeSubmitPrompt":
        out: dict[str, Any] = {"continue": True}
        if context:
            out["additional_context"] = context
        return out
    if event in {"postToolUse", "postToolUseFailure"}:
        return {"additional_context": context} if context else {}
    decision = hook.get("permissionDecision")
    reason = hook.get("permissionDecisionReason") or ""
    if decision == "deny":
        advisory = body.get("systemMessage")
        user_message = f"{reason} {advisory}".strip() if advisory else reason
        return {"permission": "deny", "user_message": user_message, "agent_message": reason}
    if decision == "ask":
        if event not in ASK_CAPABLE_EVENTS:
            # Belt and braces (spike C2): Cursor ignores `ask` on `preToolUse`
            # (it ran a `Delete`, rejected a `WebFetch`, showed nothing either
            # way). The service defers shell/MCP asks to the capable event; any
            # ask that still reaches this point must not become a silent allow.
            text = f"{reason} {NO_ASK_ON_PRE_TOOL_USE}".strip()
            return {"permission": "deny", "user_message": text, "agent_message": text}
        return {"permission": "ask", "user_message": reason, "agent_message": reason}
    # Undecided: Cursor runs its own approval flow. `permission: allow` is
    # never sent (it grants nothing, step A4, but omission is the safe default).
    # A `systemMessage` without a decision has no channel on Cursor and is dropped.
    return {"additional_context": context} if context else {}


def response_kind(cursor_body: dict[str, Any]) -> str:
    """The same vocabulary as the Claude Code tests' `kind()`."""
    permission = cursor_body.get("permission")
    if permission:
        return str(permission)
    if cursor_body.get("additional_context"):
        return "context"
    return "empty"


__all__ = ["ASK_CAPABLE_HOST_TOOLS", "DETECTOR_EXEMPT_TOOLS", "EVENT_NAMES", "NO_ASK_ON_PRE_TOOL_USE", "TOOL_NAMES", "Translated",
           "ask_capable", "response_kind", "to_cursor", "to_envelope", "translate_output", "translate_tool"]
