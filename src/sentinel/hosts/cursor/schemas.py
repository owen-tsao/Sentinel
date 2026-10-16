"""Cursor hook payloads, as the forwarder POSTs them.

Shapes verified on Cursor 3.24.12 (`spikes/week18/cursor_inject/RESULTS.md`)
and against 72k tool calls in this person's own transcripts. Lenient on
purpose: Cursor adds fields between versions, and a validation failure on a
gating event would deny every call after an upgrade. Only what Sentinel
reads is typed; everything else is ignored, which is also how `user_email`
and the other fields Sentinel must never store stay out.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_PATH = 4_096
MAX_PROMPT_LENGTH = 200_000
MAX_OUTPUT_LENGTH = 1_000_000

# Fields the route strips from a payload before any log line or 422 body
# (review S17): the person's identity and the content of their work.
SENSITIVE_FIELDS = ("user_email", "prompt", "tool_output", "error_message", "tool_input", "attachments", "result_json",
                    "command", "output")

# Gating: a deny stops the call, so a failure must deny. `beforeShellExecution`
# and `beforeMCPExecution` are also the only events whose `ask` Cursor enforces
# (spike C2); `preToolUse` accepts `ask` but ignores it.
GATING_EVENTS = frozenset({"preToolUse", "beforeShellExecution", "beforeMCPExecution"})
ASK_CAPABLE_EVENTS = frozenset({"beforeShellExecution", "beforeMCPExecution"})
NON_GATING_EVENTS = frozenset({"beforeSubmitPrompt", "postToolUse", "postToolUseFailure"})
EVENTS = GATING_EVENTS | NON_GATING_EVENTS


class _Lenient(BaseModel):
    model_config = ConfigDict(extra="ignore")


class CursorHookPayload(_Lenient):
    """One Cursor hook event plus the two facts the forwarder adds."""

    session_id: Optional[str] = Field(default=None, max_length=200)
    conversation_id: Optional[str] = Field(default=None, max_length=200)
    hook_event_name: str = Field(..., min_length=1, max_length=100)
    workspace_roots: list[str] = Field(default_factory=list, max_length=50)
    cwd: Optional[str] = Field(default=None, max_length=MAX_PATH)
    cursor_version: Optional[str] = Field(default=None, max_length=50)
    parent_tool_call_id: Optional[str] = Field(default=None, max_length=200)
    # tool events
    tool_name: Optional[str] = Field(default=None, max_length=200)
    tool_input: Any = None                 # dict normally; a JSON string on MCP events; a raw string for ApplyPatch
    tool_use_id: Optional[str] = Field(default=None, max_length=200)
    tool_output: Any = None                # JSON string on 3.24.12
    duration: Optional[float] = None       # milliseconds
    error_message: Optional[str] = Field(default=None, max_length=MAX_OUTPUT_LENGTH)
    failure_type: Optional[str] = Field(default=None, max_length=100)
    is_interrupt: Optional[bool] = None
    # MCP events
    mcp_server_name: Optional[str] = Field(default=None, max_length=200)
    mcp_server_url: Optional[str] = Field(default=None, max_length=MAX_PATH)
    # beforeShellExecution (spike C2): the command at top level, `cwd` empty
    # for top-level shells, set for a subagent's; `sandbox` is Cursor's own flag.
    command: Optional[str] = Field(default=None, max_length=MAX_PROMPT_LENGTH)
    sandbox: Optional[bool] = None
    # beforeSubmitPrompt
    prompt: Optional[str] = Field(default=None, max_length=MAX_PROMPT_LENGTH)
    # added by sentinel_forward.py
    launch_dir: Optional[str] = Field(default=None, max_length=MAX_PATH)
    launch_dir_source: Optional[str] = Field(default=None, max_length=50)
    forwarder_ms: Optional[float] = None
    forwarder_version: Optional[str] = Field(default=None, max_length=50)

    @field_validator("tool_use_id", "parent_tool_call_id", "session_id", "conversation_id", mode="before")
    @classmethod
    def _empty_is_none(cls, value: Any) -> Any:
        """Cursor sends `tool_use_id: ""` on some calls (live, October 14: 83
        subagent reads and host-internal writes). An empty id is no id: as
        `""` it would be appended to the id rings, tag every post row for the
        call `orphan`, and look like a real id to the dedupe."""
        return None if isinstance(value, str) and value == "" else value

    @property
    def conversation(self) -> Optional[str]:
        """Cursor sends both; `session_id` equals `conversation_id` on 3.24.12."""
        return self.session_id or self.conversation_id


def strip_sensitive(payload: Any) -> Any:
    """What may be logged about a payload Sentinel could not read."""
    if not isinstance(payload, dict):
        return {"type": type(payload).__name__}
    return {k: ("<stripped>" if k in SENSITIVE_FIELDS else v) for k, v in payload.items()}


__all__ = ["ASK_CAPABLE_EVENTS", "CursorHookPayload", "EVENTS", "GATING_EVENTS", "NON_GATING_EVENTS", "SENSITIVE_FIELDS",
           "strip_sensitive"]
