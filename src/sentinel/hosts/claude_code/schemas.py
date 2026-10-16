"""Hook payloads and responses for Claude Code.

Lenient envelope, strict core (docs/Week 16 Plan.md §3.2): the host adds
fields between versions and a validation failure would be a non-2xx, which
under `onFailure: "block"` blocks every call after an upgrade. So unknown
fields are ignored everywhere, and only the fields Sentinel reads are typed.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

MAX_REASON_LENGTH = 2_000
MAX_PROMPT_LENGTH = 200_000
MAX_ERROR_LENGTH = 100_000
MAX_CONTEXT_LENGTH = 400


class _Lenient(BaseModel):
    model_config = ConfigDict(extra="ignore")


class McpServer(_Lenient):
    name: Optional[str] = Field(default=None, max_length=200)
    source: Optional[str] = Field(default=None, max_length=100)


class HookEnvelope(_Lenient):
    """The common fields plus the tool-event fields, for every event."""

    session_id: str = Field(..., min_length=1, max_length=200)
    hook_event_name: str = Field(..., min_length=1, max_length=100)
    cwd: Optional[str] = Field(default=None, max_length=4_096)
    permission_mode: Optional[str] = Field(default=None, max_length=50)
    agent_id: Optional[str] = Field(default=None, max_length=200)
    agent_type: Optional[str] = Field(default=None, max_length=200)
    prompt_id: Optional[str] = Field(default=None, max_length=200)
    tool_name: Optional[str] = Field(default=None, max_length=200)
    # The host's own name for the tool before translation (Cursor: `Shell`,
    # `MCP:read_file`, `CallDynamicTool`). Informational: it lets a host say
    # whether a confirm for this exact shape can be put in front of the person.
    host_tool: Optional[str] = Field(default=None, max_length=200)
    tool_input: dict[str, Any] = Field(default_factory=dict)
    tool_use_id: Optional[str] = Field(default=None, max_length=200)
    tool_response: Any = None
    duration_ms: Optional[float] = None
    mcp_server: Optional[McpServer] = None
    # ConfigChange
    source: Optional[str] = Field(default=None, max_length=100)
    file_path: Optional[str] = Field(default=None, max_length=4_096)
    # PermissionDenied
    reason: Optional[str] = Field(default=None, max_length=MAX_REASON_LENGTH)
    # UserPromptSubmit (the prompt is read, hashed, and never stored)
    prompt: Optional[str] = Field(default=None, max_length=MAX_PROMPT_LENGTH)
    # PostToolUseFailure
    error: Optional[str] = Field(default=None, max_length=MAX_ERROR_LENGTH)
    is_interrupt: Optional[bool] = None


class SessionStartReport(_Lenient):
    """What the stdlib SessionStart command hook posts."""

    session_id: str = Field(..., min_length=1, max_length=200)
    project_dir: Optional[str] = Field(default=None, max_length=4_096)
    claude_version: Optional[str] = Field(default=None, max_length=50)
    source: Optional[str] = Field(default=None, max_length=50)
    cwd: Optional[str] = Field(default=None, max_length=4_096)


def _clip(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= MAX_REASON_LENGTH else text[: MAX_REASON_LENGTH - 1] + "…"


def allow_response() -> dict[str, Any]:
    """Empty body: the host runs its own permission flow unchanged. Sentinel
    never returns `permissionDecision: "allow"`; that would skip the host's prompt."""
    return {}


def context_response(text: str, *, event: str = "PreToolUse") -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": event, "additionalContext": _clip(text)}}


def prompt_context_response(text: str) -> dict[str, Any]:
    """The boundary line (and any caution) for `UserPromptSubmit`. Never a
    `decision`: Sentinel does not block or rewrite the person's prompt."""
    return context_response(text, event="UserPromptSubmit")


def with_detector_context(body: dict[str, Any], text: str, *, system_message: str | None = None) -> dict[str, Any]:
    """Merge a detector's sentence into a floor response without changing its
    decision (plan §3.5 table): an empty body becomes context-only; an existing
    context gains a line; `ask`/`deny` are never passed here."""
    hook = dict(body.get("hookSpecificOutput") or {})
    if hook.get("permissionDecision"):
        return body
    existing = hook.get("additionalContext")
    hook["hookEventName"] = "PreToolUse"
    hook["additionalContext"] = _clip(f"{existing}\n{text}" if existing else text)
    merged = {**body, "hookSpecificOutput": hook}
    if system_message and "systemMessage" not in merged:
        merged["systemMessage"] = _clip(system_message)
    return merged


def ask_response(reason: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                   "permissionDecisionReason": _clip(reason)}}


def deny_response(reason: str, *, system_message: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                   "permissionDecisionReason": _clip(reason)}}
    if system_message:
        body["systemMessage"] = _clip(system_message)
    return body


def config_block_response(reason: str) -> dict[str, Any]:
    return {"decision": "block", "reason": _clip(reason)}


def forbids_allow(body: dict[str, Any]) -> bool:
    """Test helper and runtime guard: no response may grant authority."""
    hook = body.get("hookSpecificOutput") or {}
    return hook.get("permissionDecision") != "allow"
