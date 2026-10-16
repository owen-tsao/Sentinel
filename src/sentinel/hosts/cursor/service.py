"""Cursor events in, Cursor responses out; every decision made by the shared
service.

`CursorHookService` owns three things and nothing else: translating the
payload (`translate.py`), fixing the session's launch directory from the
facts the forwarder sends with every event (narrow-only), and translating
the response back. The floor, the inferrer, the stuck detector, the budget,
the session registry, and the audit writer are the Claude Code service's,
constructed with `host="cursor"` (docs/Week 18 Plan.md §2).

Fail-closed is split by event: a gating event (`preToolUse`,
`beforeShellExecution`, `beforeMCPExecution`) that cannot be read or judged
is a `deny` with the failure named; a non-gating event (`beforeSubmitPrompt`,
`postToolUse`, `postToolUseFailure`) that fails returns the pass-through
body, because a stopped or confused Sentinel must never block the person's
prompt.

Confirms (spike C2, `spikes/week18/cursor_ask/RESULTS.md`): Cursor ignores
`ask` on `preToolUse` but enforces it on `beforeShellExecution` and
`beforeMCPExecution`, which fire ~80 ms later for the same `tool_use_id`.
So every call is judged once, on `preToolUse`; a shell or MCP confirm is held
on the session and answered as `ask` when the capable event arrives; a
confirm for any other tool is a deny with guidance (the shared service's
`ask_capable` parameter). A capable event for a call `preToolUse` never saw
is judged on the spot, so the gate holds even if `preToolUse` did not fire.
"""

from __future__ import annotations

import logging
import os
import posixpath
import time
from pathlib import Path
from typing import Any, Callable, Optional

from pydantic import ValidationError

from sentinel.audit.base import AuditStore
from sentinel.audit.models import AuditEvent
from sentinel.floor.extract import default_home
from sentinel.hosts.claude_code import schemas
from sentinel.hosts.claude_code.service import ClaudeCodeHookService
from sentinel.hosts.claude_code.session import HookSession, SessionRegistry
from sentinel.hosts.claude_code.settings_check import EnforcementReport
from sentinel.hosts.cursor import translate
from sentinel.hosts.cursor.schemas import ASK_CAPABLE_EVENTS, EVENTS, GATING_EVENTS, CursorHookPayload, strip_sensitive
from sentinel.supervision.floor_policy import FloorPolicy

log = logging.getLogger("sentinel.hosts.cursor")

HOST = "cursor"
DOCTOR_COMMAND = "sentinel cursor doctor"
FORWARDER_NAME = "sentinel_forward.py"
MIN_CURSOR_VERSION = (3, 24, 12)   # the only version the hook contract has been verified on

INVALID_PAYLOAD = ("Sentinel could not read this Cursor hook event, so the call cannot be checked and is not allowed. "
                   "This is a Sentinel or Cursor problem, not something to work around; tell the user.")
NO_SESSION = ("Sentinel received a tool call with no conversation id, so it cannot be tied to a session and is not "
              "allowed. Tell the user.")
NO_LAUNCH_DIR = ("Sentinel could not determine this workspace's project directory (no workspace root and no launch "
                 "directory in the hook event), so the call cannot be judged against a boundary and is not allowed. "
                 "Tell the user to open a folder in Cursor.")


def _deny(reason: str) -> dict[str, Any]:
    return {"permission": "deny", "user_message": reason, "agent_message": reason}


def _pass(event: str) -> dict[str, Any]:
    return {"continue": True} if event == "beforeSubmitPrompt" else {}


def default_hooks_file() -> Path:
    return Path.home() / ".cursor" / "hooks.json"


class CursorHookService:
    def __init__(
        self,
        *,
        policy: FloorPolicy,
        audit_store: AuditStore,
        sessions: Optional[SessionRegistry] = None,
        home: Optional[str] = None,
        hooks_file: Optional[Path] = None,
        hooks_file_reader: Optional[Callable[[Path], Optional[str]]] = None,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        self._policy = policy
        self._audit = audit_store
        self._home = home or default_home()
        self._hooks_file = hooks_file if hooks_file is not None else default_hooks_file()
        self._read_hooks_file = hooks_file_reader or _read_text
        self._clock = clock
        registry = sessions or SessionRegistry(audit_store=audit_store, host=HOST)
        self._inner = ClaudeCodeHookService(
            policy=policy, audit_store=audit_store, sessions=registry, home=home,
            managed_settings=None, facts_collector=None,
            snapshot_reader=lambda _path: None,      # Cursor has no ConfigChange event; nothing to snapshot
            clock=clock, host=HOST, enforcement_evaluator=self.evaluate_enforcement,
            doctor_command=DOCTOR_COMMAND, person_channel="ask",
            detector_exempt_tools=translate.DETECTOR_EXEMPT_TOOLS,
            ask_capable=translate.ask_capable,
        )

    @property
    def sessions(self) -> SessionRegistry:
        return self._inner.sessions

    @property
    def inner(self) -> ClaudeCodeHookService:
        return self._inner

    # ------------------------------------------------------------- enforcement

    def evaluate_enforcement(self, session: HookSession) -> EnforcementReport:
        """Cursor's hooks file lives in the person's home and the agent can
        edit it, so the claim is never `mandatory`: `advisory` while the
        forwarder is installed, `unsupported` when it is not (plan §2)."""
        text = self._read_hooks_file(self._hooks_file)
        if text is None:
            return EnforcementReport("unsupported", ("hooks_file_missing",), session.seen_pre_tool_use)
        if FORWARDER_NAME not in text:
            return EnforcementReport("unsupported", ("forwarder_not_registered",), session.seen_pre_tool_use)
        return EnforcementReport("advisory", ("hooks_file_user_writable",), session.seen_pre_tool_use)

    # ------------------------------------------------------------------ events

    def handle(self, event: str, payload: Any) -> dict[str, Any]:
        """One Cursor event. Never raises past here: a gating event that
        cannot be served is a deny, a non-gating one its pass-through."""
        if event not in EVENTS:
            return _pass(event)
        try:
            return self._handle(event, payload)
        except Exception as exc:  # noqa: BLE001 - the last line of defence inside the service
            log.exception("cursor %s handler failed: %s", event, type(exc).__name__)
            if event in GATING_EVENTS:
                return _deny(f"Sentinel failed while checking this call ({type(exc).__name__}); it is not allowed. Tell the user.")
            return _pass(event)

    def _handle(self, event: str, payload: Any) -> dict[str, Any]:
        started = self._clock()
        gating = event in GATING_EVENTS
        try:
            parsed = CursorHookPayload.model_validate(payload)
        except (ValidationError, TypeError, ValueError) as exc:
            log.warning("cursor %s payload unreadable: %s %s", event, type(exc).__name__, strip_sensitive(payload))
            self._write_optional(AuditEvent(event_type="decision" if gating else "hook_error", verdict="block" if gating else None,
                                            agent_id=HOST, reason_codes=["adapter:invalid_payload"],
                                            details={"host": HOST, "hook_event": event, "error": type(exc).__name__}))
            return _deny(INVALID_PAYLOAD) if gating else _pass(event)
        if parsed.hook_event_name != event:
            # The route name is the contract; a body claiming another event is a forgery or a bug.
            log.warning("cursor route %s received a %s body", event, parsed.hook_event_name)
            return _deny(INVALID_PAYLOAD) if gating else _pass(event)
        session_id = parsed.conversation
        if not session_id:
            return _deny(NO_SESSION) if gating else _pass(event)
        launch, source = _launch_dir(parsed)
        if launch is None:
            if gating:
                self._write_optional(AuditEvent(event_type="decision", verdict="block", agent_id=HOST, session_id=session_id,
                                                request_id=parsed.tool_use_id, reason_codes=["adapter:no_launch_dir"],
                                                details={"host": HOST, "hook_event": event, "tool": parsed.tool_name}))
                return _deny(NO_LAUNCH_DIR)
            return _pass(event)
        session = self._ensure_session(session_id, launch, source, event=event)
        translated = translate.to_envelope(parsed, launch_cwd=session.launch_cwd, home=self._home)
        body = self._dispatch(event, parsed, translated, session)
        out = translate.to_cursor(body, event=event)
        if gating and out.get("permission") == "allow":
            log.error("a cursor response tried to say permission=allow; replaced with an empty body")
            out = {k: v for k, v in out.items() if k != "permission"}
        if parsed.forwarder_ms is not None and event == "preToolUse":
            self._write_optional(AuditEvent(event_type="hook_timing", session_id=session_id, agent_id=HOST,
                                            request_id=parsed.tool_use_id,
                                            details={"host": HOST, "forwarder_ms": parsed.forwarder_ms,
                                                     "server_ms": round((self._clock() - started) * 1000.0, 3),
                                                     "cursor_version": parsed.cursor_version}))
        return out

    def _dispatch(self, event: str, parsed: CursorHookPayload, translated: translate.Translated,
                  session: HookSession) -> dict[str, Any]:
        inner = self._inner
        tool_use_id = parsed.tool_use_id
        if event == "preToolUse":
            body = inner.pre_tool_use(translated.envelope)
            return self._defer_ask_if_needed(body, translated, session, tool_use_id)
        if event in ASK_CAPABLE_EVENTS:
            # The second event for a call `preToolUse` already judged (verified
            # order and shared id: step A1 for MCP, spike C2 for shell). Deliver
            # the held confirm if there is one; otherwise add nothing. A call
            # `preToolUse` never saw, or one judged by a process that has since
            # restarted (its held ask is gone), is judged here, so this gate
            # stands alone.
            with self.sessions.lock(session.session_id):
                pending = session.take_ask(tool_use_id)
                seen = tool_use_id is not None and tool_use_id in session.judged_ids
            if pending is not None:
                self._write_optional(AuditEvent(event_type="ask_delivered", session_id=session.session_id, agent_id=HOST,
                                                request_id=tool_use_id,
                                                details={"host": HOST, "hook_event": event,
                                                         "tool": translated.envelope.get("tool_name")}))
                return schemas.ask_response(pending)
            if seen:
                if event == "beforeMCPExecution":
                    self._write_optional(AuditEvent(event_type="mcp_execution", session_id=session.session_id, agent_id=HOST,
                                                    request_id=tool_use_id,
                                                    details={"host": HOST, "tool": translated.envelope.get("tool_name"),
                                                             "server": translated.mcp_server, "deduplicated": True}))
                return {}
            return inner.pre_tool_use(translated.envelope)
        if event in {"postToolUse", "postToolUseFailure"}:
            self._note_undelivered_ask(session, tool_use_id, translated)
            if event == "postToolUseFailure" or translated.failed:
                return inner.post_tool_use_failure(translated.envelope)
            return inner.post_tool_use(translated.envelope)
        if event == "beforeSubmitPrompt":
            return inner.user_prompt_submit(translated.envelope)
        return {}

    def _defer_ask_if_needed(self, body: dict[str, Any], translated: translate.Translated, session: HookSession,
                             tool_use_id: Optional[str]) -> dict[str, Any]:
        """An `ask` decided on `preToolUse` cannot be shown there (spike C2).
        For shell and MCP it is held for the capable event and the agent is
        told, as context, that the person is being asked. Anything else is a
        deny: the shared service already denies with guidance for tools that
        are not ask-capable, so reaching here without an id is the only gap."""
        hook = body.get("hookSpecificOutput") or {}
        if hook.get("permissionDecision") != "ask":
            return body
        reason = hook.get("permissionDecisionReason") or ""
        if tool_use_id and translate.ask_capable(translated.envelope):
            with self.sessions.lock(session.session_id):
                session.defer_ask(tool_use_id, reason)
            return schemas.context_response(f"{reason} The user is being asked before this runs; wait for their answer.")
        log.warning("cursor ask on preToolUse with no deliverable event (tool %s); delivered as deny",
                    translated.envelope.get("tool_name"))
        return schemas.deny_response(f"{reason} {translate.NO_ASK_ON_PRE_TOOL_USE}")

    def _note_undelivered_ask(self, session: HookSession, tool_use_id: Optional[str], translated: translate.Translated) -> None:
        """The call finished and its capable event never came: the person was
        not asked. Recorded so Week 19 can count how often the second event is
        missing; the row says the question was put, this row says it was not."""
        with self.sessions.lock(session.session_id):
            pending = session.take_ask(tool_use_id)
        if pending is not None:
            log.error("cursor ask for %s was never delivered: the capable event did not fire", tool_use_id)
            self._write_optional(AuditEvent(event_type="ask_undelivered", session_id=session.session_id, agent_id=HOST,
                                            request_id=tool_use_id,
                                            details={"host": HOST, "tool": translated.envelope.get("tool_name")}))

    # ---------------------------------------------------------------- sessions

    def _ensure_session(self, session_id: str, launch: str, source: str, *, event: str) -> HookSession:
        """The session at the forwarder's launch directory. Exists only because
        a real hook event named it; later events can narrow it, never widen it."""
        session = self.sessions.get(session_id)
        if session is None:
            session = self.sessions.ensure(session_id, launch_cwd=launch, source=source,
                                           environment=self._policy.environment_for(launch),
                                           environment_for=self._policy.environment_for)
            self._write_optional(AuditEvent(event_type="session_start", session_id=session_id, agent_id=HOST,
                                            details={"host": HOST, "launch_cwd": session.launch_cwd, "source": source,
                                                     "first_event": event}))
            return session
        with self.sessions.lock(session_id):
            if posixpath.normpath(launch) != posixpath.normpath(session.launch_cwd):
                applied = session.narrow_launch_cwd(launch, source=source, environment_for=self._policy.environment_for)
                if not applied and not session.widening_rejected_logged:
                    # Once per session (review L12): an honest cwd that differs per
                    # event would otherwise write a row on every call.
                    session.widening_rejected_logged = True
                    self._write_optional(AuditEvent(event_type="session_start", session_id=session_id, agent_id=HOST,
                                                    details={"host": HOST, "launch_cwd": session.launch_cwd,
                                                             "rejected_widening_to": launch, "source": source}))
        return session

    def _write_optional(self, event: AuditEvent) -> None:
        try:
            self._audit.write(event)
        except Exception as exc:  # noqa: BLE001 - telemetry never changes a verdict
            log.warning("optional audit write failed: %s", exc)


def _launch_dir(parsed: CursorHookPayload) -> tuple[Optional[str], Optional[str]]:
    """The server's own choice of launch directory from the forwarder's
    facts: the forwarder's cwd when it equals or sits inside a workspace
    root, otherwise the first workspace root (review S3: an ancestor cwd
    would make sibling repositories "inside"). Nothing else is accepted."""
    roots = [posixpath.normpath(r) for r in parsed.workspace_roots if isinstance(r, str) and r.startswith("/")]
    candidate = posixpath.normpath(parsed.launch_dir) if parsed.launch_dir and parsed.launch_dir.startswith("/") else None
    if roots:
        for root in roots:
            if candidate == root:
                return root, "cursor_workspace_root"
            if candidate and candidate.startswith(root.rstrip("/") + "/"):
                return candidate, "cursor_forwarder"
        return roots[0], "cursor_workspace_root"
    if candidate:
        # No workspace roots at all (a window without a folder): the forwarder's
        # cwd is the only fact available and is used as-is.
        return candidate, "cursor_forwarder"
    return None, None


def _read_text(path: Path) -> Optional[str]:
    try:
        if not os.path.lexists(path):
            return None
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


__all__ = ["CursorHookService", "DOCTOR_COMMAND", "FORWARDER_NAME", "HOST", "MIN_CURSOR_VERSION", "default_hooks_file"]
