"""Hook events in, one decision out, the row written before the answer.

`ClaudeCodeHookService` is the adapter proper. Each public method takes the
host's JSON as a dict and returns the JSON the host should read. Nothing in
here raises past the method: a failure to decide, or to write the row, is a
`deny` with the failure named (plan §3.2), and the HTTP layer turns any
remaining exception into the same.
"""

from __future__ import annotations

import hashlib
import logging
import posixpath
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from pydantic import ValidationError

from sentinel.audit.base import AuditStore
from sentinel.audit.models import AuditEvent
from sentinel.boundary.infer import Inference, infer
from sentinel.decisions import ActionDescription, DecisionRecord, FilesystemFacts, Judgment, ResolvedTarget, ResourceFacts
from sentinel.detectors import stuck
from sentinel.floor import decide_patch, decide_path, decide_shell, zone_of
from sentinel.floor.extract import default_home
from sentinel.floor.patch import files_from_tool_input
from sentinel.floor.record import path_record, payload_sha256, shell_record
from sentinel.floor.rules import Finding
from sentinel.hosts.claude_code import schemas
from sentinel.hosts.claude_code.session import HookSession, SessionRegistry, containing_repository
from sentinel.hosts.claude_code.settings_check import (
    CONFIG_CHANGE_KEYS,
    EnforcementReport,
    SettingsFacts,
    collect_facts,
    evaluate_enforcement,
    managed_settings_path,
    settings_files_for,
    snapshot_relevant_keys,
)
from sentinel.supervision.floor_policy import FloorPolicy

log = logging.getLogger("sentinel.hosts.claude_code")

SHELL_TOOLS = {"Bash", "PowerShell"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
DELETE_TOOLS = {"Delete"}          # Cursor's Delete tool; Claude Code deletes through Bash
PATCH_TOOLS = {"ApplyPatch"}         # Cursor: the targets are header lines inside the patch text (floor/patch.py)
READ_TOOLS = {"Read", "Grep", "Glob"}
WEB_TOOLS = {"WebFetch", "WebSearch"}
HOST = "claude_code"
ENFORCEMENT_RECHECK_SECONDS = 300
ADAPTER_AGENT_ID = "claude_code"
INSIDE_ZONES = {"inside", "cwd_root", "temp"}
INVALID_PAYLOAD_GUIDANCE = (
    "Sentinel could not read this tool call's payload, so it cannot be checked and is not allowed. "
    "This is a Sentinel or host problem, not something to work around; tell the user."
)
AUDIT_FAILED_GUIDANCE = (
    "Sentinel could not record this action before it ran, so it is not allowed. Every supervised action "
    "must be written to the audit log first. Tell the user that Sentinel's audit store is unavailable."
)
DETECTOR_VERDICTS = {"allow", "warn"}
# The phrase every "confirm delivered as deny because this host cannot ask for
# this tool" message carries; the harness reads it to compare judgments, not
# deliveries, across hosts.
CONFIRM_UNDELIVERABLE_MARKER = "cannot show a confirm prompt"
MAX_CONTEXT_CHARS = 400
CAUTION_PATH = ("This prompt mentions a location outside the boundary. Do not read or write there; "
                "ask the user to confirm first.")
CAUTION_ENVIRONMENT = ("This prompt mentions a different environment. This session was launched in {env}; "
                       "do not act on another environment without asking the user.")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ClaudeCodeHookService:
    def __init__(
        self,
        *,
        policy: FloorPolicy,
        audit_store: AuditStore,
        sessions: Optional[SessionRegistry] = None,
        home: Optional[str] = None,
        managed_settings: Optional[Path] = None,
        facts_collector: Optional[Callable[[], SettingsFacts]] = None,
        snapshot_reader: Optional[Callable[[Path], Optional[dict[str, Any]]]] = None,
        clock: Callable[[], float] = time.perf_counter,
        wall_clock: Callable[[], float] = time.time,
        host: str = HOST,
        enforcement_evaluator: Optional[Callable[[HookSession], EnforcementReport]] = None,
        doctor_command: str = "sentinel claude-code doctor",
        person_channel: str = "system_message",
        detector_exempt_tools: frozenset[str] = frozenset(),
        ask_capable: Optional[Callable[[schemas.HookEnvelope], bool]] = None,
    ) -> None:
        """Host parameters (Week 18): the same floor, inferrer, detector, and
        budget serve more than one host. `host` stamps rows and filters the
        restart rebuild; `enforcement_evaluator` replaces the Claude Code
        managed-settings check; `person_channel` is how the one budgeted
        stuck message reaches the person (`system_message` on Claude Code,
        `ask` on Cursor, which shows nothing on an allowed action); tools in
        `detector_exempt_tools` neither evaluate nor enter the stuck ring;
        `ask_capable(envelope)` says whether the host can put a confirm in
        front of the person for that exact call (spike C2: on Cursor only
        shell and the MCP shapes whose second event is verified). A confirm
        for any other call is delivered as a deny with guidance, the same
        shape as `ask_fallback_modes`, because a confirm the person never sees
        is an allow. None means every tool. `clock` measures latency;
        `wall_clock` dates budget spends, so it must agree with the audit
        rows' timestamps that rebuild the budget on restart."""
        if person_channel not in {"system_message", "ask"}:
            raise ValueError(f"unknown person_channel {person_channel!r}")
        self._host = host
        self._enforcement_evaluator = enforcement_evaluator
        self._doctor_command = doctor_command
        self._person_channel = person_channel
        self._detector_exempt = frozenset(detector_exempt_tools)
        self._ask_capable = ask_capable
        self._policy = policy
        self._audit = audit_store
        self._sessions = sessions or SessionRegistry(audit_store=audit_store, host=host)
        self._home = home or default_home()
        self._managed_settings = managed_settings if managed_settings is not None else managed_settings_path()
        self._collect_facts = facts_collector or (
            lambda: collect_facts(self._managed_settings, server_url=policy.hook.server_url, probe_port=False)
        )
        self._snapshot = snapshot_reader or snapshot_relevant_keys
        self._clock = clock
        self._wall_clock = wall_clock

    @property
    def sessions(self) -> SessionRegistry:
        return self._sessions

    # ------------------------------------------------------------------ events

    def pre_tool_use(self, payload: Any) -> dict[str, Any]:
        started = self._clock()
        try:
            envelope = schemas.HookEnvelope.model_validate(payload)
        except (ValidationError, TypeError, ValueError) as exc:
            self._write_optional(AuditEvent(event_type="decision", verdict="block", agent_id=self._host,
                                            reason_codes=["adapter:invalid_payload"],
                                            details={"host": self._host, "error": type(exc).__name__}))
            return schemas.deny_response(INVALID_PAYLOAD_GUIDANCE)
        session = self._session_for(envelope)
        with self._sessions.lock(session.session_id):
            session.seen_pre_tool_use = True
            if envelope.permission_mode and not session.permission_mode:
                session.permission_mode = envelope.permission_mode
            self._refresh_enforcement(session)
            if envelope.tool_use_id:
                session.pre_tool_use_ids.append(envelope.tool_use_id)
                session.judged_ids.append(envelope.tool_use_id)
            try:
                finding, record_builder = self._judge(envelope, session)
            except Exception as exc:  # noqa: BLE001 - a floor crash is a deny, never a pass
                log.exception("floor failed for tool %s", envelope.tool_name)
                finding = Finding("block", "adapter:floor_error",
                                  f"Sentinel's rules failed on this call ({type(exc).__name__}); it is not allowed. Tell the user.")
                record_builder = None
            response, message = self._response_for(finding, session, envelope)
            if finding.rule == "F3.credential_read" and envelope.tool_use_id:
                session.credential_read_tool_use_ids.append(envelope.tool_use_id)
            floor_kind = _response_kind(response)
            detector_details = self._run_detector(finding, envelope, session)
            if detector_details.get("signal") is not None:
                nudge = detector_details["signal"].nudge
                if detector_details["message_sent"] and self._person_channel == "ask":
                    # Hosts with no person-facing channel on allow: the one
                    # budgeted message is the host's own approval prompt. Only
                    # reachable when the floor said allow/warn (DETECTOR_VERDICTS).
                    response = schemas.ask_response(nudge)
                    detector_details["delivered"] = "ask"
                else:
                    response = schemas.with_detector_context(
                        response, nudge, system_message=nudge if detector_details["message_sent"] else None)
                    if detector_details["message_sent"]:
                        detector_details["delivered"] = "system_message"
                if detector_details["message_sent"]:
                    message = "sent"
            latency_ms = (self._clock() - started) * 1000.0
            record = None
            if record_builder is not None:
                try:
                    record = record_builder(message, latency_ms)
                    if detector_details.get("signal") is not None:
                        record = _detector_record(record, detector_details["signal"], message)
                except Exception:  # noqa: BLE001 - the row is still written, without the typed record
                    log.exception("decision record could not be built")
            enforcement = session.enforcement.state if session.enforcement else "unknown"
            signal = detector_details.pop("signal", None)
            row_verdict = "warn" if signal is not None and finding.verdict == "allow" else finding.verdict
            reason_codes = [finding.rule] if finding.rule else []
            if signal is not None:
                reason_codes.append(signal.rule_id)
            if detector_details.get("detector_error"):
                reason_codes.append("detector:error")
            event = AuditEvent(
                event_type="decision", request_id=envelope.tool_use_id, agent_id=envelope.agent_id or self._host,
                session_id=session.session_id, environment=session.environment,  # type: ignore[arg-type]
                verdict=row_verdict,  # type: ignore[arg-type]
                reason_codes=reason_codes,
                details={
                    "host": self._host, "hook_event": "PreToolUse", "tool": envelope.tool_name,
                    "permission_mode": envelope.permission_mode, "agent_type": envelope.agent_type,
                    "enforcement": enforcement, "enforcement_failed": list(session.enforcement.failed) if session.enforcement else [],
                    "working_directory_source": session.working_directory_source,
                    "boundary_root": session.current_boundary().root,
                    "response": floor_kind, "latency_ms": round(latency_ms, 3),
                    "log_only": self._policy.is_log_only(finding.rule) and finding.interrupts,
                    **({"detector": detector_details} if detector_details else {}),
                    **({"targets": finding.targets[:20]} if record is None and finding.targets else {}),
                },
                decision=record,
            )
            try:
                self._audit.write_required(event)
            except Exception as exc:  # noqa: BLE001 - fail closed on the audit write
                log.error("pre-action audit write failed: %s", exc)
                self._write_optional(AuditEvent(event_type="decision", request_id=envelope.tool_use_id,
                                                session_id=session.session_id, agent_id=self._host, verdict="block",
                                                reason_codes=["audit:write_failed"],
                                                details={"host": self._host, "tool": envelope.tool_name, "error": type(exc).__name__}))
                return schemas.deny_response(AUDIT_FAILED_GUIDANCE)
            if _response_kind(response) == "ask" and envelope.tool_use_id:
                session.asked_tool_use_ids.append(envelope.tool_use_id)
                session.messages_sent += 1
            return response

    def post_tool_use(self, payload: Any) -> dict[str, Any]:
        envelope = self._envelope_or_none(payload)
        if envelope is None:
            return {}
        session = self._sessions.get(envelope.session_id)
        orphan = session is None or (envelope.tool_use_id is not None and envelope.tool_use_id not in session.pre_tool_use_ids)
        result = self._complete_action(session, envelope, failed=False)
        # The host says a call the floor denied as a credential read ran
        # anyway (deny not honoured, or the hook timed out). Only now is the
        # F4 taint armed, from this moment, for CREDENTIAL_TAINT_SECONDS.
        credential_read_executed = bool(
            session is not None and envelope.tool_use_id is not None
            and envelope.tool_use_id in session.credential_read_tool_use_ids)
        if credential_read_executed and session is not None:
            with self._sessions.lock(session.session_id):
                session.history.credential_read_at = self._wall_clock()
        self._write_optional(AuditEvent(
            event_type="post_execution", request_id=envelope.tool_use_id, session_id=envelope.session_id,
            agent_id=envelope.agent_id or self._host,
            environment=session.environment if session else None,  # type: ignore[arg-type]
            details={"host": self._host, "hook_event": envelope.hook_event_name, "tool": envelope.tool_name, "orphan": orphan,
                     "duration_ms": envelope.duration_ms, "result_sha256": result,
                     "credential_read_executed": credential_read_executed,
                     "was_asked": bool(session and envelope.tool_use_id in session.asked_tool_use_ids)},
        ))
        return {}

    def post_tool_use_failure(self, payload: Any) -> dict[str, Any]:
        """The tool ran and failed. Feeds the error-loop signal; stores only the
        first line of the error (the `Exit code N` line for Bash)."""
        envelope = self._envelope_or_none(payload)
        if envelope is None:
            return {}
        session = self._sessions.get(envelope.session_id)
        orphan = session is None or (envelope.tool_use_id is not None and envelope.tool_use_id not in session.pre_tool_use_ids)
        result = self._complete_action(session, envelope, failed=True)
        # Only a parsed exit code is stored, never the error text: the first
        # line is tool-controlled and could carry paths or file content
        # (security review finding 2). The hash covers the rest.
        self._write_optional(AuditEvent(
            event_type="post_execution_failure", request_id=envelope.tool_use_id, session_id=envelope.session_id,
            agent_id=envelope.agent_id or self._host,
            environment=session.environment if session else None,  # type: ignore[arg-type]
            details={"host": self._host, "hook_event": envelope.hook_event_name, "tool": envelope.tool_name, "orphan": orphan,
                     "duration_ms": envelope.duration_ms, "exit_code": _exit_code(envelope.error),
                     "is_interrupt": envelope.is_interrupt, "result_sha256": result},
        ))
        return {}

    def user_prompt_submit(self, payload: Any) -> dict[str, Any]:
        """Hear and tell. The boundary is the launch directory and a prompt
        never moves it; a folder the prompt names inside it becomes a focus
        hint on this prompt's context line, and a location outside it a
        caution. Never blocks the prompt; any failure here returns `{}`
        (plan §3.1)."""
        envelope = self._envelope_or_none(payload)
        if envelope is None or envelope.prompt is None:
            return {}
        session = self._session_for(envelope)
        # Inference is pure and may take milliseconds on a large prompt, so it
        # runs outside the session lock: a slow prompt must not delay this
        # session's PreToolUse past the host's timeout (fail-closed = block).
        boundary = session.current_boundary()
        try:
            inference = infer(envelope.prompt, launch_cwd=session.launch_cwd,
                              event_cwd=envelope.cwd, home=self._home, environment=session.environment)
        except Exception as exc:  # noqa: BLE001 - advisory layer fails open
            log.exception("boundary inference failed")
            self._write_optional(AuditEvent(
                event_type="boundary", session_id=session.session_id, agent_id=self._host,
                details={"host": self._host, "error": type(exc).__name__, "boundary_root": boundary.root}))
            return {}
        with self._sessions.lock(session.session_id):
            boundary = session.current_boundary()
            focus = inference.focus if inference.outcome == "focus" else None
            caution_text, message_counted = self._caution_for(inference, session)
            line = _boundary_line(boundary.root, boundary.environment, focus=focus, caution=caution_text)
            details: dict[str, Any] = {
                "host": self._host, "hook_event": "UserPromptSubmit", "prompt_sha256": inference.prompt_sha256,
                "boundary_root": boundary.root, "source": boundary.source, "focus": focus,
                "caution": inference.caution or "none", "message_counted": message_counted,
                "pasted_stripped": inference.pasted_stripped, "command_prompt": inference.command_prompt,
                "candidates_inside": inference.candidates_inside, "candidates_outside": inference.candidates_outside,
                "candidates_dropped_by_negation": inference.candidates_dropped_by_negation,
                "advisory_messages_sent": session.advisory_messages_sent,
            }
            if inference.caution == "path" and inference.caution_target:
                details["caution_target_sha256"] = _sha256(inference.caution_target)
                details["caution_zone"] = inference.caution_zone
            elif inference.caution == "environment":
                details["caution_environment"] = inference.caution_target
            self._write_optional(AuditEvent(event_type="boundary", session_id=session.session_id,
                                            agent_id=envelope.agent_id or self._host,
                                            environment=session.environment, details=details))  # type: ignore[arg-type]
            return schemas.prompt_context_response(line)

    def _caution_for(self, inference: Inference, session: HookSession) -> tuple[Optional[str], bool]:
        """The caution sentence (always delivered when due) and whether it was
        counted against the budget (plan §3.4)."""
        if inference.caution == "path" and inference.caution_target:
            key = _sha256(inference.caution_target)
            text = CAUTION_PATH
        elif inference.caution == "environment":
            key = f"env:{inference.caution_target}"
            text = CAUTION_ENVIRONMENT.format(env=session.environment)
        else:
            return None, False
        if not session.remember_caution(key):
            return None, False
        now = self._wall_clock()
        counted = session.advisory_budget_left(now)
        if counted:
            session.spend_advisory_message(now)
        return text, counted

    # ------------------------------------------------------------------ detector

    def _run_detector(self, finding: Finding, envelope: schemas.HookEnvelope, session: HookSession) -> dict[str, Any]:
        """The stuck detector, isolated: any exception is swallowed and the
        floor's response is returned untouched (plan §2). Returns the details
        to record; `signal` is present when it fired."""
        if finding.verdict not in DETECTOR_VERDICTS or (envelope.tool_name or "") in self._detector_exempt:
            return {}
        try:
            session.last_pre_seq += 1
            pre_seq = session.last_pre_seq
            ident = stuck.identity(envelope.tool_name, envelope.tool_input)
            signal = stuck.evaluate(session.stuck, ident, pre_seq)
            if envelope.tool_use_id:
                session.stuck.start(envelope.tool_use_id, ident, pre_seq, now=time.monotonic())
            if signal is None:
                return {}
            # First firing of a (rule, identity): nudge the agent only. A later
            # firing of the same pair: one systemMessage per identity per
            # boundary, if the budget allows. Streak length is not used here
            # because mixed-result streaks make it overshoot (review #1, #2).
            key = (signal.rule_id, signal.identity)   # for S3 the identity is the A|B pair
            persisted = key in session.stuck.nudged
            session.stuck.nudged.add(key)
            message_sent = False
            # On a host whose only person-facing channel is its approval popup
            # (`ask`), the message is reserved for shell retries: an agent
            # polling a file with `Read` thirty times is not worth a popup
            # (spike log, October 13: 34 identical terminal-file reads). The
            # agent still gets the nudge as context, and nothing is spent.
            popup_worthy = self._person_channel != "ask" or (envelope.tool_name or "") in SHELL_TOOLS
            now = self._wall_clock()
            if (persisted and popup_worthy and signal.identity not in session.stuck.messaged_identities
                    and session.advisory_budget_left(now)):
                session.stuck.messaged_identities.add(signal.identity)
                session.spend_advisory_message(now)
                message_sent = True
            return {"signal": signal, "rule_id": signal.rule_id, "streak": signal.streak, "message_sent": message_sent,
                    **({"popup_withheld": True} if persisted and not popup_worthy else {})}
        except Exception as exc:  # noqa: BLE001 - a detector bug is never a deny
            log.exception("stuck detector failed")
            return {"error": type(exc).__name__, "detector_error": True}

    def _complete_action(self, session: Optional[HookSession], envelope: schemas.HookEnvelope, *, failed: bool) -> Optional[str]:
        if session is None or not envelope.tool_use_id or (envelope.tool_name or "") in self._detector_exempt:
            return None
        try:
            result = stuck.error_fingerprint(envelope.error) if failed else stuck.fingerprint(envelope.tool_name, envelope.tool_response)
            with self._sessions.lock(session.session_id):
                session.last_pre_seq += 1
                session.stuck.complete(envelope.tool_use_id, result=result, failed=failed, post_seq=session.last_pre_seq)
            return result
        except Exception:  # noqa: BLE001
            log.exception("could not record tool completion")
            return None

    def permission_request(self, payload: Any) -> dict[str, Any]:
        envelope = self._envelope_or_none(payload)
        if envelope is None:
            return {}
        session = self._sessions.get(envelope.session_id)
        caused_by_sentinel = bool(session and envelope.tool_use_id and envelope.tool_use_id in session.asked_tool_use_ids)
        self._write_optional(AuditEvent(
            event_type="permission_request", request_id=envelope.tool_use_id, session_id=envelope.session_id,
            agent_id=envelope.agent_id or self._host,
            details={"host": self._host, "tool": envelope.tool_name, "caused_by_sentinel": caused_by_sentinel,
                     "permission_mode": envelope.permission_mode},
        ))
        return {}

    def permission_denied(self, payload: Any) -> dict[str, Any]:
        """Auto-mode classifier denials only. Nothing is inferred from them."""
        envelope = self._envelope_or_none(payload)
        if envelope is None:
            return {}
        self._write_optional(AuditEvent(
            event_type="permission_denied", request_id=envelope.tool_use_id, session_id=envelope.session_id,
            agent_id=envelope.agent_id or self._host,
            details={"host": self._host, "tool": envelope.tool_name, "reason": (envelope.reason or "")[:500]},
        ))
        return {}

    def config_change(self, payload: Any) -> dict[str, Any]:
        envelope = self._envelope_or_none(payload)
        if envelope is None:
            return {}
        session = self._sessions.get(envelope.session_id)
        source = envelope.source or "unknown"
        file_path = envelope.file_path
        if source == "policy_settings":
            if session is not None:
                with self._sessions.lock(session.session_id):
                    self._refresh_enforcement(session, force=True)
            self._write_optional(AuditEvent(
                event_type="config_change", session_id=envelope.session_id, agent_id=self._host,
                details={"host": self._host, "source": source, "file_path": file_path, "blocked": False,
                         "enforcement": session.enforcement.state if session and session.enforcement else None},
            ))
            return {}
        blocked = False
        reason = ""
        if source == "skills":
            blocked, reason = True, "Skill files can declare hooks; changes during a supervised session are not applied."
        elif file_path and session is not None:
            before = session.config_snapshots.get(file_path)
            after = self._snapshot(Path(file_path))
            if (before or {}) != (after or {}):
                changed = sorted({k for k in CONFIG_CHANGE_KEYS if (before or {}).get(k) != (after or {}).get(k)})
                blocked = True
                reason = f"Settings keys that govern hooks or permissions changed ({', '.join(changed) or 'contents'}); the change is not applied."
        record: Optional[DecisionRecord] = None
        if blocked:
            try:
                record = DecisionRecord(
                    action=ActionDescription(
                        family="file", host=self._host, tool="ConfigChange",
                        working_directory=session.launch_cwd if session else None,
                        working_directory_source=session.working_directory_source if session else None,  # type: ignore[arg-type]
                        targets=[ResolvedTarget(raw=file_path or source, kind="write", surface="filesystem",
                                                filesystem=FilesystemFacts(resolved=file_path, zone="protected_config"))]
                        if file_path else [],
                    ),
                    judgment=Judgment(verdict="block", floor_verdict="block", rule_id="F2.hook_config_change",
                                      ceiling_version=self._policy.version,
                                      enforcement=session.enforcement.state if session and session.enforcement else "unknown",
                                      reason=reason, agent_guidance=reason + " Hook and permission settings are the user's to change.",
                                      message="sent"),
                )
            except Exception:  # noqa: BLE001
                record = None
        self._write_optional(AuditEvent(
            event_type="config_change", session_id=envelope.session_id, agent_id=self._host,
            verdict="block" if blocked else None,
            reason_codes=["F2.hook_config_change"] if blocked else [],
            details={"host": self._host, "source": source, "file_path": file_path, "blocked": blocked},
            decision=record,
        ))
        return schemas.config_block_response(reason) if blocked else {}

    def session_start(self, payload: Any) -> dict[str, Any]:
        try:
            report = schemas.SessionStartReport.model_validate(payload)
        except (ValidationError, TypeError, ValueError):
            return {}
        project_dir = report.project_dir or report.cwd
        applied = False
        session = self._sessions.get(report.session_id)
        if project_dir and project_dir.startswith("/"):
            if session is None:
                environment = self._policy.environment_for(project_dir)
                session = self._sessions.ensure(report.session_id, launch_cwd=project_dir, source="launch",
                                                environment=environment, environment_for=self._policy.environment_for)
                applied = True
            else:
                with self._sessions.lock(session.session_id):
                    applied = session.narrow_launch_cwd(project_dir, environment_for=self._policy.environment_for)
        if session is not None:
            with self._sessions.lock(session.session_id):
                if report.claude_version and not session.claude_version:
                    session.claude_version = report.claude_version
                if applied and not session.config_snapshots:
                    self._take_snapshots(session)
                self._refresh_enforcement(session, force=True)
        self._write_optional(AuditEvent(
            event_type="session_start", session_id=report.session_id, agent_id=self._host,
            details={"host": self._host, "project_dir": project_dir, "applied": applied, "source": report.source,
                     "claude_version": report.claude_version,
                     "launch_cwd": session.launch_cwd if session else None,
                     "enforcement": session.enforcement.state if session and session.enforcement else None},
        ))
        return {}

    # ------------------------------------------------------------------ judging

    def _judge(self, envelope: schemas.HookEnvelope, session: HookSession) -> tuple[Finding, Optional[Callable[[str, float], DecisionRecord]]]:
        tool = envelope.tool_name or ""
        tool_input = envelope.tool_input
        common = dict(launch_cwd=session.launch_cwd, working_directory_source=session.working_directory_source,
                      ceiling_version=self._policy.version, enforcement=self._enforcement_value(session),
                      history=session.history, tool_input=tool_input, host=self._host)
        if tool in SHELL_TOOLS:
            command = tool_input.get("command")
            if not isinstance(command, str) or not command.strip():
                finding = Finding("block", "adapter:invalid_payload", "The shell call carried no command text to check; it is not allowed.")
                return finding, None
            cwd = envelope.cwd if envelope.cwd and envelope.cwd.startswith("/") else session.launch_cwd
            finding = decide_shell(command, cwd=cwd, launch_cwd=session.launch_cwd, home=self._home,
                                   environment=session.environment, history=session.history,
                                   sentinel_port=self._policy.sentinel_port, now=self._wall_clock())
            return finding, lambda message, latency: shell_record(
                finding, command=command, tool=tool, environment=session.environment, message=message,
                latency_ms=latency, **common)
        if tool in WRITE_TOOLS:
            path = tool_input.get("file_path") or tool_input.get("notebook_path")
            finding = decide_path(path if isinstance(path, str) else None, "write", launch_cwd=session.launch_cwd,
                                  home=self._home, history=session.history, tool=tool)
            zone = self._zone_or_none(path, session.launch_cwd)
            return finding, lambda message, latency: path_record(
                finding, family="file", tool=tool, message=message, latency_ms=latency, zone=zone, **common)
        if tool in DELETE_TOOLS:
            path = tool_input.get("file_path") or tool_input.get("path")
            finding = decide_path(path if isinstance(path, str) else None, "delete", launch_cwd=session.launch_cwd,
                                  home=self._home, history=session.history, tool=tool)
            zone = self._zone_or_none(path, session.launch_cwd)
            return finding, lambda message, latency: path_record(
                finding, family="file", tool=tool, message=message, latency_ms=latency, zone=zone, **common)
        if tool in PATCH_TOOLS:
            # Each file the patch names is judged as Write or Delete would be;
            # a patch with no readable header stays the opaque-write confirm
            # (review S15b): an unseen write tool is otherwise a path bypass.
            finding = decide_patch(files_from_tool_input(tool_input), launch_cwd=session.launch_cwd,
                                   home=self._home, tool=tool)
            return finding, lambda message, latency: path_record(
                finding, family="file", tool=tool, message=message, latency_ms=latency, zone=None, **common)
        if tool in READ_TOOLS:
            path = tool_input.get("file_path") or tool_input.get("path")
            finding = decide_path(path if isinstance(path, str) else None, "read", launch_cwd=session.launch_cwd,
                                  home=self._home, history=session.history, tool=tool)
            zone = self._zone_or_none(path, session.launch_cwd)
            return finding, lambda message, latency: path_record(
                finding, family="file", tool=tool, message=message, latency_ms=latency, zone=zone, **common)
        if tool in WEB_TOOLS:
            return self._judge_web(tool, tool_input, session, common)
        if tool.startswith("mcp__"):
            return self._judge_mcp(tool, envelope, session, common)
        return Finding("allow", "", ""), None

    def _judge_web(self, tool: str, tool_input: dict[str, Any], session: HookSession, common: dict[str, Any]):
        url = tool_input.get("url") if tool == "WebFetch" else None
        host = (urlsplit(url).hostname or "").lower() if isinstance(url, str) else ""
        finding = Finding("allow", "", "", [host] if host else [])
        if session.history.tainted(self._wall_clock()):
            if tool == "WebSearch":
                finding = Finding("confirm_required", "F4.web_egress_after_credential_read",
                                  "A web search within 30 minutes of a credential store being read can carry data off the machine. Ask the user before searching.")
            elif host and host not in session.web_hosts_seen:
                finding = Finding("confirm_required", "F4.web_egress_after_credential_read",
                                  f"Fetches a host not seen earlier in this session ({host}) within 30 minutes of a credential store being read; the URL can carry data off the machine. Ask the user.", [host])
        if host:
            session.web_hosts_seen.add(host)

        def build(message: str, latency: float) -> DecisionRecord:
            targets = [ResolvedTarget(raw=host, kind="network", surface="resource",
                                      resource=ResourceFacts(resource_type="web_host", resource_id=host))] if host else []
            return DecisionRecord(
                action=ActionDescription(family="web", host=common["host"], tool=tool, payload_sha256=payload_sha256(common["tool_input"]),
                                         working_directory=common["launch_cwd"], working_directory_source=common["working_directory_source"],
                                         targets=targets),
                judgment=_judgment(finding, common, message, latency),
            )
        return finding, build

    def _judge_mcp(self, tool: str, envelope: schemas.HookEnvelope, session: HookSession, common: dict[str, Any]):
        outside: list[tuple[str, str]] = []
        for value in _string_values(envelope.tool_input):
            if value.startswith("/") or value.startswith("~/"):
                resolved = posixpath.normpath(self._home + value[1:] if value.startswith("~/") else value)
                zone = zone_of(resolved, session.launch_cwd, self._home)
                if zone not in INSIDE_ZONES:
                    outside.append((resolved, zone))
        source = envelope.mcp_server.source if envelope.mcp_server else None
        finding = Finding("allow", "", "")
        if outside:
            resolved, zone = outside[0]
            finding = Finding("confirm_required", "F5.mcp_path_outside",
                              f"The MCP tool is given a path outside the working directory ({resolved}, {zone}). Sentinel cannot see what the server does with it; ask the user.",
                              [r for r, _ in outside])
        elif source is not None and source not in self._policy.accepted_mcp_sources:
            finding = Finding("confirm_required", "F5.mcp_source_unaccepted",
                              f"The MCP server comes from a source Sentinel's policy does not accept ({source}). Ask the user.")

        def build(message: str, latency: float) -> DecisionRecord:
            targets = [ResolvedTarget(raw=r[:4096], kind="write", surface="filesystem",
                                      filesystem=FilesystemFacts(resolved=r, zone=z)) for r, z in outside[:50]]  # type: ignore[arg-type]
            targets.append(ResolvedTarget(raw=tool, kind="execute", surface="resource",
                                          resource=ResourceFacts(resource_type="mcp_tool", resource_id=f"{source or 'unknown'}:{tool}")))
            return DecisionRecord(
                action=ActionDescription(family="mcp", host=common["host"], tool=tool, payload_sha256=payload_sha256(common["tool_input"]),
                                         working_directory=common["launch_cwd"], working_directory_source=common["working_directory_source"],
                                         targets=targets),
                judgment=_judgment(finding, common, message, latency),
            )
        return finding, build

    def _zone_or_none(self, path: Any, launch_cwd: str) -> Optional[str]:
        """The zone of a file-tool path, for the record's target (the finding
        carries only the rule)."""
        if not isinstance(path, str) or not path.startswith(("/", "~")):
            return None
        resolved = posixpath.normpath(self._home + path[1:] if path.startswith("~") else path)
        return zone_of(resolved, launch_cwd, self._home)

    # ------------------------------------------------------------------ responses

    def _response_for(self, finding: Finding, session: HookSession, envelope: schemas.HookEnvelope) -> tuple[dict[str, Any], str]:
        if finding.interrupts and self._policy.is_log_only(finding.rule):
            return schemas.allow_response(), "none"
        advisory_note = None
        if session.enforcement is not None and session.enforcement.state == "advisory":
            advisory_note = (f"Sentinel blocked this action but its hook is not locked on this machine "
                             f"({', '.join(session.enforcement.failed[:3]) or session.enforcement.state}); the block may not hold. "
                             f"Run `{self._doctor_command}`.")
        if finding.verdict == "block":
            return schemas.deny_response(finding.reason, system_message=advisory_note), "none"
        if finding.verdict == "confirm_required":
            mode = envelope.permission_mode or session.permission_mode or ""
            if mode in self._policy.ask_fallback_modes:
                guidance = (f"{finding.reason} Sentinel needs the user's confirmation and cannot prompt in permission mode "
                            f"'{mode}'. Ask the user in chat; do not retry until they have answered.")
                return schemas.deny_response(guidance), "none"
            if self._ask_capable is not None and not self._ask_capable(envelope):
                guidance = (f"{finding.reason} Sentinel needs the user's confirmation and this host {CONFIRM_UNDELIVERABLE_MARKER} "
                            f"for the {envelope.tool_name or 'tool'} tool. Ask the user in chat; do not retry until "
                            f"they have answered.")
                return schemas.deny_response(guidance), "none"
            return schemas.ask_response(f"Sentinel: {finding.reason}"), "sent"
        if finding.verdict == "warn":
            return schemas.context_response(f"Sentinel note: {finding.reason}"), "none"
        return schemas.allow_response(), "none"

    # ------------------------------------------------------------------ sessions

    def _session_for(self, envelope: schemas.HookEnvelope) -> HookSession:
        existing = self._sessions.get(envelope.session_id)
        if existing is not None:
            return existing
        cwd = envelope.cwd if envelope.cwd and envelope.cwd.startswith("/") else self._home
        launch = containing_repository(cwd)
        session = self._sessions.ensure(envelope.session_id, launch_cwd=launch, source="hook_payload",
                                        environment=self._policy.environment_for(launch),
                                        environment_for=self._policy.environment_for)
        with self._sessions.lock(session.session_id):
            if not session.config_snapshots:
                self._take_snapshots(session)
        return session

    def _take_snapshots(self, session: HookSession) -> None:
        for _, path in settings_files_for(session.launch_cwd, self._home).items():
            try:
                session.config_snapshots[str(path)] = self._snapshot(path)
            except OSError:
                session.config_snapshots[str(path)] = None

    def _refresh_enforcement(self, session: HookSession, *, force: bool = False) -> None:
        now = _now()
        if not force and session.enforcement is not None and session.enforcement_checked_at is not None:
            if (now - session.enforcement_checked_at).total_seconds() < ENFORCEMENT_RECHECK_SECONDS and session.enforcement.liveness == session.seen_pre_tool_use:
                return
        if self._enforcement_evaluator is not None:
            try:
                session.enforcement = self._enforcement_evaluator(session)
            except Exception as exc:  # noqa: BLE001 - an evaluator bug is an advisory claim, never a pass
                log.warning("enforcement evaluator failed: %s", exc)
                session.enforcement = EnforcementReport(state="advisory", failed=("evaluator_error",),
                                                        liveness=session.seen_pre_tool_use)
            session.enforcement_checked_at = now
            return
        try:
            facts = self._collect_facts()
        except Exception as exc:  # noqa: BLE001 - an unreadable file is an advisory claim, not a crash
            log.warning("managed settings could not be read: %s", exc)
            facts = SettingsFacts(path=str(self._managed_settings) if self._managed_settings else None, exists=False)
        session.enforcement = evaluate_enforcement(facts, self._policy.hook, claude_version=session.claude_version,
                                                   liveness=session.seen_pre_tool_use)
        session.enforcement_checked_at = now

    def _enforcement_value(self, session: HookSession) -> str:
        return session.enforcement.state if session.enforcement is not None else "unknown"

    # ------------------------------------------------------------------ helpers

    def _envelope_or_none(self, payload: Any) -> Optional[schemas.HookEnvelope]:
        try:
            return schemas.HookEnvelope.model_validate(payload)
        except (ValidationError, TypeError, ValueError):
            return None

    def _write_optional(self, event: AuditEvent) -> None:
        try:
            self._audit.write(event)
        except Exception as exc:  # noqa: BLE001 - telemetry never changes a verdict
            log.warning("optional audit write failed: %s", exc)


def _judgment(finding: Finding, common: dict[str, Any], message: str, latency: float) -> Judgment:
    interrupting = finding.interrupts
    return Judgment(
        verdict=finding.verdict, floor_verdict=finding.verdict, decided_by="floor",  # type: ignore[arg-type]
        rule_id=finding.rule or None, ceiling_version=common["ceiling_version"], enforcement=common["enforcement"],
        reason=(finding.reason or "No floor rule matched.")[:2000],
        agent_guidance=finding.reason[:2000] if interrupting else None,
        history_facts=common["history"].facts(), message=message, latency_ms=latency,  # type: ignore[arg-type]
    )


def _detector_record(record: DecisionRecord, signal: stuck.Signal, message: str) -> DecisionRecord:
    """Re-stamp a floor record as a detector `warn` (decided_by=detector keeps
    floor_verdict so the invariant "never below the floor" is checkable)."""
    data = record.model_dump(mode="json")
    judgment = data["judgment"]
    judgment.update({
        "verdict": "warn", "decided_by": "detector", "rule_id": signal.rule_id,
        "reason": signal.nudge, "agent_guidance": signal.nudge, "message": message,
    })
    return DecisionRecord.model_validate(data)


_EXIT_CODE = re.compile(r"^\s*Exit code (\d{1,5})\b")


def _exit_code(error: Optional[str]) -> Optional[int]:
    match = _EXIT_CODE.match(error or "")
    return int(match.group(1)) if match else None


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _boundary_line(root: str, environment: str, *, focus: Optional[str], caution: Optional[str]) -> str:
    """One sentence from server facts; line + focus + caution under 400
    characters. The focus is shown relative to the root; roots truncated from
    the left."""
    tail = f" {caution}" if caution else ""
    hint = ""
    if focus and focus.startswith(root.rstrip("/") + "/"):
        hint = f" This prompt points at `{focus[len(root.rstrip('/')) + 1:]}`."
    fixed = len("Sentinel boundary: `` (). Work inside it; ask the user before touching anything outside it.") + len(environment) + len(tail)
    room = MAX_CONTEXT_CHARS - fixed - 1
    shown_root, shown_hint = root, hint
    if len(shown_root) + len(shown_hint) > room:
        shown_hint = ""
        if len(shown_root) > room:
            shown_root = "…" + shown_root[-(room - 1):]
    return (f"Sentinel boundary: `{shown_root}` ({environment}). Work inside it; ask the user before touching "
            f"anything outside it.{shown_hint}{tail}")


def _response_kind(response: dict[str, Any]) -> str:
    hook = response.get("hookSpecificOutput") or {}
    decision = hook.get("permissionDecision")
    if decision:
        return str(decision)
    if hook.get("additionalContext"):
        return "context"
    return "empty"


def _string_values(value: Any, depth: int = 0) -> list[str]:
    if depth > 6:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _string_values(v, depth + 1)]
    if isinstance(value, list):
        return [s for v in value[:200] for s in _string_values(v, depth + 1)]
    return []


__all__ = ["CONFIRM_UNDELIVERABLE_MARKER", "ClaudeCodeHookService", "EnforcementReport"]
