"""Authenticated FastAPI handoff for mediated MCP fixture calls.

`McpMediator` is the single place where an adapter call meets Sentinel's
authorities. For every call it: authenticates the adapter session, checks the
startup ceiling is bound and unexpired, canonicalizes the raw arguments,
intersects the ceiling with the active contract, audits the decision, and only
then touches the fixture. Effects happen only after durable audit admission,
and only through the fixture's at-most-once operation record.

Approval for confirm-required writes uses the existing approval service and
coordinator: the browser approves in the protected control center, the server
retries the unchanged action once, and the token never leaves the process.
"""

from __future__ import annotations

import json
from contextlib import nullcontext
from datetime import datetime, timezone
from typing import Any, Callable, ContextManager
from uuid import uuid4

from sentinel.api.integration_schemas import McpCallRequest, McpCallResponse
from sentinel.api.schemas import EvaluateResponse
from sentinel.approval.service import ApprovalBinding, InMemoryApprovalService
from sentinel.audit.base import AuditStore, AuditStoreError
from sentinel.audit.models import AuditEvent
from sentinel.authority.service import ContractAuthorityService
from sentinel.contracts import ContractRecord
from sentinel.control.approvals import ApprovalExecutionEnvelope, InMemoryApprovalCoordinator
from sentinel.control.workspace import SupervisionBinding
from sentinel.decision.contract_policy import match_action_to_contract
from sentinel.decision.engine import VERDICT_RISK_SCORES, VERDICT_TO_RISK_TIER
from sentinel.integrations import AdapterSession, AdapterSessionError, AdapterSessionRegistry
from sentinel.mcp.fixture import FixtureError, OperationBinding, SQLiteIssueFixture
from sentinel.mcp.mediation import (
    PROPOSAL_TOOL,
    McpActionFacts,
    McpCanonicalizationError,
    McpDecision,
    canonicalize_mcp_call,
    canonicalize_task_proposal,
    decide_mcp_action,
)
from sentinel.proposals import ProposalError, TaskProposalService
from sentinel.supervision import SupervisionPolicyBinding

ADAPTER_AGENT_ID = "cursor_mcp_adapter"
ADAPTER_USER_ID = "adapter"
LockFactory = Callable[[str], ContextManager[None]]


class McpMediator:
    def __init__(
        self,
        *,
        registry: AdapterSessionRegistry,
        fixture: SQLiteIssueFixture,
        policy_binding: SupervisionPolicyBinding,
        supervision: SupervisionBinding,
        contract_store: Any,
        authority_service: ContractAuthorityService,
        approval_service: InMemoryApprovalService,
        approval_coordinator: InMemoryApprovalCoordinator,
        audit_store: AuditStore,
        environment: str,
        lock: LockFactory | None = None,
        clock: Callable[[], datetime] | None = None,
        proposals: TaskProposalService | None = None,
    ) -> None:
        self._registry = registry
        self._fixture = fixture
        self._policy_binding = policy_binding
        self._supervision = supervision
        self._contracts = contract_store
        self._authority = authority_service
        self._approvals = approval_service
        self._coordinator = approval_coordinator
        self._audit = audit_store
        self._environment = environment
        self._lock = lock or (lambda _session_id: nullcontext())
        self._now = clock or (lambda: datetime.now(timezone.utc))
        self._proposals = proposals

    # -- adapter entry point ----------------------------------------------------------

    def mediate(self, bearer: str | None, payload: McpCallRequest) -> McpCallResponse:
        """Decide and, when authorized, apply one adapter call. Raises AdapterSessionError."""

        adapter = self._registry.authenticate(bearer, now=self._now())
        with self._lock(self._supervision.session_id):
            response = self._mediate_locked(adapter, payload)
        self._registry.record_call(tool=payload.tool, verdict=response.verdict, now=self._now())
        return response

    def _mediate_locked(self, adapter: AdapterSession, payload: McpCallRequest) -> McpCallResponse:
        request_id = str(uuid4())
        ceiling_problem = self._ceiling_problem(adapter)
        if ceiling_problem is not None:
            return self._blocked(request_id, payload, ceiling_problem, coverage="unavailable")
        if payload.tool == PROPOSAL_TOOL:
            # Proposals share the bearer, ceiling, and audit path but are not
            # fixture operations: nothing below this line runs for them.
            return self._propose(request_id, adapter, payload)
        try:
            facts = canonicalize_mcp_call(payload.tool, payload.arguments, environment=self._environment)
        except McpCanonicalizationError as exc:
            coverage = "unsupported" if exc.reason_code == "mcp:unsupported_tool" else "mandatory"
            problem = McpDecision("block", exc.reason_code, exc.reason, (exc.reason_code,),
                                  "Use only the declared fixture tools with exactly their documented arguments.")
            self._write_decision(request_id, payload, problem, facts=None, record=None)
            return self._blocked(request_id, payload, problem, coverage=coverage)

        record = self._active_record()
        decision = self._decide(facts, record)
        self._write_decision(request_id, payload, decision, facts=facts, record=record)
        if decision.verdict == "block" or record is None:
            return self._blocked(request_id, payload, decision, coverage="mandatory")

        binding = self._operation_binding(payload.attempt_id, adapter, facts, record)
        try:
            operation = self._fixture.prepare(binding)
        except FixtureError as exc:
            problem = McpDecision("block", exc.reason_code, "The attempt does not match its first reviewed action.",
                                  (exc.reason_code,), "Start a new attempt for a changed action; never reuse an attempt ID.")
            return self._blocked(request_id, payload, problem, coverage="mandatory")

        if operation.state in {"succeeded", "failed", "unknown", "applying"}:
            # `applying` means an earlier attempt crashed mid-effect and has not
            # been reconciled; treat it as unknown rather than re-admitting it.
            return self._terminal(request_id, payload, decision, operation.state, operation.result,
                                  duplicate=operation.state == "succeeded")
        if decision.verdict == "allow":
            return self._admit_and_apply(request_id, payload, decision, facts, record, binding, approval_id=None)
        return self._request_or_report_approval(request_id, payload, decision, facts, record, binding)

    # -- agent task proposals -----------------------------------------------------------

    def _propose(self, request_id: str, adapter: AdapterSession, payload: McpCallRequest) -> McpCallResponse:
        if self._proposals is None:
            problem = McpDecision("block", "mcp:unsupported_tool", "Task proposals are not enabled in this process.",
                                  ("mcp:unsupported_tool",), "Ask the user to create the task in the Sentinel control center.")
            self._write_decision(request_id, payload, problem, facts=None, record=None)
            return self._blocked(request_id, payload, problem, coverage="unsupported")
        try:
            facts = canonicalize_task_proposal(payload.arguments)
            proposal, superseded = self._proposals.propose(
                facts, request_id=request_id, adapter_session_id=adapter.adapter_session_id,
            )
        except (McpCanonicalizationError, ProposalError) as exc:
            guidance = getattr(exc, "guidance", "") or (
                "Call sentinel_task_propose with exactly: operation ('read' or 'write'), "
                "issue_ids (list of issue IDs), minutes (whole number)."
            )
            field = getattr(exc, "field", None)
            if field:
                guidance = f"Fix the '{field}' argument. {guidance}"
            problem = McpDecision("block", exc.reason_code, exc.reason, (exc.reason_code,), guidance)
            self._write_decision(request_id, payload, problem, facts=None, record=None)
            return self._blocked(request_id, payload, problem, coverage="mandatory")
        active = self._active_record()
        decision = McpDecision(
            "confirm_required", "task:proposal_pending",
            "The task proposal is stored and waiting for the user to confirm it in Sentinel.",
            ("task:proposal_pending",),
            "A task proposal is waiting for the user in Sentinel. Do not retry or call other tools until they confirm it.",
        )
        self._write_decision(request_id, payload, decision, facts=None, record=None)
        return McpCallResponse(
            request_id=request_id, verdict="confirm_required", reason_code=decision.reason_code,
            reason=decision.reason, reason_codes=list(decision.reason_codes), guidance=decision.guidance,
            risk_score=VERDICT_RISK_SCORES["confirm_required"], risk_tier=VERDICT_TO_RISK_TIER["confirm_required"],
            attempt_id=payload.attempt_id, coverage_status="mandatory",
            result={
                "draft_id": proposal.draft_id,
                "proposal_expires_at": proposal.proposal_expires_at.isoformat(),
                "replaces_active_task": active is not None,
                "superseded_draft_id": superseded.draft_id if superseded else None,
            },
        )

    # -- protected-browser retry ------------------------------------------------------

    def retry_approved(self, envelope: ApprovalExecutionEnvelope, token: str) -> EvaluateResponse:
        """Server-owned retry after a human approved the exact envelope."""

        request_id = str(uuid4())
        with self._lock(self._supervision.session_id):
            arguments = json.loads(envelope.arguments_json)
            facts = canonicalize_mcp_call(envelope.tool or "", arguments, environment=self._environment)
            record = self._active_record()
            adapter = self._registry.current(self._policy_binding.policy.adapter_kind)
            if record is None or adapter is None or self._ceiling_problem(adapter) is not None:
                return self._evaluate_response(request_id, "block", ["approval:authority_changed"],
                                               "Authority changed before the approved retry; nothing was performed.")
            binding = self._operation_binding(envelope.attempt_id, adapter, facts, record)
            approval_binding = self._approval_binding(envelope.attempt_id, facts, record)
            if approval_binding != envelope.binding:
                return self._evaluate_response(request_id, "block", ["approval:binding_mismatch"],
                                               "The approved action no longer matches; nothing was performed.")
            # The prepared operation was bound to the adapter session and ceiling
            # at request time. If either changed since (for example the adapter
            # capability was rotated), refuse before consuming the token so the
            # approver sees a clean block instead of a failed apply.
            prepared = self._fixture.get(envelope.attempt_id)
            if prepared is None or prepared.binding_sha256 != binding.binding_sha256:
                if prepared is not None and prepared.state in {"prepared", "admitted"}:
                    self._fixture.fail(envelope.attempt_id, reason="binding_changed_before_approval")
                return self._evaluate_response(request_id, "block", ["approval:binding_mismatch"],
                                               "The adapter session or ceiling changed before the approved retry; "
                                               "nothing was performed. Ask the agent to submit a new request.")
            try:
                consumed = self._approvals.consume(
                    token,
                    approval_binding,
                    consume_observer=lambda issued: self._admit(request_id, envelope.attempt_id, facts, record,
                                                                approval_id=issued.approval_id),
                )
            except AuditStoreError:
                # The observer raised before the token was deleted, so the token is
                # still unconsumed; the coordinator discards it. Nothing was performed.
                return self._evaluate_response(request_id, "block", ["audit:admission_failed"],
                                               "Sentinel could not durably record admission; nothing was performed.")
            except FixtureError as exc:
                return self._evaluate_response(request_id, "block", [exc.reason_code],
                                               "The operation is not in a state that can be admitted; nothing was performed.")
            if not consumed:
                return self._evaluate_response(request_id, "block", ["approval:token_invalid_or_mismatch"],
                                               "Approval could not be consumed; nothing was performed.")
            try:
                operation = self._fixture.apply(binding)
            except FixtureError as exc:
                self._write_effect(request_id, envelope.attempt_id, facts, record, "failed")
                return self._evaluate_response(
                    request_id, "block", ["mcp:approved_write_not_applied", exc.reason_code],
                    "The approval was used, but the fixture refused the write; nothing was performed.",
                    approval_id=envelope.approval_id,
                )
            self._write_effect(request_id, envelope.attempt_id, facts, record, operation.state)
            if operation.state != "succeeded":
                return self._evaluate_response(
                    request_id, "block", ["mcp:approved_write_not_applied", f"fixture:{operation.state}"],
                    "The approval was used, but the write did not complete; check Activity before retrying.",
                    approval_id=envelope.approval_id,
                )
            return self._evaluate_response(
                request_id, "allow", ["mcp:approved_write_applied"],
                "The approved note was applied exactly once.", approval_id=envelope.approval_id,
                extra_reasons=[f"fixture:{operation.state}"],
            )

    def abandon_denied(self, attempt_id: str | None) -> None:
        """Mark a denied fixture operation failed so later retries report the denial."""

        if not attempt_id:
            return
        operation = self._fixture.get(attempt_id)
        if operation is not None and operation.state == "prepared":
            self._fixture.fail(attempt_id, reason="approval_denied")

    # -- internals --------------------------------------------------------------------

    def _ceiling_problem(self, adapter: AdapterSession) -> McpDecision | None:
        policy = self._policy_binding.policy
        if self._policy_binding.is_expired(self._now()):
            return McpDecision("block", "supervision:ceiling_expired", "The startup ceiling has expired.",
                               ("supervision:ceiling_expired",), "Ask the user to restart Sentinel.")
        if adapter.tool_family != policy.tool_family or adapter.adapter_kind != policy.adapter_kind:
            return McpDecision("block", "supervision:outside_tool_family",
                               "This adapter session is not covered by the startup ceiling.",
                               ("supervision:outside_tool_family",), "Reconnect through the Sentinel MCP shim.")
        if adapter.supervision_session_id != self._supervision.session_id:
            return McpDecision("block", "adapter:session_mismatch", "Adapter session is bound elsewhere.",
                               ("adapter:session_mismatch",), "Reconnect through the Sentinel MCP shim.")
        return None

    def _active_record(self) -> ContractRecord | None:
        if not self._authority.authority_available:
            return None
        return self._contracts.get_active(self._supervision.session_id, now=self._now())

    def _decide(self, facts: McpActionFacts, record: ContractRecord | None) -> McpDecision:
        policy = self._policy_binding.policy
        ceiling = policy.classify(
            adapter_kind=policy.adapter_kind, tool_family=policy.tool_family, operation=facts.operation,
            issue_id=facts.issue_id, environment=self._environment, note_bytes=facts.note_bytes,
        )
        match = None
        if record is not None:
            match = match_action_to_contract(
                record, facts.action, expected_contract_id=record.contract_id, expected_version=record.version,
                session_id=self._supervision.session_id, active_task_id=record.task_id, now=self._now(),
            )
        proposal_pending = (
            record is None and self._proposals is not None and self._proposals.pending() is not None
        )
        return decide_mcp_action(ceiling, match, proposal_pending=proposal_pending)

    def _operation_binding(self, attempt_id: str, adapter: AdapterSession, facts: McpActionFacts,
                           record: ContractRecord) -> OperationBinding:
        return OperationBinding(
            attempt_id=attempt_id, adapter_session_id=adapter.adapter_session_id,
            supervision_session_id=self._supervision.session_id, task_id=record.task_id,
            contract_version=record.version, authority_epoch=str(record.authority_epoch),
            policy_sha256=self._policy_binding.content_sha256, tool=facts.tool,
            operation=facts.operation,  # type: ignore[arg-type]
            issue_id=facts.issue_id, note_body=facts.note_body,
        )

    def _approval_binding(self, attempt_id: str, facts: McpActionFacts, record: ContractRecord) -> ApprovalBinding:
        from sentinel.actions.models import fingerprint_action

        return ApprovalBinding(
            contract_id=record.contract_id, contract_version=record.version,
            authority_epoch=record.authority_epoch, action_fingerprint=fingerprint_action(facts.action),
            environment=self._environment, session_id=self._supervision.session_id,
            task_id=record.task_id, attempt_id=attempt_id,
        )

    def _admit(self, request_id: str, attempt_id: str, facts: McpActionFacts, record: ContractRecord,
               *, approval_id: str | None) -> None:
        """Durable admission: required audit first, then the fixture's admitted state.

        The fixture state is checked before the audit row is written so a
        non-admittable operation (for example one stuck in `applying`) does not
        accumulate admission evidence it never earned.
        """

        current = self._fixture.get(attempt_id)
        if current is None:
            raise FixtureError("fixture:unknown_attempt")
        if current.state not in {"prepared", "admitted"}:
            raise FixtureError(f"fixture:cannot_admit_from_{current.state}")
        self._audit.write_required(
            AuditEvent(
                event_type="execution_admitted", request_id=request_id, agent_id=ADAPTER_AGENT_ID,
                session_id=self._supervision.session_id, task_id=record.task_id,
                contract_id=record.contract_id, contract_version=record.version,
                environment=self._environment,  # type: ignore[arg-type]
                verdict="allow", reason_codes=["mcp:admitted"],
                details={"attempt_id": attempt_id, "tool": facts.tool, "operation": facts.operation,
                         "targets": [facts.issue_id], "payload_sha256": facts.action.payload_sha256,
                         "authority_epoch": record.authority_epoch, "approval_id": approval_id,
                         "policy_sha256": self._policy_binding.content_sha256},
            )
        )
        self._fixture.admit(attempt_id)

    def _admit_and_apply(self, request_id: str, payload: McpCallRequest, decision: McpDecision,
                         facts: McpActionFacts, record: ContractRecord, binding: OperationBinding,
                         *, approval_id: str | None) -> McpCallResponse:
        try:
            self._admit(request_id, payload.attempt_id, facts, record, approval_id=approval_id)
        except AuditStoreError:
            problem = McpDecision("block", "audit:admission_failed",
                                  "Sentinel could not durably record admission; nothing was performed.",
                                  ("audit:admission_failed",), "Ask the user to check Sentinel's audit store.")
            return self._blocked(request_id, payload, problem, coverage="unavailable")
        except FixtureError as exc:
            problem = McpDecision("block", exc.reason_code, "The operation is not in a state that can be admitted.",
                                  (exc.reason_code,), "Start a new attempt if the user still wants this action.")
            return self._blocked(request_id, payload, problem, coverage="mandatory")
        try:
            operation = self._fixture.apply(binding)
        except FixtureError as exc:
            problem = McpDecision("block", exc.reason_code, "The fixture refused the operation.",
                                  (exc.reason_code,), "Ask the user to inspect the fixture state.")
            return self._blocked(request_id, payload, problem, coverage="mandatory", operation_state="failed")
        self._write_effect(request_id, payload.attempt_id, facts, record, operation.state)
        return self._terminal(request_id, payload, decision, operation.state, operation.result, duplicate=False)

    def _request_or_report_approval(self, request_id: str, payload: McpCallRequest, decision: McpDecision,
                                    facts: McpActionFacts, record: ContractRecord,
                                    binding: OperationBinding) -> McpCallResponse:
        approval_binding = self._approval_binding(payload.attempt_id, facts, record)
        pending = self._approvals.request(approval_binding)
        envelope = self._coordinator.record(
            pending, attempt_id=payload.attempt_id, agent_id=ADAPTER_AGENT_ID, user_id=ADAPTER_USER_ID,
            raw_command=facts.describe(), cwd="/workspace", recent_actions=[], action=facts.action,
            workspace=self._supervision.workspace.display_name, reasons=list(decision.reason_codes),
            arguments=dict(payload.arguments),
        )
        return McpCallResponse(
            request_id=request_id, verdict="confirm_required", reason_code=decision.reason_code,
            reason=decision.reason, reason_codes=list(decision.reason_codes), guidance=decision.guidance,
            risk_score=VERDICT_RISK_SCORES["confirm_required"], risk_tier=VERDICT_TO_RISK_TIER["confirm_required"],
            attempt_id=payload.attempt_id, approval_id=envelope.approval_id, operation_state="prepared",
            coverage_status="mandatory",
        )

    def _terminal(self, request_id: str, payload: McpCallRequest, decision: McpDecision, state: str,
                  result: dict[str, Any] | None, *, duplicate: bool) -> McpCallResponse:
        if state == "succeeded":
            reason_code = "mcp:already_applied" if duplicate else decision.reason_code
            reason = "Terminal result replayed; no new effect." if duplicate else decision.reason
            verdict = "allow"
            if duplicate and result is not None:
                result = {**result, "note_added": False, "duplicate_suppressed": True}
        elif state == "failed":
            reason_code, reason, verdict = "mcp:attempt_failed", "This attempt was denied or failed; nothing more will happen.", "block"
        else:
            # Covers both `unknown` and an unreconciled `applying` state.
            reason_code, reason, verdict = "mcp:outcome_unknown", "The outcome is unknown and will not be retried automatically.", "block"
        return McpCallResponse(
            request_id=request_id, verdict=verdict, reason_code=reason_code, reason=reason,
            reason_codes=[reason_code], guidance="Start a new attempt if the user still wants this action.",
            risk_score=VERDICT_RISK_SCORES[verdict], risk_tier=VERDICT_TO_RISK_TIER[verdict],
            attempt_id=payload.attempt_id, operation_state=state,
            result=result if verdict == "allow" else None, coverage_status="mandatory",
        )

    def _blocked(self, request_id: str, payload: McpCallRequest, decision: McpDecision, *, coverage: str,
                 operation_state: str | None = None) -> McpCallResponse:
        return McpCallResponse(
            request_id=request_id, verdict="block", reason_code=decision.reason_code, reason=decision.reason,
            reason_codes=list(decision.reason_codes), guidance=decision.guidance,
            risk_score=VERDICT_RISK_SCORES["block"], risk_tier=VERDICT_TO_RISK_TIER["block"],
            attempt_id=payload.attempt_id, operation_state=operation_state,
            coverage_status=coverage,  # type: ignore[arg-type]
        )

    def _evaluate_response(self, request_id: str, verdict: str, reasons: list[str], message: str, *,
                           approval_id: str | None = None, extra_reasons: list[str] | None = None) -> EvaluateResponse:
        return EvaluateResponse(
            request_id=request_id, verdict=verdict,  # type: ignore[arg-type]
            risk_score=VERDICT_RISK_SCORES[verdict], risk_tier=VERDICT_TO_RISK_TIER[verdict],  # type: ignore[index]
            reasons=reasons + (extra_reasons or []), routing_path="approval", agent_message=message,
            approval_id=approval_id,
        )

    def _write_decision(self, request_id: str, payload: McpCallRequest, decision: McpDecision,
                        *, facts: McpActionFacts | None, record: ContractRecord | None) -> None:
        try:
            self._audit.write(
                AuditEvent(
                    event_type="decision", request_id=request_id, agent_id=ADAPTER_AGENT_ID,
                    session_id=self._supervision.session_id,
                    task_id=record.task_id if record else None,
                    contract_id=record.contract_id if record else None,
                    contract_version=record.version if record else None,
                    environment=self._environment,  # type: ignore[arg-type]
                    verdict=decision.verdict, reason_codes=list(decision.reason_codes) or [decision.reason_code],
                    details={"attempt_id": payload.attempt_id, "tool": payload.tool, "family": "mcp",
                             "targets": [facts.issue_id] if facts else [],
                             "payload_sha256": facts.action.payload_sha256 if facts else None},
                )
            )
        except AuditStoreError:
            pass  # Decision telemetry is optional; admission uses write_required.

    def _write_effect(self, request_id: str, attempt_id: str, facts: McpActionFacts,
                      record: ContractRecord, state: str) -> None:
        try:
            self._audit.write(
                AuditEvent(
                    event_type="post_execution", request_id=request_id, agent_id=ADAPTER_AGENT_ID,
                    session_id=self._supervision.session_id, task_id=record.task_id,
                    contract_id=record.contract_id, contract_version=record.version,
                    environment=self._environment,  # type: ignore[arg-type]
                    verdict="allow" if state == "succeeded" else "block",
                    reason_codes=[f"fixture:{state}"],
                    details={"attempt_id": attempt_id, "tool": facts.tool, "operation": facts.operation,
                             "targets": [facts.issue_id], "family": "mcp"},
                )
            )
        except AuditStoreError:
            pass
