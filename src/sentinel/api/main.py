"""FastAPI application for contract-aware shell authorization and execution."""

from __future__ import annotations

import os
import posixpath
import hashlib
import subprocess
import threading
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Iterator
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from sentinel import __version__
from sentinel.actions import (
    CanonicalAction,
    ShellCanonicalizationError,
    canonicalize_shell_action,
    fingerprint_action,
)
from sentinel.api.schemas import (
    ApiRequest,
    ContractEvaluateRequest,
    EvaluateRequest,
    EvaluateResponse,
    HealthResponse,
)
from sentinel.api.control_routes import (
    build_control_router,
    validate_control_transport,
)
from sentinel.api.control_schemas import (
    AcceptedContractDraft,
    ActiveAuthorityResponse,
    AgentConnectionResponse,
    AuditListResponse,
    CeilingStatusResponse,
    ContractActivationRequest,
    ContractActivationResponse,
    ContractDraftRequest,
    ContractDraftResponse,
    ControlCheckResponse,
    ControlRuntimeStatus,
    DraftQuestionResponse,
    DraftSuggestionResponse,
    FamilyCoverageResponse,
    IntegrationStatusResponse,
    PendingProposalResponse,
    ProposalAdjustResponse,
    ProposalConfirmRequest,
    ProposalConfirmResponse,
    ProposalDismissResponse,
    TaskProposalResponse,
)
from sentinel.approval import (
    ApprovalBinding,
    InMemoryApprovalService,
    PendingApproval,
)
from sentinel.authority import ContractAuthorityService
from sentinel.audit import (
    AuditEvent,
    AuditFallbackFullError,
    AuditHealth,
    AuditQuery,
    AuditStore,
    AuditStoreError,
    SQLiteAuditStore,
)
from sentinel.audit.redaction import redact
from sentinel.contracts import (
    ActionContract,
    ContractEnvironment,
    ContractRecord,
    ContractStoreError,
    InMemoryContractStore,
    InMemoryTrustedEventConsumer,
    SQLiteContractStore,
    TrustedEventError,
    TrustedPromptEnvelope,
)
from sentinel.control import (
    ApprovalCoordinatorError,
    ApprovalExecutionEnvelope,
    ControlConfig,
    DraftCompilationError,
    InMemoryApprovalCoordinator,
    PairingService,
    SQLiteWorkspaceBindingStore,
    WorkspaceBindingError,
    WorkspaceBindingStore,
    compile_task_prompt,
    review_workspace,
)
from sentinel.decision.contract_policy import (
    ContractMatchResult,
    match_action_to_contract,
)
from sentinel.decision.engine import (
    DecisionResult,
    RiskModelProtocol,
    VERDICT_RISK_SCORES,
    VERDICT_TO_RISK_TIER,
    evaluate_contract_request,
    evaluate_request,
)
from sentinel.decision.policy import PolicyProfile, load_policy_profile
from sentinel.execution import CommandExecutor, DockerExecutor, ExecutionResult
from sentinel.ml.inference import DEFAULT_ONNX_PATH, OnnxRiskModel
from sentinel.api.integration_routes import build_integration_router
from sentinel.api.integration_schemas import McpCallRequest, McpCallResponse
from sentinel.integrations import AdapterSessionError, AdapterSessionRegistry
from sentinel.integrations.hooks import inspect_hooks_profile
from sentinel.mcp import SQLiteIssueFixture
from sentinel.mcp.gateway import McpMediator
from sentinel.proposals import (
    InMemoryTaskProposalStore,
    ProposalStateError,
    TaskProposal,
    TaskProposalService,
)
from sentinel.supervision import (
    SQLiteSupervisionPolicyStore,
    SupervisionPolicy,
    SupervisionPolicyError,
    SupervisionPolicyStore,
)
from sentinel.session import (
    ExecutionAttempt,
    ExecutionAttemptBinding,
    ExecutionAttemptConflictError,
    InMemorySessionStore,
    SessionAction,
    SessionStore,
    SQLiteSessionStore,
)

MAX_REQUEST_BODY_BYTES = 64 * 1024


@dataclass(frozen=True)
class _ResolvedContractRequest:
    record: ContractRecord | None
    action: CanonicalAction | None
    match: ContractMatchResult | None
    environment: str
    context: str
    recent_actions: list[dict[str, Any]]
    canonicalization_error: str | None
    task_id: str | None

    def approval_binding(self, attempt_id: str | None) -> ApprovalBinding | None:
        if (
            self.record is None
            or self.match is None
            or not self.match.matches
            or self.task_id is None
        ):
            return None
        return ApprovalBinding(
            contract_id=self.record.contract_id,
            contract_version=self.record.version,
            authority_epoch=self.record.authority_epoch,
            action_fingerprint=self.match.action_fingerprint,
            environment=self.environment,
            session_id=self.record.session_id,
            task_id=self.task_id,
            attempt_id=attempt_id,
        )


class _InMemoryAuditStore:
    """Bounded default evidence store; full capacity fails closed."""

    def __init__(self, capacity: int = 10_000) -> None:
        self._capacity = capacity
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()

    @property
    def health(self) -> AuditHealth:
        with self._lock:
            full = len(self._events) >= self._capacity
            return AuditHealth(
                status="degraded" if full else "ok",
                detail="Default audit evidence capacity is full." if full else None,
                fallback_event_count=len(self._events),
                fallback_capacity=self._capacity,
            )

    def write(self, event: AuditEvent) -> None:
        with self._lock:
            if len(self._events) >= self._capacity:
                raise AuditFallbackFullError("default audit evidence capacity is full")
            self._events.append(AuditEvent(**redact(_model_to_dict(event))))

    def write_required(self, event: AuditEvent) -> None:
        del event
        raise AuditStoreError(
            "durable audit storage is required for real execution admission"
        )

    def query(
        self,
        filters: AuditQuery | None = None,
        **filter_values: object,
    ) -> list[AuditEvent]:
        selected = filters or AuditQuery(**filter_values)
        with self._lock:
            events = list(self._events)
        for field in (
            "event_type",
            "verdict",
            "environment",
            "agent_id",
            "session_id",
            "task_id",
            "contract_id",
        ):
            value = getattr(selected, field)
            if value is not None:
                events = [event for event in events if getattr(event, field) == value]
        if selected.start_time is not None:
            events = [
                event for event in events
                if event.timestamp >= selected.start_time
            ]
        if selected.end_time is not None:
            events = [
                event for event in events
                if event.timestamp <= selected.end_time
            ]
        return events[: selected.limit] if selected.limit is not None else events

    def export_jsonl(self, destination: object, filters: AuditQuery | None = None, **filter_values: object) -> int:
        raise NotImplementedError("use SQLiteAuditStore for JSONL export")


class _ExecutorCapabilityError(ValueError):
    """The canonical operation exceeds the injected executor's capabilities."""


class _SessionLockPool:
    """Bounded-lifetime per-session locks without an ever-growing key map."""

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._entries: dict[str, tuple[threading.RLock, int]] = {}

    @contextmanager
    def hold(self, session_id: str) -> Iterator[None]:
        with self._guard:
            lock, references = self._entries.get(
                session_id,
                (threading.RLock(), 0),
            )
            self._entries[session_id] = (lock, references + 1)
        lock.acquire()
        try:
            yield
        finally:
            lock.release()
            with self._guard:
                current_lock, current_references = self._entries[session_id]
                if current_references == 1:
                    del self._entries[session_id]
                else:
                    self._entries[session_id] = (
                        current_lock,
                        current_references - 1,
                    )


def create_app(
    *,
    model: RiskModelProtocol | None = None,
    load_model: bool = False,
    policy_profile: PolicyProfile | None = None,
    load_policy: bool = True,
    contract_store: InMemoryContractStore | SQLiteContractStore | None = None,
    session_store: SessionStore | None = None,
    approval_service: InMemoryApprovalService | None = None,
    audit_store: AuditStore | None = None,
    executor: CommandExecutor | None = None,
    execution_environment: ContractEnvironment = "sandbox",
    execution_environment_context: dict[str, str] | None = None,
    execution_cwd: str | None = None,
    confirmation_store: object | None = None,
    control_config: ControlConfig | None = None,
    control_binding_store: WorkspaceBindingStore | None = None,
    pairing_service: PairingService | None = None,
    supervision_policy: SupervisionPolicy | None = None,
    supervision_policy_store: SupervisionPolicyStore | None = None,
    mcp_fixture: SQLiteIssueFixture | None = None,
    adapter_registry: AdapterSessionRegistry | None = None,
) -> FastAPI:
    """Build an app with injectable stores and fail-closed empty defaults."""

    del confirmation_store  # Legacy injection is accepted but cannot authorize.
    if control_config is not None and (model is not None or load_model):
        raise ValueError("control mode requires ML loading to remain disabled")
    owned_stores: list[object] = []

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            for store in reversed(owned_stores):
                close = getattr(store, "close", None)
                if callable(close):
                    close()

    app = FastAPI(
        title="Sentinel Guardrail API",
        version=__version__,
        description="Local contract-aware enforcement API for AI-agent shell actions.",
        lifespan=lifespan,
    )

    @app.exception_handler(RequestValidationError)
    async def redact_request_validation(
        _: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "detail": [
                    {
                        "type": error.get("type", "validation_error"),
                        "loc": list(error.get("loc", ())),
                        "msg": "Invalid request field.",
                    }
                    for error in exc.errors()
                ]
            },
        )

    app.state.risk_model = model
    app.state.model_load_error = (
        None
        if model is not None or load_model
        else "Model loading is disabled."
    )
    app.state.policy_profile = policy_profile
    app.state.policy_load_error = None
    state_database = os.environ.get("SENTINEL_STATE_DB")
    app.state.contract_store = contract_store
    if app.state.contract_store is None:
        app.state.contract_store = (
            SQLiteContractStore(state_database)
            if state_database
            else InMemoryContractStore()
        )
        owned_stores.append(app.state.contract_store)
    app.state.session_store = session_store
    if app.state.session_store is None:
        app.state.session_store = (
            SQLiteSessionStore(state_database)
            if state_database
            else InMemorySessionStore()
        )
        owned_stores.append(app.state.session_store)
    app.state.approval_service = approval_service or InMemoryApprovalService()
    app.state.audit_store = audit_store
    if app.state.audit_store is None:
        app.state.audit_store = (
            SQLiteAuditStore(state_database)
            if state_database
            else _InMemoryAuditStore()
        )
        owned_stores.append(app.state.audit_store)
    app.state.authority_service = ContractAuthorityService(
        app.state.contract_store,
        app.state.audit_store,
    )
    app.state.approval_service.set_issue_observer(
        lambda token: _write_approval_issue_audit(app, token)
    )
    app.state.executor = executor or _default_executor()
    executor_cwd = getattr(app.state.executor, "container_workspace", None)
    configured_cwd = (
        execution_cwd
        if execution_cwd is not None
        else executor_cwd if executor_cwd is not None else "/workspace"
    )
    if not isinstance(configured_cwd, str) or not configured_cwd.startswith("/"):
        raise ValueError("execution_cwd must be an absolute container path")
    normalized_cwd = posixpath.normpath(configured_cwd)
    if execution_cwd is not None and executor_cwd is not None:
        if not isinstance(executor_cwd, str) or not executor_cwd.startswith("/"):
            raise ValueError(
                "executor container_workspace must be an absolute container path"
            )
        if normalized_cwd != posixpath.normpath(executor_cwd):
            raise ValueError(
                "execution_cwd must match the executor container_workspace"
            )
    if execution_environment not in {"sandbox", "dev", "staging", "production"}:
        raise ValueError("execution_environment is unsupported")
    app.state.execution_cwd = normalized_cwd
    app.state.execution_environment = execution_environment
    app.state.execution_environment_context = dict(
        execution_environment_context or {}
    )
    app.state.execution_limiter = threading.BoundedSemaphore(
        _max_concurrent_executions()
    )
    app.state.session_locks = _SessionLockPool()
    app.state.control_enabled = control_config is not None
    app.state.approval_coordinator = None
    app.state.supervision_policy_binding = None
    if control_config is None and (
        supervision_policy is not None or supervision_policy_store is not None
    ):
        raise SupervisionPolicyError("supervision:control_config_required")
    if control_config is not None:
        reviewed_workspace = review_workspace(control_config.workspace)
        executor_workspace = getattr(app.state.executor, "workspace", None)
        if executor_workspace is not None:
            try:
                resolved_executor_workspace = Path(executor_workspace).expanduser().resolve(
                    strict=True
                )
            except OSError as exc:
                raise WorkspaceBindingError(
                    "control:executor_workspace_unavailable"
                ) from exc
            if resolved_executor_workspace != reviewed_workspace.path:
                raise WorkspaceBindingError(
                    "control:executor_workspace_mismatch"
                )
        app.state.control_docker_ready = _control_executor_ready(
            app.state.executor
        )
        selected_binding_store = control_binding_store
        if selected_binding_store is None:
            if not state_database:
                raise WorkspaceBindingError(
                    "control:durable_state_database_required"
                )
            selected_binding_store = SQLiteWorkspaceBindingStore(state_database)
            owned_stores.append(selected_binding_store)
        supervision_binding = selected_binding_store.bind(reviewed_workspace)
        # The ceiling is bound beside the session so a restart with a weaker
        # ceiling against the same state database refuses to start.
        supervision_policy_binding = None
        if supervision_policy is not None:
            selected_policy_store = supervision_policy_store
            if selected_policy_store is None:
                if not state_database:
                    raise SupervisionPolicyError(
                        "supervision:durable_state_database_required"
                    )
                selected_policy_store = SQLiteSupervisionPolicyStore(state_database)
                owned_stores.append(selected_policy_store)
            supervision_policy_binding = selected_policy_store.bind(
                supervision_policy,
                supervision_binding,
            )
        elif supervision_policy_store is not None:
            raise SupervisionPolicyError("supervision:policy_required_for_store")
        app.state.supervision_policy_binding = supervision_policy_binding
        control_event_consumer = app.state.contract_store.set_trusted_event_consumer(
            InMemoryTrustedEventConsumer(
                host_id=f"sentinel-control:{reviewed_workspace.identity_sha256}",
                session_id=supervision_binding.session_id,
                channel="protected_local_ui",
            )
        )
        selected_pairing_service = pairing_service or PairingService(
            control_config.pairing_capability
        )
        approval_coordinator = InMemoryApprovalCoordinator(
            app.state.approval_service
        )
        app.state.control_binding_store = selected_binding_store
        app.state.supervision_binding = supervision_binding
        app.state.pairing_service = selected_pairing_service
        app.state.approval_coordinator = approval_coordinator
        app.state.control_event_consumer = control_event_consumer
        app.state.authority_service.set_authority_change_observer(
            lambda record: _invalidate_control_approvals_for_authority(
                app,
                record.session_id,
            )
        )
        app.state.mcp_mediator = None
        app.state.adapter_registry = None
        app.state.mcp_fixture = None
        app.state.task_proposals = None
        if supervision_policy_binding is not None:
            selected_fixture = mcp_fixture
            if selected_fixture is None:
                if not state_database:
                    raise SupervisionPolicyError(
                        "supervision:durable_state_database_required"
                    )
                selected_fixture = SQLiteIssueFixture(
                    Path(state_database).with_name("mcp_fixture.sqlite3")
                )
                owned_stores.append(selected_fixture)
            selected_registry = adapter_registry or AdapterSessionRegistry(
                supervision_session_id=supervision_binding.session_id,
            )
            # Proposals are process-local like adapter sessions and pending
            # approvals; a restart clears them and the agent proposes again.
            task_proposals = TaskProposalService(
                store=InMemoryTaskProposalStore(),
                policy_binding=supervision_policy_binding,
                supervision=supervision_binding,
                audit_store=app.state.audit_store,
                environment=app.state.execution_environment,
            )
            mediator = McpMediator(
                registry=selected_registry,
                fixture=selected_fixture,
                policy_binding=supervision_policy_binding,
                supervision=supervision_binding,
                contract_store=app.state.contract_store,
                authority_service=app.state.authority_service,
                approval_service=app.state.approval_service,
                approval_coordinator=approval_coordinator,
                audit_store=app.state.audit_store,
                environment=app.state.execution_environment,
                lock=app.state.session_locks.hold,
                proposals=task_proposals,
            )
            app.state.mcp_mediator = mediator
            app.state.adapter_registry = selected_registry
            app.state.mcp_fixture = selected_fixture
            app.state.task_proposals = task_proposals
            app.include_router(
                build_integration_router(
                    config=control_config,
                    mediate=lambda bearer, payload: _mediate_mcp_call(
                        app,
                        bearer,
                        payload,
                    ),
                )
            )

        app.add_middleware(
            CORSMiddleware,
            allow_origins=[control_config.ui_origin],
            allow_credentials=True,
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type"],
        )

        @app.middleware("http")
        async def protect_control_transport(
            request: Request,
            call_next: Any,
        ) -> Any:
            if request.url.path == "/control" or request.url.path.startswith(
                "/control/"
            ):
                try:
                    validate_control_transport(request, control_config)
                except HTTPException as exc:
                    return JSONResponse(
                        status_code=exc.status_code,
                        content={"detail": exc.detail},
                    )
            response = await call_next(request)
            if request.url.path == "/control" or request.url.path.startswith(
                "/control/"
            ):
                response.headers["Cache-Control"] = "no-store"
            return response

        app.include_router(
            build_control_router(
                config=control_config,
                pairing=selected_pairing_service,
                binding=supervision_binding,
                approvals=approval_coordinator,
                retry_approval=lambda envelope, token: _retry_control_approval(
                    app,
                    envelope,
                    token,
                ),
                denial_observer=lambda pending: _observe_control_denial(
                    app,
                    pending,
                ),
                draft_contract=lambda payload: _draft_control_contract(
                    app,
                    payload,
                ),
                activate_contract=lambda payload: _activate_control_contract(
                    app,
                    payload,
                ),
                active_authority=lambda: _control_active_authority(app),
                approval_is_current=lambda envelope: _control_approval_is_current(
                    app,
                    envelope,
                ),
                query_audit=lambda **filters: _query_control_audit(
                    app,
                    **filters,
                ),
                runtime_status=lambda: _control_runtime_status(
                    app,
                    control_config,
                ),
                integration_status=lambda: _control_integration_status(app),
                pending_proposal=lambda: _control_pending_proposal(app),
                confirm_proposal=lambda draft_id, payload: _confirm_task_proposal(
                    app,
                    draft_id,
                    payload,
                ),
                dismiss_proposal=lambda draft_id: _dismiss_task_proposal(
                    app,
                    draft_id,
                ),
                adjust_proposal=lambda draft_id: _adjust_task_proposal(
                    app,
                    draft_id,
                ),
            )
        )

    if app.state.risk_model is None and load_model:
        try:
            app.state.risk_model = OnnxRiskModel()
        except Exception as exc:
            app.state.model_load_error = str(exc)
    if app.state.policy_profile is None and load_policy:
        try:
            app.state.policy_profile = load_policy_profile()
        except Exception as exc:
            app.state.policy_load_error = str(exc)

    @app.middleware("http")
    async def reject_oversized_bodies(request: Request, call_next: Any) -> Any:
        raw_length = request.headers.get("content-length")
        if raw_length:
            try:
                if int(raw_length) > MAX_REQUEST_BODY_BYTES:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Request body exceeds 65536 bytes."},
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length header."},
                )
        original_receive = request._receive
        received = 0
        too_large = False

        async def limited_receive() -> dict[str, Any]:
            nonlocal received, too_large
            message = await original_receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > MAX_REQUEST_BODY_BYTES:
                    too_large = True
                    return {
                        "type": "http.request",
                        "body": b"",
                        "more_body": False,
                    }
            return message

        request._receive = limited_receive
        response = await call_next(request)
        if too_large:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body exceeds 65536 bytes."},
            )
        return response

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        model_loaded = app.state.risk_model is not None
        policy_loaded = app.state.policy_profile is not None
        audit_health = _audit_health(app.state.audit_store)
        details = [
            detail
            for detail in (
                None if model_loaded else app.state.model_load_error or "Model is not loaded.",
                None if policy_loaded else app.state.policy_load_error or "Policy is not loaded.",
                audit_health.detail if audit_health.status == "degraded" else None,
            )
            if detail
        ]
        healthy = model_loaded and policy_loaded and audit_health.status == "ok"
        return HealthResponse(
            status="ok" if healthy else "degraded",
            model_loaded=model_loaded,
            policy_loaded=policy_loaded,
            audit_status=audit_health.status,
            model_path=str(DEFAULT_ONNX_PATH),
            model_detail=None if model_loaded else app.state.model_load_error or "Model is not loaded.",
            policy_detail=None if policy_loaded else app.state.policy_load_error or "Policy is not loaded.",
            audit_detail=audit_health.detail,
            detail="; ".join(details) if details else None,
        )

    @app.post("/evaluate", response_model=EvaluateResponse)
    def evaluate(payload: ApiRequest) -> EvaluateResponse:
        if isinstance(payload, ContractEvaluateRequest):
            return _handle_contract(payload, app, execute=False)
        return _handle_legacy(payload, app, execute=False)

    @app.post("/execute", response_model=EvaluateResponse)
    def execute(payload: ApiRequest) -> EvaluateResponse:
        if isinstance(payload, ContractEvaluateRequest):
            return _handle_contract(payload, app, execute=True)
        return _handle_legacy(payload, app, execute=True)

    return app


def _handle_contract(
    payload: ContractEvaluateRequest,
    app: FastAPI,
    *,
    execute: bool,
) -> EvaluateResponse:
    if execute:
        if payload.attempt_id is None:
            raise HTTPException(
                status_code=400,
                detail="attempt_id is required for contract-aware execution.",
            )
        return _handle_contract_execution(payload, app)

    request_id = str(uuid4())
    resolved = _resolve_contract_request(payload, app)
    _write_pre_decision_audit(
        app,
        payload,
        request_id,
        resolved,
        execute_requested=False,
    )
    decision = evaluate_contract_request(
        context=resolved.context,
        command=payload.action.raw_command,
        environment=resolved.environment,
        recent_actions=resolved.recent_actions,
        contract_match=resolved.match,
        action_operation=resolved.action.operation if resolved.action is not None else None,
        canonicalization_error=resolved.canonicalization_error,
        model=app.state.risk_model,
        policy_profile=app.state.policy_profile,
        policy_available=app.state.policy_profile is not None,
        request_id_factory=lambda: request_id,
    )

    binding = resolved.approval_binding(payload.attempt_id)
    if (
        decision.verdict == "confirm_required"
        and binding is not None
        and not app.state.control_enabled
    ):
        pending = _request_approval(app, binding)
        decision = _replace_decision(
            decision,
            reasons=[*decision.reasons, "approval:pending"],
            approval_id=pending.approval_id,
        )

    _write_decision_audit(
        app,
        payload,
        decision,
        resolved,
        execute_requested=False,
    )
    return response_from_decision(decision)


def _handle_contract_execution(
    payload: ContractEvaluateRequest,
    app: FastAPI,
) -> EvaluateResponse:
    assert payload.attempt_id is not None
    with app.state.session_locks.hold(payload.session_id):
        request_id = str(uuid4())
        resolved = _resolve_contract_request(payload, app)
        existing = _existing_attempt_for_payload(payload, resolved, app)
        if existing is not None:
            return _response_for_existing_attempt(existing)
        _write_optional_execution_telemetry(
            _write_pre_decision_audit,
            app,
            payload,
            request_id,
            resolved,
            execute_requested=True,
        )
        decision = evaluate_contract_request(
            context=resolved.context,
            command=payload.action.raw_command,
            environment=resolved.environment,
            recent_actions=resolved.recent_actions,
            contract_match=resolved.match,
            action_operation=(
                resolved.action.operation if resolved.action is not None else None
            ),
            canonicalization_error=resolved.canonicalization_error,
            model=app.state.risk_model,
            policy_profile=app.state.policy_profile,
            policy_available=app.state.policy_profile is not None,
            request_id_factory=lambda: request_id,
        )
        binding = resolved.approval_binding(payload.attempt_id)
        approval_candidate = (
            decision.verdict == "confirm_required"
            and binding is not None
            and payload.approval_token is not None
        )
        if decision.verdict == "confirm_required" and binding is not None:
            if not approval_candidate:
                pending = _request_approval(app, binding)
                decision = _replace_decision(
                    decision,
                    reasons=[*decision.reasons, "approval:pending"],
                    approval_id=pending.approval_id,
                )
                _record_control_approval(
                    app,
                    pending,
                    payload,
                    resolved,
                    decision,
                )
        _write_optional_execution_telemetry(
            _write_decision_audit,
            app,
            payload,
            decision,
            resolved,
            execute_requested=True,
        )
        if decision.verdict != "allow" and not approval_candidate:
            return response_from_decision(decision)
        if (
            binding is None
            or resolved.record is None
            or resolved.action is None
            or resolved.task_id is None
        ):
            return response_from_decision(
                _execution_admission_block(
                    app,
                    payload,
                    resolved,
                    request_id,
                    "contract:execution_recheck_failed",
                )
            )

        attempt_binding = ExecutionAttemptBinding(
            attempt_id=payload.attempt_id,
            session_id=payload.session_id,
            task_id=resolved.task_id,
            contract_id=resolved.record.contract_id,
            contract_version=resolved.record.version,
            authority_epoch=resolved.record.authority_epoch,
            action_fingerprint=binding.action_fingerprint,
            environment=resolved.environment,
        )
        try:
            _validate_execution_action(app, resolved.action)
        except _ExecutorCapabilityError:
            return response_from_decision(
                _execution_admission_block(
                    app,
                    payload,
                    resolved,
                    request_id,
                    "execution:unsupported_executor_capability",
                )
            )
        except ValueError:
            return response_from_decision(
                _execution_admission_block(
                    app,
                    payload,
                    resolved,
                    request_id,
                    "execution:unsafe_workspace_target",
                )
            )
        if not app.state.execution_limiter.acquire(blocking=False):
            raise HTTPException(
                status_code=429,
                detail="Too many concurrent sandbox executions; retry shortly.",
            )
        try:
            return _admit_run_and_persist(
                app,
                payload,
                decision,
                resolved,
                attempt_binding=attempt_binding,
                approval_candidate=approval_candidate,
            )
        finally:
            app.state.execution_limiter.release()


def _admit_run_and_persist(
    app: FastAPI,
    payload: ContractEvaluateRequest,
    decision: DecisionResult,
    resolved: _ResolvedContractRequest,
    *,
    attempt_binding: ExecutionAttemptBinding,
    approval_candidate: bool,
) -> EvaluateResponse:
    record = resolved.record
    action = resolved.action
    assert record is not None
    assert action is not None
    try:
        with app.state.contract_store.execution_guard(
            record.contract_id,
            expected_version=record.version,
            expected_authority_epoch=record.authority_epoch,
            session_id=payload.session_id,
        ):
            try:
                if approval_candidate:
                    assert payload.approval_token is not None
                    approved = _approved_decision(decision)
                    binding = resolved.approval_binding(payload.attempt_id)
                    assert binding is not None
                    consumed = app.state.approval_service.consume(
                        payload.approval_token,
                        binding,
                        consume_observer=lambda token: _reserve_and_record_admission(
                            app,
                            payload,
                            approved,
                            resolved,
                            attempt_binding,
                            approval_id=token.approval_id,
                        ),
                    )
                    if not consumed:
                        rejected = _replace_decision(
                            decision,
                            reasons=[
                                *decision.reasons,
                                "approval:token_invalid_or_mismatch",
                            ],
                        )
                        pending = _request_approval(app, binding)
                        rejected = _replace_decision(
                            rejected,
                            reasons=[*rejected.reasons, "approval:pending"],
                            approval_id=pending.approval_id,
                        )
                        _write_optional_execution_telemetry(
                            _write_decision_audit,
                            app,
                            payload,
                            rejected,
                            resolved,
                            execute_requested=True,
                        )
                        return response_from_decision(rejected)
                    decision = approved
                else:
                    _reserve_and_record_admission(
                        app,
                        payload,
                        decision,
                        resolved,
                        attempt_binding,
                    )
            except ExecutionAttemptConflictError as exc:
                existing = app.state.session_store.get_attempt(
                    attempt_binding.attempt_id
                )
                if existing is not None and existing.binding == attempt_binding:
                    return _response_for_existing_attempt(existing)
                raise _attempt_binding_conflict() from exc

        # Admission is already durable and at-most-once before the executor
        # starts. Authority changes after this point do not cancel this attempt.
        execution = _run_executor(
            app,
            command=action.canonical_command or payload.action.raw_command,
            shell_type="unknown",
            slot_acquired=True,
        )
        completed = _replace_decision(
            decision,
            reasons=[*decision.reasons, "execution:sandbox_attempted"],
            execution=execution,
        )
        response = response_from_decision(completed)
        response_payload = _model_to_json_dict(response)
        terminal_state = "failed" if execution.error is not None else "completed"
        try:
            app.state.session_store.transition_attempt(
                attempt_binding.attempt_id,
                expected_state="running",
                new_state=terminal_state,
                response_payload=response_payload,
            )
        except Exception as exc:
            _mark_attempt_unknown(app, attempt_binding.attempt_id)
            raise HTTPException(
                status_code=409,
                detail=(
                    "The executor returned, but its response could not be "
                    "persisted. The attempt will not run again; manual "
                    "inspection is required."
                ),
            ) from exc
    except ContractStoreError:
        stale = _resolve_contract_request(payload, app)
        return response_from_decision(
            _execution_admission_block(
                app,
                payload,
                stale,
                decision.request_id,
                "contract:execution_admission_stale",
            )
        )
    try:
        _write_post_execution_audit(app, payload, completed, resolved)
    except HTTPException:
        pass
    return response


def _reserve_and_record_admission(
    app: FastAPI,
    payload: ContractEvaluateRequest,
    decision: DecisionResult,
    resolved: _ResolvedContractRequest,
    binding: ExecutionAttemptBinding,
    *,
    approval_id: str | None = None,
) -> None:
    attempt = app.state.session_store.reserve_attempt(binding)
    if attempt.state != "reserved":
        raise ExecutionAttemptConflictError("attempt:state_conflict")
    try:
        app.state.session_store.transition_attempt(
            binding.attempt_id,
            expected_state="reserved",
            new_state="running",
        )
        _write_execution_admitted_audit(
            app,
            payload,
            decision,
            resolved,
            approval_id=approval_id,
        )
        _append_admitted_session_action(app, payload, resolved)
    except Exception:
        _mark_attempt_unknown(app, binding.attempt_id)
        raise


def _mark_attempt_unknown(app: FastAPI, attempt_id: str) -> None:
    attempt = app.state.session_store.get_attempt(attempt_id)
    if attempt is None or attempt.state not in {"reserved", "running"}:
        return
    try:
        app.state.session_store.transition_attempt(
            attempt_id,
            expected_state=attempt.state,
            new_state="unknown",
        )
    except Exception:
        pass


def _response_for_existing_attempt(attempt: ExecutionAttempt) -> EvaluateResponse:
    if attempt.state in {"completed", "failed"}:
        assert attempt.response_payload is not None
        return EvaluateResponse(**attempt.response_payload)
    state_detail = {
        "reserved": "is reserved and may already be admitted",
        "running": "is already running",
        "unknown": "has an unknown outcome and requires manual inspection",
    }[attempt.state]
    raise HTTPException(
        status_code=409,
        detail=(
            f"This attempt {state_detail}. Sentinel will not retry it "
            "automatically."
        ),
    )


def _existing_attempt_for_payload(
    payload: ContractEvaluateRequest,
    resolved: _ResolvedContractRequest,
    app: FastAPI,
) -> ExecutionAttempt | None:
    assert payload.attempt_id is not None
    attempt = app.state.session_store.get_attempt(payload.attempt_id)
    if attempt is None:
        return None
    binding = attempt.binding
    same_caller_binding = (
        binding.session_id == payload.session_id
        and binding.contract_id == payload.contract_id
        and binding.contract_version == payload.version
        and binding.environment == resolved.environment
        and resolved.action is not None
        and binding.action_fingerprint == fingerprint_action(resolved.action)
    )
    if not same_caller_binding:
        raise _attempt_binding_conflict()
    return attempt


def _attempt_binding_conflict() -> HTTPException:
    return HTTPException(
        status_code=409,
        detail=(
            "attempt_id was already used with a different execution binding; "
            "the executor was not invoked."
        ),
    )


def _execution_admission_block(
    app: FastAPI,
    payload: ContractEvaluateRequest,
    resolved: _ResolvedContractRequest,
    request_id: str,
    reason_code: str,
) -> DecisionResult:
    blocked = evaluate_contract_request(
        context=resolved.context,
        command=payload.action.raw_command,
        environment=resolved.environment,
        recent_actions=resolved.recent_actions,
        contract_match=resolved.match,
        action_operation=(
            resolved.action.operation if resolved.action is not None else None
        ),
        canonicalization_error=reason_code,
        model=app.state.risk_model,
        policy_profile=app.state.policy_profile,
        policy_available=app.state.policy_profile is not None,
        request_id_factory=lambda: request_id,
    )
    _write_decision_audit(
        app,
        payload,
        blocked,
        resolved,
        execute_requested=True,
    )
    return blocked


def _handle_legacy(
    payload: EvaluateRequest,
    app: FastAPI,
    *,
    execute: bool,
) -> EvaluateResponse:
    request_id = str(uuid4())
    _write_legacy_pre_audit(app, payload, request_id)
    decision = evaluate_request(
        context=payload.context,
        command=payload.command,
        environment=payload.environment,
        shell_type=payload.shell_type,
        recent_actions=[_model_to_dict(action) for action in payload.recent_actions],
        model=app.state.risk_model,
        policy_profile=app.state.policy_profile,
        request_id_factory=lambda: request_id,
    )
    decision = _restrict_legacy_decision(decision)
    _write_legacy_decision_audit(app, payload, decision, execute_requested=execute)
    if not execute or decision.verdict != "allow":
        return response_from_decision(decision)
    execution = _run_executor(
        app,
        command=payload.command,
        shell_type=payload.shell_type,
    )
    completed = _replace_decision(
        decision,
        reasons=[*decision.reasons, "execution:sandbox_attempted"],
        execution=execution,
    )
    _write_legacy_post_audit(app, payload, completed)
    return response_from_decision(completed)


def _resolve_contract_request(
    payload: ContractEvaluateRequest,
    app: FastAPI,
) -> _ResolvedContractRequest:
    authority_available = app.state.authority_service.authority_available
    record = (
        app.state.contract_store.get_active(payload.session_id)
        if authority_available
        else None
    )
    environment = app.state.execution_environment
    context = record.contract.objective if record else "No active contract."
    recent = [
        _session_action_to_history(action)
        for action in app.state.session_store.get_recent_actions(payload.session_id)
    ]
    action: CanonicalAction | None = None
    canonicalization_error: str | None = (
        None
        if authority_available
        else "authority:audit_compensation_unverified"
    )
    requested_cwd = posixpath.normpath(payload.action.cwd)
    if authority_available:
        if requested_cwd != app.state.execution_cwd:
            canonicalization_error = "action:untrusted_working_directory"
        else:
            try:
                action = canonicalize_shell_action(
                    payload.action.raw_command,
                    environment=environment,
                    cwd=app.state.execution_cwd,
                    environment_context=app.state.execution_environment_context,
                )
            except ShellCanonicalizationError as exc:
                canonicalization_error = exc.reason_code

    match: ContractMatchResult | None = None
    if record is not None and action is not None:
        match = match_action_to_contract(
            record,
            action,
            expected_contract_id=payload.contract_id,
            expected_version=payload.version,
            session_id=payload.session_id,
            active_task_id=record.task_id,
        )
    return _ResolvedContractRequest(
        record=record,
        action=action,
        match=match,
        environment=environment,
        context=context,
        recent_actions=recent,
        canonicalization_error=canonicalization_error,
        task_id=record.task_id if record else None,
    )


def _restrict_legacy_decision(decision: DecisionResult) -> DecisionResult:
    if decision.verdict == "block":
        return decision
    return _replace_decision(
        decision,
        verdict="confirm_required",
        reasons=[*decision.reasons, "legacy:non_authorizing_request"],
        routing_path="policy",
        agent_message=(
            "Legacy requests cannot carry approval authority. Use an active "
            "contract request for this action."
        ),
        execution=None,
    )


def _approved_decision(decision: DecisionResult) -> DecisionResult:
    return _replace_decision(
        decision,
        verdict="allow",
        reasons=[*decision.reasons, "approval:token_valid"],
        routing_path="approval",
        agent_message="Sentinel allows this exact action under a protected one-use approval.",
        suggested_safe_actions=[],
        approval_id=None,
    )


def _run_executor(
    app: FastAPI,
    *,
    command: str,
    shell_type: str,
    slot_acquired: bool = False,
) -> ExecutionResult:
    if not slot_acquired and not app.state.execution_limiter.acquire(blocking=False):
        raise HTTPException(
            status_code=429,
            detail="Too many concurrent sandbox executions; retry shortly.",
        )
    try:
        try:
            return app.state.executor.run(command=command, shell_type=shell_type)
        except Exception as exc:
            return ExecutionResult(
                stdout="",
                stderr="",
                exit_code=None,
                timed_out=False,
                duration_ms=0,
                error=f"Executor failed: {type(exc).__name__}",
            )
    finally:
        if not slot_acquired:
            app.state.execution_limiter.release()


def _validate_execution_action(app: FastAPI, action: CanonicalAction) -> None:
    validators = {
        name: getattr(app.state.executor, name, None)
        for name in (
            "validate_configuration",
            "validate_operation",
            "validate_targets",
            "run",
        )
    }
    missing = [
        name
        for name, validator in validators.items()
        if not callable(validator)
    ]
    if missing:
        raise _ExecutorCapabilityError(
            "executor is missing required methods: "
            + ", ".join(sorted(missing))
        )
    validators["validate_configuration"]()
    operation_validator = getattr(app.state.executor, "validate_operation", None)
    try:
        operation_validator(action.operation)
    except ValueError as exc:
        raise _ExecutorCapabilityError(str(exc)) from exc
    validators["validate_targets"](action.targets)
    action_validator = getattr(app.state.executor, "validate_action", None)
    if callable(action_validator):
        action_validator(action)


def _request_approval(
    app: FastAPI,
    binding: ApprovalBinding,
) -> Any:
    try:
        return app.state.approval_service.request(binding)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Approval queue is unavailable; request failed closed.",
        ) from exc


def _record_control_approval(
    app: FastAPI,
    pending: PendingApproval,
    payload: ContractEvaluateRequest,
    resolved: _ResolvedContractRequest,
    decision: DecisionResult,
) -> None:
    coordinator = app.state.approval_coordinator
    supervision = getattr(app.state, "supervision_binding", None)
    if (
        coordinator is None
        or supervision is None
        or payload.session_id != supervision.session_id
        or payload.attempt_id is None
        or resolved.action is None
    ):
        return
    try:
        coordinator.record(
            pending,
            attempt_id=payload.attempt_id,
            agent_id=payload.agent_id,
            user_id=payload.user_id,
            raw_command=payload.action.raw_command,
            cwd=payload.action.cwd,
            recent_actions=[
                _model_to_dict(action)
                for action in payload.recent_actions
            ],
            action=resolved.action,
            workspace=str(supervision.workspace.path),
            reasons=decision.reasons,
        )
    except ApprovalCoordinatorError as exc:
        raise HTTPException(
            status_code=503,
            detail="Approval request could not be retained; request failed closed.",
        ) from exc


def _retry_control_approval(
    app: FastAPI,
    envelope: ApprovalExecutionEnvelope,
    approval_token: str,
) -> EvaluateResponse:
    supervision = app.state.supervision_binding
    if envelope.binding.session_id != supervision.session_id:
        raise HTTPException(
            status_code=409,
            detail="Approval session no longer matches the supervised workspace.",
        )
    if envelope.family == "mcp":
        mediator = app.state.mcp_mediator
        if mediator is None:
            raise HTTPException(
                status_code=409,
                detail="MCP mediation is not available in this process.",
            )
        return mediator.retry_approved(envelope, approval_token)
    payload = ContractEvaluateRequest(
        contract_id=envelope.binding.contract_id,
        version=envelope.binding.contract_version,
        attempt_id=envelope.attempt_id,
        session_id=envelope.binding.session_id,
        agent_id=envelope.agent_id,
        user_id=envelope.user_id,
        action={
            "family": "shell",
            "raw_command": envelope.raw_command,
            "cwd": envelope.cwd,
        },
        approval_token=approval_token,
        recent_actions=envelope.recent_actions(),
    )
    return _handle_contract_execution(payload, app)


def _mediate_mcp_call(
    app: FastAPI,
    bearer: str | None,
    payload: McpCallRequest,
) -> McpCallResponse:
    try:
        return app.state.mcp_mediator.mediate(bearer, payload)
    except AdapterSessionError as exc:
        raise HTTPException(
            status_code=401,
            detail={"reason_code": exc.reason_code, "verdict": "block"},
        ) from exc


def _observe_control_denial(app: FastAPI, pending: PendingApproval) -> None:
    """Record the denial durably first; only then close any MCP fixture attempt."""

    _write_approval_denial_audit(app, pending)
    mediator = app.state.mcp_mediator
    if mediator is not None:
        mediator.abandon_denied(pending.binding.attempt_id)


def _control_approval_is_current(
    app: FastAPI,
    envelope: ApprovalExecutionEnvelope,
) -> bool:
    if not app.state.authority_service.authority_available:
        return False
    binding = envelope.binding
    active = app.state.contract_store.get_active(binding.session_id)
    return _approval_binding_matches_active(binding, active)


def _approval_binding_matches_active(
    binding: ApprovalBinding,
    active: ContractRecord | None,
) -> bool:
    return bool(
        active is not None
        and active.task_id == binding.task_id
        and active.contract_id == binding.contract_id
        and active.version == binding.contract_version
        and active.authority_epoch == binding.authority_epoch
        and active.contract.environment == binding.environment
    )


def _invalidate_control_approvals_for_authority(
    app: FastAPI,
    session_id: str,
) -> None:
    coordinator = app.state.approval_coordinator
    if coordinator is None:
        return
    active = (
        app.state.contract_store.get_active(session_id)
        if app.state.authority_service.authority_available
        else None
    )
    coordinator.invalidate_where(
        lambda binding: binding.session_id == session_id
        and not _approval_binding_matches_active(binding, active)
    )


def _draft_control_contract(
    app: FastAPI,
    payload: ContractDraftRequest,
) -> ContractDraftResponse:
    try:
        preview = compile_task_prompt(payload.raw_prompt)
    except DraftCompilationError as exc:
        raise HTTPException(
            status_code=422,
            detail="Task prompt could not be compiled.",
        ) from exc
    proposed = None
    if payload.accepted_contract is not None:
        contract = _accepted_control_contract(
            app,
            payload.accepted_contract,
            prompt_sha256=preview.prompt_sha256,
        )
        try:
            proposed = app.state.authority_service.create_proposed(
                contract,
                session_id=app.state.supervision_binding.session_id,
                authorization_source="protected_local_ui",
                created_at=datetime.now(timezone.utc),
                preflight_status="complete",
            )
        except (ContractStoreError, AuditStoreError) as exc:
            raise HTTPException(
                status_code=409,
                detail="Proposed contract could not be created.",
            ) from exc
    return ContractDraftResponse(
        prompt_sha256=preview.prompt_sha256,
        suggestions=[
            DraftSuggestionResponse(
                field=suggestion.field,
                value=suggestion.value,
                source=suggestion.source,
            )
            for suggestion in preview.suggestions
        ],
        questions=[
            DraftQuestionResponse(
                question_id=question.question_id,
                field=question.field,
                prompt=question.prompt,
            )
            for question in (
                ()
                if payload.accepted_contract is not None
                else preview.questions
            )
        ],
        proposed_contract=proposed,
    )


def _accepted_control_contract(
    app: FastAPI,
    accepted: AcceptedContractDraft,
    *,
    prompt_sha256: str,
) -> ActionContract:
    if accepted.environment != app.state.execution_environment:
        raise HTTPException(
            status_code=409,
            detail="Contract environment must match the fixed server environment.",
        )
    if accepted.tool_family == "sentinel_issue_fixture":
        return _accepted_fixture_contract(app, accepted, prompt_sha256=prompt_sha256)
    targets: list[str] = []
    for target in accepted.exact_targets:
        normalized = posixpath.normpath(target)
        if (
            not target.startswith("/")
            or normalized != target
            or (
                normalized != app.state.execution_cwd
                and not normalized.startswith(app.state.execution_cwd.rstrip("/") + "/")
            )
        ):
            raise HTTPException(
                status_code=422,
                detail="Every target must be an exact path in the fixed workspace.",
            )
        targets.append(normalized)
    if accepted.operation not in accepted.allowed_effects:
        raise HTTPException(
            status_code=422,
            detail="Allowed effects must include the selected operation.",
        )
    if accepted.operation in accepted.forbidden_operations:
        raise HTTPException(
            status_code=422,
            detail="The selected operation cannot also be forbidden.",
        )
    target_summary = ", ".join(targets)
    objective = f"{accepted.operation.capitalize()} exactly {target_summary}."
    return ActionContract(
        objective=objective[:2_000],
        allowed_operations={accepted.operation},
        allowed_tools={"shell"},
        exact_targets=targets,
        environment=accepted.environment,
        maximum_scope="exact",
        expected_side_effects=accepted.expected_side_effects,
        allowed_effects=accepted.allowed_effects,
        forbidden_operations=accepted.forbidden_operations,
        forbidden_effects=accepted.forbidden_effects,
        forbidden_effect_codes=accepted.forbidden_effect_codes,
        rollback_plan=accepted.rollback_plan,
        dry_run_required=accepted.dry_run_required,
        rollback_required=accepted.rollback_required,
        transaction_required=accepted.transaction_required,
        backup_required=accepted.backup_required,
        source_prompt_sha256=prompt_sha256,
        authorization_reference=f"control-draft:{uuid4()}",
        expires_at=(
            datetime.now(timezone.utc)
            + timedelta(minutes=accepted.expires_in_minutes)
        ),
    )


def _accepted_fixture_contract(
    app: FastAPI,
    accepted: AcceptedContractDraft,
    *,
    prompt_sha256: str,
    authorization_reference: str | None = None,
) -> ActionContract:
    """A task over the MCP issue fixture. Targets are issue IDs the ceiling permits.

    The ceiling stays the outer bound: a task can only name issues that match
    the startup policy pattern, and only the read/write operations the fixture
    tools express. Reads are always included because a note-writing task is
    useless without them and reads are ordinary under the ceiling.

    Both the manual form and the Week 13 proposal confirmation build through
    this function, so there is exactly one place fixture authority is shaped.
    """

    policy_binding = app.state.supervision_policy_binding
    if policy_binding is None:
        raise HTTPException(
            status_code=409,
            detail="No fixture ceiling is bound in this Sentinel process.",
        )
    if accepted.operation not in {"read", "write"}:
        raise HTTPException(
            status_code=422,
            detail="Fixture tasks support only read or write.",
        )
    targets: list[str] = []
    for target in accepted.exact_targets:
        if not policy_binding.policy.issue_in_scope(target):
            raise HTTPException(
                status_code=422,
                detail="Every target must be a fixture issue ID the startup ceiling permits.",
            )
        targets.append(target)
    if accepted.operation in accepted.forbidden_operations:
        raise HTTPException(
            status_code=422,
            detail="The selected operation cannot also be forbidden.",
        )
    if accepted.operation not in accepted.allowed_effects:
        raise HTTPException(
            status_code=422,
            detail="Allowed effects must include the selected operation.",
        )
    operations: set[str] = {"read"} | {accepted.operation}
    tools = {"sentinel_issue_read"}
    if accepted.operation == "write":
        tools.add("sentinel_issue_add_note")
    unsatisfiable = [
        label
        for flag, label in (
            (accepted.dry_run_required, "a dry run"),
            (accepted.rollback_required, "automatic rollback"),
            (accepted.transaction_required, "a transaction"),
            (accepted.backup_required, "a backup"),
        )
        if flag
    ]
    if unsatisfiable:
        # The fixture tools cannot satisfy these shell-style safeguard
        # obligations. Accepting them would make every real call fail closed
        # (found in the live run for dry_run_required; siblings caught in review).
        raise HTTPException(
            status_code=422,
            detail=(
                f"Fixture tasks cannot require {', '.join(unsatisfiable)}; "
                "the fixture tools do not support these safeguards."
            ),
        )
    verb = "Add notes to" if accepted.operation == "write" else "Read"
    objective = f"{verb} fixture issues {', '.join(targets)} through the Sentinel MCP tools."
    return ActionContract(
        objective=objective[:2_000],
        allowed_operations=operations,  # type: ignore[arg-type]
        allowed_tools=tools,
        exact_targets=targets,
        environment=accepted.environment,
        maximum_scope="exact",
        expected_side_effects=accepted.expected_side_effects,
        allowed_effects=set(accepted.allowed_effects) | {"read"},
        forbidden_operations=accepted.forbidden_operations,
        forbidden_effects=accepted.forbidden_effects,
        forbidden_effect_codes=accepted.forbidden_effect_codes,
        rollback_plan=accepted.rollback_plan,
        dry_run_required=accepted.dry_run_required,
        rollback_required=accepted.rollback_required,
        transaction_required=accepted.transaction_required,
        backup_required=accepted.backup_required,
        source_prompt_sha256=prompt_sha256,
        authorization_reference=authorization_reference or f"control-draft:{uuid4()}",
        expires_at=(
            datetime.now(timezone.utc)
            + timedelta(minutes=accepted.expires_in_minutes)
        ),
    )


def _activate_control_contract(
    app: FastAPI,
    payload: ContractActivationRequest,
) -> ContractActivationResponse:
    session_id = app.state.supervision_binding.session_id
    record = app.state.contract_store.get(
        payload.contract_id,
        payload.expected_version,
    )
    if record is None or record.session_id != session_id:
        raise HTTPException(
            status_code=404,
            detail="Proposed contract was not found.",
        )
    now = datetime.now(timezone.utc)
    event = TrustedPromptEnvelope(
        event_id=f"control-activation:{uuid4()}",
        nonce=uuid4().hex,
        host_id=app.state.control_event_consumer.binding[0],
        session_id=session_id,
        channel="protected_local_ui",
        prompt=(
            f"Activate reviewed contract {record.contract_id} "
            f"version {record.version}."
        ),
        purpose="task_transition",
        contract_id=record.contract_id,
        contract_version=record.version,
        decision="approve",
        issued_at=now,
        expires_at=now + timedelta(minutes=2),
        authenticated=True,
    )
    try:
        receipt = app.state.control_event_consumer.consume(event, now=now)
        active = app.state.authority_service.activate_proposed(
            record.contract_id,
            expected_version=payload.expected_version,
            expected_active_task_id=payload.expected_active_task_id,
            trusted_event=receipt,
            activated_at=now,
        )
    except (ContractStoreError, TrustedEventError, AuditStoreError) as exc:
        raise HTTPException(
            status_code=409,
            detail="Contract activation failed because authority changed.",
        ) from exc
    return ContractActivationResponse(active_contract=active)


def _control_active_authority(app: FastAPI) -> ActiveAuthorityResponse:
    active = (
        app.state.contract_store.get_active(
            app.state.supervision_binding.session_id
        )
        if app.state.authority_service.authority_available
        else None
    )
    return ActiveAuthorityResponse(active_contract=active)


# -- agent task proposals (Week 13) --------------------------------------------------


def _proposal_response(
    app: FastAPI,
    proposal: TaskProposal,
    *,
    active_task_id: str | None,
) -> TaskProposalResponse:
    return TaskProposalResponse(
        draft_id=proposal.draft_id,
        state=proposal.state,
        source=proposal.source,
        objective=proposal.objective,
        operation=proposal.operation,
        exact_targets=list(proposal.exact_targets),
        environment=proposal.environment,
        allowed_effects=list(proposal.allowed_effects),
        task_duration_minutes=proposal.task_duration_minutes,
        content_sha256=proposal.content_sha256,
        proposal_number=proposal.proposal_number,
        created_at=proposal.created_at,
        proposal_expires_at=proposal.proposal_expires_at,
        replaces_active_task=proposal.state == "pending" and active_task_id is not None,
        resolution=proposal.resolution,
        resolved_at=proposal.resolved_at,
        confirmed_contract_id=proposal.confirmed_contract_id,
    )


def _current_active_task_id(app: FastAPI) -> str | None:
    if not app.state.authority_service.authority_available:
        return None
    active = app.state.contract_store.get_active(app.state.supervision_binding.session_id)
    return active.task_id if active is not None else None


def _control_pending_proposal(app: FastAPI) -> PendingProposalResponse:
    service: TaskProposalService | None = app.state.task_proposals
    if service is None:
        return PendingProposalResponse()
    active_task_id = _current_active_task_id(app)
    pending = service.pending()
    return PendingProposalResponse(
        proposal=(
            _proposal_response(app, pending, active_task_id=active_task_id)
            if pending is not None
            else None
        ),
        recent=[
            _proposal_response(app, item, active_task_id=active_task_id)
            for item in service.history()[:10]
        ],
    )


def _require_proposal_service(app: FastAPI) -> TaskProposalService:
    service: TaskProposalService | None = app.state.task_proposals
    if service is None:
        raise HTTPException(status_code=404, detail="Task proposals are not enabled.")
    return service


def _proposal_state_conflict(exc: ProposalStateError) -> HTTPException:
    status = 404 if exc.reason_code == "proposal:not_found" else 409
    return HTTPException(status_code=status, detail={"reason_code": exc.reason_code, "message": exc.reason})


def _accepted_draft_from_proposal(proposal: TaskProposal) -> AcceptedContractDraft:
    """Expand stored facts into the same shape the manual form submits.

    Only the five authority facts come from the proposal. The descriptive and
    narrowing fields are fixed server-side defaults for fixture tasks, so a
    proposal can never widen them.
    """

    write = proposal.operation == "write"
    return AcceptedContractDraft(
        operation=proposal.operation,
        exact_targets=list(proposal.exact_targets),
        environment=proposal.environment,  # type: ignore[arg-type]
        expected_side_effects=[
            "One reviewed internal note per approval on the listed fixture issues."
            if write
            else "Read-only access to the listed fixture issues."
        ],
        allowed_effects=set(proposal.allowed_effects),
        forbidden_operations={"delete", "network", "credential_access"},
        forbidden_effects=["No deletion, network, or credential access."],
        forbidden_effect_codes={"delete", "network", "credential_access"},
        rollback_plan="Notes are disposable fixture data; nothing outside the fixture changes.",
        dry_run_required=False,
        expires_in_minutes=proposal.task_duration_minutes,
        tool_family="sentinel_issue_fixture",
    )


def _confirm_task_proposal(
    app: FastAPI,
    draft_id: str,
    payload: ProposalConfirmRequest,
) -> ProposalConfirmResponse:
    """One protected click: rebuild the contract from the stored draft and activate it.

    The request carries only the draft ID (plus an optional stale-view guard).
    Every authority fact is re-read from the server-stored proposal and
    re-validated against the ceiling by `_accepted_fixture_contract`, the same
    builder the manual form uses.
    """

    service = _require_proposal_service(app)
    session_id = app.state.supervision_binding.session_id
    with app.state.session_locks.hold(session_id):
        try:
            proposal = service.require_confirmable(draft_id)
        except ProposalStateError as exc:
            raise _proposal_state_conflict(exc) from exc
        active_task_id = _current_active_task_id(app)
        # `None` here means the browser saw no active task; it must still match.
        if payload.expected_active_task_id != active_task_id:
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "proposal:stale_view", "message": "The active task changed; refresh and review again."},
            )
        accepted = _accepted_draft_from_proposal(proposal)
        contract = _accepted_fixture_contract(
            app,
            accepted,
            prompt_sha256=proposal.content_sha256,
            authorization_reference=f"task-proposal:{proposal.draft_id}",
        )
        now = datetime.now(timezone.utc)
        try:
            proposed = app.state.authority_service.create_proposed(
                contract,
                session_id=session_id,
                authorization_source="protected_local_ui",
                created_at=now,
                preflight_status="complete",
            )
        except (ContractStoreError, AuditStoreError) as exc:
            raise HTTPException(status_code=409, detail="Proposed contract could not be created.") from exc
        activation = _activate_control_contract(
            app,
            ContractActivationRequest(
                contract_id=proposed.contract_id,
                expected_version=proposed.version,
                expected_active_task_id=active_task_id,
            ),
        )
        active = activation.active_contract
        request_id = f"proposal-confirm:{uuid4()}"
        try:
            service.confirm(
                draft_id,
                contract_id=active.contract_id,
                task_id=active.task_id,
                request_id=request_id,
            )
        except ProposalStateError:
            # Authority is already active; the draft record is evidence only.
            pass
    return ProposalConfirmResponse(draft_id=draft_id, active_contract=active)


def _dismiss_task_proposal(app: FastAPI, draft_id: str) -> ProposalDismissResponse:
    service = _require_proposal_service(app)
    # Same lock as confirm/propose so a dismiss cannot land between confirm's
    # state check and its activation.
    with app.state.session_locks.hold(app.state.supervision_binding.session_id):
        try:
            dismissed = service.dismiss(
                draft_id,
                resolution="human_dismissed",
                request_id=f"proposal-dismiss:{uuid4()}",
            )
        except ProposalStateError as exc:
            raise _proposal_state_conflict(exc) from exc
    return ProposalDismissResponse(draft_id=draft_id, state=dismissed.state)  # type: ignore[arg-type]


def _adjust_task_proposal(app: FastAPI, draft_id: str) -> ProposalAdjustResponse:
    """Hand the draft to the full form and retire it so it cannot also be confirmed."""

    service = _require_proposal_service(app)
    with app.state.session_locks.hold(app.state.supervision_binding.session_id):
        try:
            proposal = service.require_confirmable(draft_id)
            service.dismiss(
                draft_id,
                resolution="adjusted_in_full_form",
                request_id=f"proposal-adjust:{uuid4()}",
            )
        except ProposalStateError as exc:
            raise _proposal_state_conflict(exc) from exc
    return ProposalAdjustResponse(
        draft_id=draft_id,
        raw_prompt=proposal.objective,
        accepted_contract=_accepted_draft_from_proposal(proposal),
    )


def _control_executor_ready(executor: object) -> bool:
    if (
        isinstance(executor, DockerExecutor)
        and executor.runner is not subprocess.run
    ):
        try:
            executor.validate_configuration()
        except Exception:
            return False
        return True
    runtime_ready = getattr(executor, "runtime_ready", None)
    if callable(runtime_ready):
        try:
            return bool(runtime_ready())
        except Exception:
            return False
    validate = getattr(executor, "validate_configuration", None)
    if not callable(validate):
        return False
    try:
        validate()
    except Exception:
        return False
    return True


def _control_integration_status(
    app: FastAPI,
) -> IntegrationStatusResponse | None:
    """Honest, per-family status of the mandatory MCP path; None when not wired."""

    policy_binding = app.state.supervision_policy_binding
    registry = app.state.adapter_registry
    if policy_binding is None or registry is None or app.state.mcp_mediator is None:
        return None
    now = datetime.now(timezone.utc)
    policy = policy_binding.policy
    expired = policy_binding.is_expired(now)
    audit_ready = _audit_health(app.state.audit_store).status == "ok"
    gateway_ready = not expired and audit_ready
    hooks = inspect_hooks_profile(app.state.supervision_binding.workspace.path)
    connection = registry.connection
    adapter = registry.current(policy.adapter_kind)
    coverage = [
        FamilyCoverageResponse(
            family=entry.family,
            status=entry.status,
            basis=entry.basis,
            conditions=list(entry.conditions),
            known_bypasses=list(entry.known_bypasses),
        )
        for entry in registry.profile.families
    ]
    if not gateway_ready:
        coverage = [
            entry.model_copy(update={"status": "unavailable"})
            if entry.status == "mandatory"
            else entry
            for entry in coverage
        ]
    return IntegrationStatusResponse(
        gateway=ControlCheckResponse(
            status="ready" if gateway_ready else "unavailable",
            detail=(
                "MCP gateway is bound to the startup ceiling and required audit storage."
                if gateway_ready
                else "Startup ceiling expired or required audit storage is unavailable; calls fail closed."
            ),
        ),
        hooks=ControlCheckResponse(
            status="ready" if hooks.status == "installed" else "unavailable",
            detail=hooks.detail,
        ),
        sandbox=ControlCheckResponse(
            status="unavailable",
            detail=(
                "Cursor's agent sandbox is a host setting Sentinel cannot read. "
                "Mandatory coverage assumes it is enabled."
            ),
        ),
        ceiling=CeilingStatusResponse(
            adapter_kind=policy.adapter_kind,
            tool_family=policy.tool_family,
            policy_sha256=policy_binding.content_sha256,
            expires_at=policy_binding.expires_at,
            expired=expired,
        ),
        agent=AgentConnectionResponse(
            host=connection.host,
            status=connection.status,
            last_seen_at=connection.last_seen_at,
            last_tool=connection.last_tool,
            last_verdict=connection.last_verdict,
            mediated_calls=connection.mediated_calls,
            rejected_calls=connection.rejected_calls,
            adapter_session_expires_at=adapter.expires_at if adapter else None,
        ),
        coverage=coverage,
    )


def _control_runtime_status(
    app: FastAPI,
    config: ControlConfig,
) -> ControlRuntimeStatus:
    docker_ready = bool(app.state.control_docker_ready)
    audit_ready = _audit_health(app.state.audit_store).status == "ok"
    policy_ready = app.state.policy_profile is not None
    authority_ready = app.state.authority_service.authority_available
    rules_ready = policy_ready and audit_ready and authority_ready
    workspace_path = str(app.state.supervision_binding.workspace.path)
    return ControlRuntimeStatus(
        backend=ControlCheckResponse(
            status="ready",
            detail="Protected FastAPI control routes are responding.",
        ),
        workspace=ControlCheckResponse(
            status="ready",
            detail="Workspace identity was reviewed and fixed at startup.",
        ),
        docker=ControlCheckResponse(
            status="ready" if docker_ready else "unavailable",
            detail=(
                "Docker executor and daemon passed the process startup check."
                if docker_ready
                else "Docker executor or daemon failed the process startup check."
            ),
        ),
        rules=ControlCheckResponse(
            status="ready" if rules_ready else "unavailable",
            detail=(
                "Rules-only enforcement and required audit storage are ready."
                if rules_ready
                else "Policy, authority, or required audit storage is unavailable."
            ),
        ),
        demo_mode=config.demo_mode,
        sample_repository=workspace_path if config.demo_mode else None,
    )


def _query_control_audit(
    app: FastAPI,
    **filters: object,
) -> AuditListResponse:
    query = AuditQuery(
        session_id=app.state.supervision_binding.session_id,
        **filters,
    )
    return AuditListResponse(events=app.state.audit_store.query(query))


def _write_pre_decision_audit(
    app: FastAPI,
    payload: ContractEvaluateRequest,
    request_id: str,
    resolved: _ResolvedContractRequest,
    *,
    execute_requested: bool,
) -> None:
    details: dict[str, Any] = {
        "action_family": "shell",
        "execution_requested": execute_requested,
        **_untrusted_identity_details(payload.user_id, payload.agent_id),
    }
    if resolved.match is not None:
        details["action_fingerprint"] = resolved.match.action_fingerprint
    _audit_write(
        app,
        AuditEvent(
            event_type="pre_decision",
            request_id=request_id,
            session_id=payload.session_id,
            task_id=resolved.task_id,
            contract_id=payload.contract_id,
            contract_version=payload.version,
            environment=resolved.environment,  # type: ignore[arg-type]
            details=details,
        ),
    )


def _write_approval_issue_audit(app: FastAPI, token: Any) -> None:
    binding = token.binding
    _audit_write_required(
        app,
        AuditEvent(
            event_type="exact_action_approved",
            user_id=token.approver_id,
            session_id=binding.session_id,
            task_id=binding.task_id,
            contract_id=binding.contract_id,
            contract_version=binding.contract_version,
            environment=binding.environment,
            reason_codes=["approval:issued_by_protected_channel"],
            details={
                "approval_id": token.approval_id,
                "approver_channel": token.approver_channel,
                "action_fingerprint": binding.action_fingerprint,
            },
        ),
    )


def _write_approval_denial_audit(
    app: FastAPI,
    pending: PendingApproval,
) -> None:
    binding = pending.binding
    _audit_write_required(
        app,
        AuditEvent(
            event_type="exact_action_denied",
            user_id="local-human",
            session_id=binding.session_id,
            task_id=binding.task_id,
            contract_id=binding.contract_id,
            contract_version=binding.contract_version,
            environment=binding.environment,  # type: ignore[arg-type]
            reason_codes=["approval:denied_by_protected_channel"],
            details={
                "approval_id": pending.approval_id,
                "approver_channel": "protected_local_ui",
                "action_fingerprint": binding.action_fingerprint,
                "authority_epoch": binding.authority_epoch,
            },
        ),
    )


def _write_execution_admitted_audit(
    app: FastAPI,
    payload: ContractEvaluateRequest,
    decision: DecisionResult,
    resolved: _ResolvedContractRequest,
    approval_id: str | None = None,
) -> None:
    _audit_write_required(
        app,
        AuditEvent(
            event_type="execution_admitted",
            request_id=decision.request_id,
            session_id=payload.session_id,
            task_id=resolved.task_id,
            contract_id=payload.contract_id,
            contract_version=payload.version,
            environment=resolved.environment,  # type: ignore[arg-type]
            verdict="allow",
            reason_codes=decision.reasons,
            details={
                "attempt_id": payload.attempt_id,
                "action_fingerprint": (
                    resolved.match.action_fingerprint if resolved.match else None
                ),
                "authority_epoch": (
                    resolved.record.authority_epoch if resolved.record else None
                ),
                "approval_id": approval_id,
                **_untrusted_identity_details(payload.user_id, payload.agent_id),
            },
        ),
    )


def _write_post_execution_audit(
    app: FastAPI,
    payload: ContractEvaluateRequest,
    decision: DecisionResult,
    resolved: _ResolvedContractRequest,
) -> None:
    execution = decision.execution
    assert execution is not None
    _audit_write(
        app,
        AuditEvent(
            event_type="post_execution",
            request_id=decision.request_id,
            session_id=payload.session_id,
            task_id=resolved.task_id,
            contract_id=payload.contract_id,
            contract_version=payload.version,
            environment=resolved.environment,  # type: ignore[arg-type]
            verdict="allow",
            reason_codes=decision.reasons,
            details={
                "action_fingerprint": (
                    resolved.match.action_fingerprint if resolved.match else None
                ),
                "exit_code": execution.exit_code,
                "timed_out": execution.timed_out,
                "executor_error": execution.error is not None,
                **_untrusted_identity_details(payload.user_id, payload.agent_id),
            },
        ),
    )


def _write_decision_audit(
    app: FastAPI,
    payload: ContractEvaluateRequest,
    decision: DecisionResult,
    resolved: _ResolvedContractRequest,
    *,
    execute_requested: bool,
) -> None:
    details: dict[str, Any] = {
        "action_family": "shell",
        "execution_requested": execute_requested,
        **_untrusted_identity_details(payload.user_id, payload.agent_id),
        "execution_route": (
            "docker" if execute_requested and decision.verdict == "allow" else "none"
        ),
    }
    if resolved.match is not None:
        details["action_fingerprint"] = resolved.match.action_fingerprint
    _audit_write(
        app,
        AuditEvent(
            event_type="decision",
            request_id=decision.request_id,
            session_id=payload.session_id,
            task_id=resolved.task_id,
            contract_id=payload.contract_id,
            contract_version=payload.version,
            environment=resolved.environment,  # type: ignore[arg-type]
            verdict=decision.verdict,
            reason_codes=decision.reasons,
            details=details,
        ),
    )


def _append_admitted_session_action(
    app: FastAPI,
    payload: ContractEvaluateRequest,
    resolved: _ResolvedContractRequest,
) -> None:
    action = resolved.action
    record = resolved.record
    assert action is not None
    assert record is not None
    try:
        app.state.session_store.append_action(
            payload.session_id,
            SessionAction(
                action_id=f"attempt:{payload.attempt_id}",
                action_type="shell.execute",
                summary=(
                    f"{action.family} {action.operation} "
                    f"targets={len(action.targets)} "
                    f"effects={','.join(sorted(action.effects)[:16]) or 'none'}"
                ),
                task_id=record.task_id,
                sensitive_resources=_security_categories(action),
                metadata={
                    "admitted": True,
                    "family": action.family,
                    "operation": action.operation,
                    "target_count": len(action.targets),
                    "audience_target_count": len(action.audience_targets),
                    "effects": sorted(action.effects)[:32],
                    "security_categories": _security_categories(action),
                    "target_hashes": [
                        hashlib.sha256(target.encode("utf-8")).hexdigest()
                        for target in action.targets[:32]
                    ],
                },
            ),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Execution admission history could not be retained; executor was not started.",
        ) from exc


def _write_legacy_pre_audit(
    app: FastAPI,
    payload: EvaluateRequest,
    request_id: str,
) -> None:
    _audit_write(
        app,
        AuditEvent(
            event_type="pre_decision",
            request_id=request_id,
            session_id=payload.session_id,
            environment=payload.environment,
            details={
                "legacy_non_authorizing": True,
                **_untrusted_identity_details(payload.user_id, payload.agent_id),
            },
        ),
    )


def _write_legacy_post_audit(
    app: FastAPI,
    payload: EvaluateRequest,
    decision: DecisionResult,
) -> None:
    execution = decision.execution
    assert execution is not None
    _audit_write(
        app,
        AuditEvent(
            event_type="post_execution",
            request_id=decision.request_id,
            session_id=payload.session_id,
            environment=payload.environment,
            verdict="allow",
            reason_codes=decision.reasons,
            details={
                "legacy_non_authorizing": True,
                "exit_code": execution.exit_code,
                "timed_out": execution.timed_out,
                **_untrusted_identity_details(payload.user_id, payload.agent_id),
            },
        ),
    )


def _write_legacy_decision_audit(
    app: FastAPI,
    payload: EvaluateRequest,
    decision: DecisionResult,
    *,
    execute_requested: bool,
) -> None:
    _audit_write(
        app,
        AuditEvent(
            event_type="decision",
            request_id=decision.request_id,
            session_id=payload.session_id,
            environment=payload.environment,
            verdict=decision.verdict,
            reason_codes=decision.reasons,
            details={
                "legacy_non_authorizing": True,
                "execution_requested": execute_requested,
                "execution_route": (
                    "docker"
                    if execute_requested and decision.verdict == "allow"
                    else "none"
                ),
                **_untrusted_identity_details(payload.user_id, payload.agent_id),
            },
        ),
    )


def _audit_write(app: FastAPI, event: AuditEvent) -> None:
    try:
        app.state.audit_store.write(event)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Audit evidence could not be retained; request failed closed.",
        ) from exc


def _audit_write_required(app: FastAPI, event: AuditEvent) -> None:
    try:
        app.state.audit_store.write_required(event)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "Required audit evidence could not be committed; "
                "executor was not started."
            ),
        ) from exc


def _write_optional_execution_telemetry(
    writer: Any,
    *args: Any,
    **kwargs: Any,
) -> None:
    try:
        writer(*args, **kwargs)
    except HTTPException:
        pass


def _untrusted_identity_details(user_id: str, agent_id: str) -> dict[str, Any]:
    return {
        "caller_identity_trusted": False,
        "claimed_user_id_hash": hashlib.sha256(user_id.encode("utf-8")).hexdigest(),
        "claimed_agent_id_hash": hashlib.sha256(agent_id.encode("utf-8")).hexdigest(),
    }


def _audit_health(store: AuditStore) -> AuditHealth:
    try:
        return store.health
    except Exception as exc:
        return AuditHealth(
            status="degraded",
            detail=f"Audit health unavailable: {type(exc).__name__}",
            fallback_event_count=0,
            fallback_capacity=0,
        )


def _session_action_to_history(action: SessionAction) -> dict[str, Any]:
    return {
        "type": action.action_type,
        "summary": action.summary,
        "sensitive_resources": list(action.sensitive_resources),
        "metadata": dict(action.metadata),
    }


def _security_categories(action: CanonicalAction) -> list[str]:
    categories: set[str] = set()
    lowered_targets = [target.lower() for target in action.targets]
    if any(
        indicator in target
        for target in lowered_targets
        for indicator in (
            ".env",
            ".aws",
            "credential",
            "id_rsa",
            ".pem",
            "private_key",
            "secret",
        )
    ):
        categories.add("credential")
    if any(".env" in target for target in lowered_targets):
        categories.add("environment_variables")
    if any("customer" in target for target in lowered_targets):
        categories.add("customer_data")
    if action.environment == "production":
        categories.add("production")
    if action.operation in {"network", "external_communication"}:
        categories.add("external_communication")
    categories.update(
        effect
        for effect in action.effects
        if effect in {"credential_access", "network", "external_communication"}
    )
    return sorted(categories)


def _replace_decision(
    decision: DecisionResult,
    *,
    verdict: str | None = None,
    reasons: list[str] | None = None,
    routing_path: str | None = None,
    agent_message: str | None = None,
    suggested_safe_actions: list[str] | None = None,
    approval_id: str | None = None,
    execution: ExecutionResult | None = None,
) -> DecisionResult:
    selected_verdict = verdict or decision.verdict
    replaced = DecisionResult(
        request_id=decision.request_id,
        verdict=selected_verdict,  # type: ignore[arg-type]
        risk_score=(
            VERDICT_RISK_SCORES[selected_verdict]  # type: ignore[index]
            if verdict is not None
            else decision.risk_score
        ),
        risk_tier=(
            VERDICT_TO_RISK_TIER[selected_verdict]  # type: ignore[index]
            if verdict is not None
            else decision.risk_tier
        ),
        reasons=reasons if reasons is not None else decision.reasons,
        routing_path=routing_path or decision.routing_path,  # type: ignore[arg-type]
        agent_message=agent_message or decision.agent_message,
        suggested_safe_actions=(
            suggested_safe_actions
            if suggested_safe_actions is not None
            else decision.suggested_safe_actions
        ),
        rule_decision=decision.rule_decision,
        model_prediction=decision.model_prediction,
        confirmation_id=decision.confirmation_id,
        approval_id=approval_id,
        execution=execution if execution is not None else decision.execution,
    )
    return replaced


def response_from_decision(decision: DecisionResult) -> EvaluateResponse:
    return EvaluateResponse(
        request_id=decision.request_id,
        verdict=decision.verdict,
        risk_score=decision.risk_score,
        risk_tier=decision.risk_tier,
        reasons=decision.reasons,
        routing_path=decision.routing_path,
        agent_message=decision.agent_message,
        suggested_safe_actions=decision.suggested_safe_actions,
        confirmation_id=decision.confirmation_id,
        approval_id=decision.approval_id,
        execution=(
            decision.execution.to_response_payload()
            if decision.execution is not None
            else None
        ),
    )


def _model_to_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "dict"):
        return value.dict()
    return dict(value)


def _model_to_json_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", warnings=False)
    if hasattr(value, "json"):
        import json

        return json.loads(value.json())
    return dict(value)


def _default_executor() -> DockerExecutor:
    kwargs: dict[str, Any] = {}
    image = os.environ.get("SENTINEL_EXECUTOR_IMAGE")
    if image:
        kwargs["image"] = image
    workspace = os.environ.get("SENTINEL_EXECUTOR_WORKSPACE")
    if workspace:
        kwargs["workspace"] = Path(workspace)
    timeout = _positive_int_env("SENTINEL_EXECUTOR_TIMEOUT_SECONDS")
    if timeout is not None:
        kwargs["timeout_seconds"] = timeout
    readonly = os.environ.get("SENTINEL_EXECUTOR_READONLY_WORKSPACE")
    if readonly is not None:
        kwargs["read_only_workspace"] = _strict_bool_env(
            "SENTINEL_EXECUTOR_READONLY_WORKSPACE",
            readonly,
        )
    return DockerExecutor(**kwargs)


def _max_concurrent_executions() -> int:
    return _positive_int_env("SENTINEL_MAX_CONCURRENT_EXECUTIONS") or 8


def _positive_int_env(name: str) -> int | None:
    raw = os.environ.get(name)
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def _strict_bool_env(name: str, raw: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a recognized boolean value")


def _module_ml_enabled() -> bool:
    raw = os.environ.get("SENTINEL_ENABLE_ML")
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise ValueError(
        "SENTINEL_ENABLE_ML must be exactly 'true' or 'false'"
    )


app = create_app(load_model=_module_ml_enabled())
