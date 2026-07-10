"""FastAPI application for Sentinel command evaluation."""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException

from sentinel.api.schemas import ConfirmRequest, ConfirmResponse, EvaluateRequest, EvaluateResponse, HealthResponse
from sentinel.decision.confirmation import ConfirmationRequest, InMemoryConfirmationStore
from sentinel.decision.engine import DecisionResult, RiskModelProtocol, evaluate_request
from sentinel.decision.policy import PolicyProfile, load_policy_profile
from sentinel.execution import CommandExecutor, DockerExecutor, ExecutionResult
from sentinel.ml.inference import DEFAULT_ONNX_PATH, OnnxRiskModel


def create_app(
    *,
    model: RiskModelProtocol | None = None,
    load_model: bool = True,
    policy_profile: PolicyProfile | None = None,
    load_policy: bool = True,
    confirmation_store: InMemoryConfirmationStore | None = None,
    executor: CommandExecutor | None = None,
) -> FastAPI:
    app = FastAPI(
        title="Sentinel Guardrail API",
        version="0.1.0",
        description="Local evaluation API for AI-agent command execution guardrails.",
    )
    app.state.risk_model = model
    app.state.model_load_error = None
    app.state.policy_profile = policy_profile
    app.state.policy_load_error = None
    app.state.confirmation_store = confirmation_store or InMemoryConfirmationStore()
    app.state.executor = executor or _default_executor()
    # Cap concurrent sandbox executions so slow containers cannot exhaust the
    # shared request thread pool and starve /evaluate and /health.
    app.state.execution_limiter = threading.BoundedSemaphore(_max_concurrent_executions())

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

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        model_loaded = app.state.risk_model is not None
        return HealthResponse(
            status="ok" if model_loaded else "degraded",
            model_loaded=model_loaded,
            model_path=str(DEFAULT_ONNX_PATH),
            detail=None if model_loaded else app.state.model_load_error or "Model is not loaded; gray-area requests require confirmation.",
        )

    @app.post("/evaluate", response_model=EvaluateResponse)
    def evaluate(payload: EvaluateRequest) -> EvaluateResponse:
        return response_from_decision(_evaluate_payload(payload, app))

    @app.post("/execute", response_model=EvaluateResponse)
    def execute(payload: EvaluateRequest) -> EvaluateResponse:
        decision = _evaluate_payload(payload, app)
        if decision.verdict != "allow":
            return response_from_decision(decision)

        # Non-blocking acquire: fail fast with 429 instead of queueing threads,
        # so a burst of slow executions cannot freeze the whole API.
        if not app.state.execution_limiter.acquire(blocking=False):
            raise HTTPException(
                status_code=429,
                detail="Too many concurrent sandbox executions; retry shortly.",
            )
        try:
            execution = app.state.executor.run(command=payload.command, shell_type=payload.shell_type)
        finally:
            app.state.execution_limiter.release()
        return response_from_decision(
            _replace_decision(
                decision,
                reasons=[*decision.reasons, "execution:sandbox_attempted"],
                execution=execution,
            )
        )

    @app.post("/confirm", response_model=ConfirmResponse)
    def confirm(payload: ConfirmRequest) -> ConfirmResponse:
        token = app.state.confirmation_store.approve(payload.confirmation_id)
        if token is None:
            raise HTTPException(status_code=404, detail="Unknown confirmation_id")

        return ConfirmResponse(
            confirmation_id=token.confirmation_id,
            confirmation_token=token.token,
        )

    return app


def _default_executor() -> DockerExecutor:
    """Build the executor from environment overrides so deployments can tune the sandbox without code changes."""

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
        kwargs["read_only_workspace"] = readonly.strip().lower() in {"1", "true", "yes", "on"}
    return DockerExecutor(**kwargs)


def _max_concurrent_executions() -> int:
    return _positive_int_env("SENTINEL_MAX_CONCURRENT_EXECUTIONS") or 8


def _positive_int_env(name: str) -> int | None:
    """Parse a positive integer env var, ignoring malformed or non-positive values.

    Misconfiguration must not crash app creation (create_app runs at import),
    so bad values fall back to defaults instead of raising.
    """
    raw = os.environ.get(name)
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def _evaluate_payload(payload: EvaluateRequest, app: FastAPI) -> DecisionResult:
    recent_actions = [_model_to_dict(action) for action in payload.recent_actions]
    confirmation_request = _confirmation_request_from_payload(payload, recent_actions)
    decision = evaluate_request(
        context=payload.context,
        command=payload.command,
        environment=payload.environment,
        shell_type=payload.shell_type,
        recent_actions=recent_actions,
        model=app.state.risk_model,
        policy_profile=app.state.policy_profile,
    )
    return _apply_confirmation_flow(
        decision,
        confirmation_request,
        confirmation_token=payload.confirmation_token,
        user_confirmed=payload.user_confirmed,
        confirmation_store=app.state.confirmation_store,
    )


def _apply_confirmation_flow(
    decision: DecisionResult,
    confirmation_request: ConfirmationRequest,
    *,
    confirmation_token: str | None,
    user_confirmed: bool,
    confirmation_store: InMemoryConfirmationStore,
) -> DecisionResult:
    if decision.verdict != "confirm_required":
        return decision

    reasons = list(decision.reasons)
    if confirmation_token:
        if confirmation_store.consume_token(confirmation_token, confirmation_request):
            return _confirmed_decision(decision)
        reasons.append("confirmation:token_invalid_or_mismatch")
    elif user_confirmed:
        reasons.append("confirmation:user_confirmed_untrusted_without_token")

    pending = confirmation_store.create_pending(confirmation_request, decision.verdict)
    return _replace_decision(
        decision,
        reasons=[*reasons, "confirmation:pending"],
        confirmation_id=pending.confirmation_id,
    )


def _confirmed_decision(decision: DecisionResult) -> DecisionResult:
    return _replace_decision(
        decision,
        verdict="allow",
        reasons=[*decision.reasons, "confirmation:token_valid"],
        routing_path="confirmation",
        agent_message="Sentinel allows this command because a human approved this exact request.",
        suggested_safe_actions=[],
        confirmation_id=None,
    )


def _replace_decision(
    decision: DecisionResult,
    *,
    verdict: str | None = None,
    reasons: list[str] | None = None,
    routing_path: str | None = None,
    agent_message: str | None = None,
    suggested_safe_actions: list[str] | None = None,
    confirmation_id: str | None = None,
    execution: ExecutionResult | None = None,
) -> DecisionResult:
    return DecisionResult(
        request_id=decision.request_id,
        verdict=verdict or decision.verdict,  # type: ignore[arg-type]
        risk_score=decision.risk_score,
        risk_tier=decision.risk_tier,
        reasons=reasons if reasons is not None else decision.reasons,
        routing_path=routing_path or decision.routing_path,  # type: ignore[arg-type]
        agent_message=agent_message or decision.agent_message,
        suggested_safe_actions=suggested_safe_actions if suggested_safe_actions is not None else decision.suggested_safe_actions,
        rule_decision=decision.rule_decision,
        model_prediction=decision.model_prediction,
        confirmation_id=confirmation_id,
        execution=execution if execution is not None else decision.execution,
    )


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
        execution=decision.execution.to_response_payload() if decision.execution is not None else None,
    )


def _confirmation_request_from_payload(payload: EvaluateRequest, recent_actions: list[dict[str, Any]]) -> ConfirmationRequest:
    return ConfirmationRequest(
        context=payload.context,
        command=payload.command,
        environment=payload.environment,
        shell_type=payload.shell_type,
        recent_actions=recent_actions,
        session_id=payload.session_id,
        agent_id=payload.agent_id,
        user_id=payload.user_id,
    )


def _model_to_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "dict"):
        return value.dict()
    return dict(value)


app = create_app()

