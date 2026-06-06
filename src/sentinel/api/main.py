"""FastAPI application for Sentinel command evaluation."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from sentinel.api.schemas import EvaluateRequest, EvaluateResponse, HealthResponse
from sentinel.decision.engine import DecisionResult, RiskModelProtocol, evaluate_request
from sentinel.ml.inference import DEFAULT_ONNX_PATH, OnnxRiskModel


def create_app(*, model: RiskModelProtocol | None = None, load_model: bool = True) -> FastAPI:
    app = FastAPI(
        title="Sentinel Guardrail API",
        version="0.1.0",
        description="Local evaluation API for AI-agent command execution guardrails.",
    )
    app.state.risk_model = model
    app.state.model_load_error = None

    if app.state.risk_model is None and load_model:
        try:
            app.state.risk_model = OnnxRiskModel()
        except Exception as exc:
            app.state.model_load_error = str(exc)

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
        decision = evaluate_request(
            context=payload.context,
            command=payload.command,
            environment=payload.environment,
            shell_type=payload.shell_type,
            recent_actions=[_model_to_dict(action) for action in payload.recent_actions],
            model=app.state.risk_model,
        )
        return response_from_decision(decision)

    return app


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
        execution=decision.execution,
    )


def _model_to_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "dict"):
        return value.dict()
    return dict(value)


app = create_app()

