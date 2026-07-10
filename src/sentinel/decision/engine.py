"""Rules-first decision engine for Sentinel command evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Literal
from uuid import uuid4

from sentinel.decision.policy import EnvironmentPolicy, PolicyProfile
from sentinel.decision.rules import RuleDecision, Verdict, evaluate_command
from sentinel.execution import ExecutionResult
from sentinel.ml.inference import RiskPrediction

RiskTier = Literal["low", "medium", "high", "critical"]
RoutingPath = Literal["rules", "policy", "model", "combined", "confirmation"]

VERDICT_RISK_SCORES: dict[Verdict, float] = {
    "allow": 0.05,
    "warn": 0.35,
    "confirm_required": 0.75,
    "block": 1.0,
}

MODEL_TIER_TO_RISK_TIER: dict[str, RiskTier] = {
    "allow": "low",
    "warn": "medium",
    "confirm_required": "high",
}

MODEL_TIER_ORDER = {
    "allow": 0,
    "warn": 1,
    "confirm_required": 2,
}

VERDICT_TO_RISK_TIER: dict[Verdict, RiskTier] = {
    "allow": "low",
    "warn": "medium",
    "confirm_required": "high",
    "block": "critical",
}


@dataclass(frozen=True)
class DecisionResult:
    request_id: str
    verdict: Verdict
    risk_score: float
    risk_tier: RiskTier
    reasons: list[str]
    routing_path: RoutingPath
    agent_message: str
    suggested_safe_actions: list[str]
    rule_decision: RuleDecision
    model_prediction: RiskPrediction | None = None
    confirmation_id: str | None = None
    execution: ExecutionResult | None = None


class RiskModelProtocol:
    def predict_row(self, row: dict[str, Any]) -> RiskPrediction:
        raise NotImplementedError


RequestIdFactory = Callable[[], str]


def evaluate_request(
    *,
    context: str,
    command: str,
    environment: str,
    shell_type: str = "unknown",
    recent_actions: list[dict[str, Any]] | None = None,
    model: RiskModelProtocol | None = None,
    policy_profile: PolicyProfile | None = None,
    request_id_factory: RequestIdFactory | None = None,
) -> DecisionResult:
    """Evaluate a command using deterministic rules before optional model scoring."""

    request_id = (request_id_factory or _new_request_id)()
    actions = recent_actions or []
    environment_policy = policy_profile.policy_for(environment) if policy_profile else None
    rule_decision = evaluate_command(
        context=context,
        command=command,
        environment=environment,
        recent_actions=actions,
    )

    if rule_decision.skip_model:
        return _apply_policy_to_rule_result(
            _result_from_rule(request_id, rule_decision, environment, shell_type),
            environment_policy,
        )

    if model is None:
        return _result_without_model(request_id, rule_decision, environment, shell_type, environment_policy)

    try:
        # Keep shell_type out of model input until the dataset/training format is intentionally updated.
        prediction = model.predict_row(
            {
                "context": context,
                "command": command,
                "environment": environment,
                "recent_actions": actions,
            }
        )
    except Exception as exc:
        return _result_without_model(request_id, rule_decision, environment, shell_type, environment_policy, str(exc))
    return _apply_policy_to_model_result(
        _result_from_model(request_id, rule_decision, prediction, environment, shell_type),
        environment_policy,
        prediction,
    )


def _result_from_rule(request_id: str, rule_decision: RuleDecision, environment: str, shell_type: str) -> DecisionResult:
    verdict = rule_decision.verdict
    return DecisionResult(
        request_id=request_id,
        verdict=verdict,
        risk_score=VERDICT_RISK_SCORES[verdict],
        risk_tier=VERDICT_TO_RISK_TIER[verdict],
        reasons=_base_reasons(rule_decision, environment, shell_type),
        routing_path="rules",
        agent_message=agent_message_for_verdict(verdict, rule_decision.reason),
        suggested_safe_actions=suggested_safe_actions_for_verdict(verdict),
        rule_decision=rule_decision,
    )


def _result_without_model(
    request_id: str,
    rule_decision: RuleDecision,
    environment: str,
    shell_type: str,
    environment_policy: EnvironmentPolicy | None,
    error_detail: str | None = None,
) -> DecisionResult:
    verdict: Verdict = "confirm_required"
    reasons = [
        *_base_reasons(rule_decision, environment, shell_type),
        "model:unavailable",
        "policy:confirmation_required_without_model",
    ]
    if error_detail:
        reasons.append("model:error")
    decision = DecisionResult(
        request_id=request_id,
        verdict=verdict,
        risk_score=VERDICT_RISK_SCORES[verdict],
        risk_tier=VERDICT_TO_RISK_TIER[verdict],
        reasons=reasons,
        routing_path="rules",
        agent_message=agent_message_for_verdict(
            verdict,
            "Model review is unavailable, so Sentinel requires confirmation before this ambiguous command can proceed.",
        ),
        suggested_safe_actions=suggested_safe_actions_for_verdict(verdict),
        rule_decision=rule_decision,
    )
    return _apply_policy_to_model_unavailable_result(decision, environment_policy)


def _result_from_model(
    request_id: str,
    rule_decision: RuleDecision,
    prediction: RiskPrediction,
    environment: str,
    shell_type: str,
) -> DecisionResult:
    verdict = _model_verdict(prediction)
    return DecisionResult(
        request_id=request_id,
        verdict=verdict,
        risk_score=prediction.risk_probability,
        risk_tier=MODEL_TIER_TO_RISK_TIER[prediction.model_tier],
        reasons=[*_base_reasons(rule_decision, environment, shell_type), f"model:{prediction.model_tier}"],
        routing_path="model" if rule_decision.reason_code == "unmatched_ambiguous_command" else "combined",
        agent_message=agent_message_for_verdict(verdict, rule_decision.reason),
        suggested_safe_actions=suggested_safe_actions_for_verdict(verdict),
        rule_decision=rule_decision,
        model_prediction=prediction,
    )


def _apply_policy_to_rule_result(
    decision: DecisionResult,
    environment_policy: EnvironmentPolicy | None,
) -> DecisionResult:
    if environment_policy is None or decision.verdict == "block":
        return decision

    if decision.verdict == "warn" and environment_policy.warn_requires_confirmation:
        return _escalate_to_confirmation(decision, f"policy:{environment_policy.name}_warn_requires_confirmation")

    return decision


def _apply_policy_to_model_unavailable_result(
    decision: DecisionResult,
    environment_policy: EnvironmentPolicy | None,
) -> DecisionResult:
    if environment_policy is None:
        return decision

    reasons = [*decision.reasons, f"policy:{environment_policy.name}_model_unavailable_confirmation"]
    return DecisionResult(
        request_id=decision.request_id,
        verdict=decision.verdict,
        risk_score=decision.risk_score,
        risk_tier=decision.risk_tier,
        reasons=reasons,
        routing_path="policy",
        agent_message=decision.agent_message,
        suggested_safe_actions=decision.suggested_safe_actions,
        rule_decision=decision.rule_decision,
        model_prediction=decision.model_prediction,
        confirmation_id=decision.confirmation_id,
        execution=decision.execution,
    )


def _apply_policy_to_model_result(
    decision: DecisionResult,
    environment_policy: EnvironmentPolicy | None,
    prediction: RiskPrediction,
) -> DecisionResult:
    if environment_policy is None or decision.verdict == "block":
        return decision

    reasons: list[str] = []
    if _model_tier_requires_confirmation(prediction.model_tier, environment_policy.minimum_model_tier_for_confirmation):
        reasons.append(f"policy:{environment_policy.name}_minimum_model_tier_for_confirmation")
    if decision.verdict == "warn" and environment_policy.warn_requires_confirmation:
        reasons.append(f"policy:{environment_policy.name}_warn_requires_confirmation")
    if decision.rule_decision.reason_code == "unmatched_ambiguous_command" and environment_policy.unmatched_requires_confirmation:
        reasons.append(f"policy:{environment_policy.name}_unmatched_requires_confirmation")

    if not reasons:
        return decision

    return _escalate_to_confirmation(decision, *reasons)


def _model_tier_requires_confirmation(model_tier: str, minimum_model_tier: str) -> bool:
    return MODEL_TIER_ORDER[model_tier] >= MODEL_TIER_ORDER[minimum_model_tier]


def _escalate_to_confirmation(decision: DecisionResult, *policy_reasons: str) -> DecisionResult:
    verdict: Verdict = "confirm_required"
    risk_score = max(decision.risk_score, VERDICT_RISK_SCORES[verdict])
    return DecisionResult(
        request_id=decision.request_id,
        verdict=verdict,
        risk_score=risk_score,
        risk_tier=VERDICT_TO_RISK_TIER[verdict],
        reasons=[*decision.reasons, *policy_reasons],
        routing_path="policy",
        agent_message=agent_message_for_verdict(
            verdict,
            "The active policy profile requires confirmation for this environment before the command can proceed.",
        ),
        suggested_safe_actions=suggested_safe_actions_for_verdict(verdict),
        rule_decision=decision.rule_decision,
        model_prediction=decision.model_prediction,
        confirmation_id=decision.confirmation_id,
        execution=decision.execution,
    )


def _model_verdict(prediction: RiskPrediction) -> Verdict:
    if prediction.model_tier == "confirm_required":
        return "confirm_required"
    if prediction.model_tier == "warn":
        return "warn"
    return "allow"


def _base_reasons(rule_decision: RuleDecision, environment: str, shell_type: str) -> list[str]:
    return [f"rule:{rule_decision.reason_code}", f"environment:{environment}", f"shell_type:{shell_type}"]


def agent_message_for_verdict(verdict: Verdict, reason: str) -> str:
    if verdict == "block":
        return f"Sentinel blocked this command. {reason} Do not retry the same command without changing scope."
    if verdict == "confirm_required":
        return f"Sentinel requires confirmation before this command can proceed. {reason}"
    if verdict == "warn":
        return f"Sentinel allows this command with a warning. {reason}"
    return f"Sentinel allows this command. {reason}"


def suggested_safe_actions_for_verdict(verdict: Verdict) -> list[str]:
    if verdict == "block":
        return [
            "Use a narrower command that only touches the intended resource.",
            "Ask the user for a safer scoped alternative before retrying.",
        ]
    if verdict == "confirm_required":
        return [
            "Explain why the command is necessary.",
            "Ask the user to approve this exact command before retrying.",
        ]
    if verdict == "warn":
        return ["Review the command output for sensitive data or unintended side effects."]
    return []


def _new_request_id() -> str:
    return str(uuid4())

