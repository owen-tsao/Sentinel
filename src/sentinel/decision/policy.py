"""Local policy profile contract for Sentinel decisions."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from sentinel.decision.rules import Verdict

Environment = Literal["sandbox", "dev", "staging", "production"]

DEFAULT_POLICY_PATH = Path("policies/default.json")
ENVIRONMENTS = ("sandbox", "dev", "staging", "production")
MODEL_TIERS = ("allow", "warn", "confirm_required")
CONFIRMABLE_VERDICTS = ("confirm_required",)


@dataclass(frozen=True)
class EnvironmentPolicy:
    name: Environment
    minimum_model_tier_for_confirmation: str
    warn_requires_confirmation: bool
    production_change_requires_confirmation: bool
    unmatched_requires_confirmation: bool
    allow_confirmation_for_verdicts: tuple[Verdict, ...]


@dataclass(frozen=True)
class PolicyProfile:
    name: str
    version: int
    default_environment: Environment
    environments: dict[Environment, EnvironmentPolicy]

    def policy_for(self, environment: str) -> EnvironmentPolicy:
        key = normalize_environment(environment or self.default_environment)
        return self.environments.get(key, self.environments[self.default_environment])


def load_policy_profile(path: Path = DEFAULT_POLICY_PATH) -> PolicyProfile:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return parse_policy_profile(raw, source=str(path))


def parse_policy_profile(raw: dict[str, Any], *, source: str = "<policy>") -> PolicyProfile:
    if not isinstance(raw, dict):
        raise ValueError(f"{source}: expected JSON object")

    name = _required_string(raw, "name", source)
    version = raw.get("version")
    if not isinstance(version, int) or version < 1:
        raise ValueError(f"{source}: version must be a positive integer")

    default_environment = normalize_environment(_required_string(raw, "default_environment", source))
    environments_raw = raw.get("environments")
    if not isinstance(environments_raw, dict) or not environments_raw:
        raise ValueError(f"{source}: environments must be a non-empty object")

    environments: dict[Environment, EnvironmentPolicy] = {}
    for environment_name, policy_raw in environments_raw.items():
        environment = normalize_environment(str(environment_name))
        environments[environment] = parse_environment_policy(environment, policy_raw, source=source)

    if default_environment not in environments:
        raise ValueError(f"{source}: default_environment must exist in environments")

    return PolicyProfile(
        name=name,
        version=version,
        default_environment=default_environment,
        environments=environments,
    )


def parse_environment_policy(environment: Environment, raw: Any, *, source: str) -> EnvironmentPolicy:
    if not isinstance(raw, dict):
        raise ValueError(f"{source}: environment {environment} must be an object")

    minimum_model_tier = str(raw.get("minimum_model_tier_for_confirmation", "confirm_required"))
    if minimum_model_tier not in MODEL_TIERS:
        raise ValueError(f"{source}: {environment}.minimum_model_tier_for_confirmation is invalid")

    allow_confirmation = raw.get("allow_confirmation_for_verdicts", ["confirm_required"])
    if not isinstance(allow_confirmation, list) or not allow_confirmation:
        raise ValueError(f"{source}: {environment}.allow_confirmation_for_verdicts must be a non-empty list")
    invalid_verdicts = [verdict for verdict in allow_confirmation if verdict not in CONFIRMABLE_VERDICTS]
    if invalid_verdicts:
        raise ValueError(f"{source}: {environment}.allow_confirmation_for_verdicts contains invalid verdicts")

    return EnvironmentPolicy(
        name=environment,
        minimum_model_tier_for_confirmation=minimum_model_tier,
        warn_requires_confirmation=_bool(raw, "warn_requires_confirmation", default=False),
        production_change_requires_confirmation=_bool(raw, "production_change_requires_confirmation", default=False),
        unmatched_requires_confirmation=_bool(raw, "unmatched_requires_confirmation", default=True),
        allow_confirmation_for_verdicts=tuple(allow_confirmation),  # type: ignore[arg-type]
    )


def normalize_environment(value: str) -> Environment:
    normalized = value.strip().lower()
    if normalized not in ENVIRONMENTS:
        raise ValueError(f"unsupported environment: {value}")
    return normalized  # type: ignore[return-value]


def _required_string(raw: dict[str, Any], key: str, source: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{source}: {key} must be a non-empty string")
    return value.strip()


def _bool(raw: dict[str, Any], key: str, *, default: bool) -> bool:
    value = raw.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value

