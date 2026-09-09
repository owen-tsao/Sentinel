"""Deterministic, non-persistent task prompt compilation."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Literal

DraftSource = Literal[
    "prompt_explicit",
    "prompt_inference",
    "deterministic_derivation",
    "safe_default",
]

MAX_RAW_PROMPT_BYTES = 32_000

_OPERATION_PATTERNS: dict[str, re.Pattern[str]] = {
    "read": re.compile(r"\b(read|inspect|show|list|view)\b", re.IGNORECASE),
    "write": re.compile(
        r"\b(write|create|touch|update|edit|modify)\b",
        re.IGNORECASE,
    ),
    "delete": re.compile(r"\b(delete|remove|unlink)\b", re.IGNORECASE),
    "execute": re.compile(r"\b(run|execute)\b", re.IGNORECASE),
}
_ENVIRONMENTS = ("sandbox", "dev", "staging", "production")
_ABSOLUTE_PATH = re.compile(r"(?<![\w.-])(/[^\s,;:'\"()\[\]{}]+)")


class DraftCompilationError(ValueError):
    """Raw prompt input is invalid without reflecting it into an error."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class DraftSuggestion:
    field: str
    value: object
    source: DraftSource
    requires_review: bool = True


@dataclass(frozen=True)
class DraftQuestion:
    question_id: str
    field: str
    prompt: str


@dataclass(frozen=True)
class CompiledDraftPreview:
    prompt_sha256: str
    suggestions: tuple[DraftSuggestion, ...]
    questions: tuple[DraftQuestion, ...]


def compile_task_prompt(raw_prompt: str) -> CompiledDraftPreview:
    """Extract only explicit facts and visibly labeled conservative defaults."""

    encoded = raw_prompt.encode("utf-8")
    if not raw_prompt.strip():
        raise DraftCompilationError("draft:prompt_required")
    if len(encoded) > MAX_RAW_PROMPT_BYTES:
        raise DraftCompilationError("draft:prompt_too_large")

    suggestions: list[DraftSuggestion] = []
    questions: list[DraftQuestion] = []
    operation = _extract_operation(raw_prompt)
    targets = _extract_workspace_targets(raw_prompt)
    environment = _extract_environment(raw_prompt)

    if operation is None:
        questions.append(
            DraftQuestion(
                question_id="operation",
                field="operation",
                prompt="What single operation should the agent perform?",
            )
        )
    else:
        suggestions.append(
            DraftSuggestion(
                field="operation",
                value=operation,
                source="prompt_inference",
            )
        )
    if not targets:
        questions.append(
            DraftQuestion(
                question_id="exact_targets",
                field="exact_targets",
                prompt=(
                    "What exact /workspace path or paths may this task affect?"
                ),
            )
        )
    else:
        suggestions.append(
            DraftSuggestion(
                field="exact_targets",
                value=targets,
                source="prompt_explicit",
            )
        )
    if environment is None:
        questions.append(
            DraftQuestion(
                question_id="environment",
                field="environment",
                prompt="Which environment is this for: sandbox, dev, staging, or production?",
            )
        )
    else:
        suggestions.append(
            DraftSuggestion(
                field="environment",
                value=environment,
                source="prompt_explicit",
            )
        )

    suggestions.extend(
        (
            DraftSuggestion(
                field="allowed_tools",
                value=["shell"],
                source="safe_default",
            ),
            DraftSuggestion(
                field="maximum_scope",
                value="exact",
                source="safe_default",
            ),
            DraftSuggestion(
                field="forbidden_operations",
                value=["credential_access", "network"],
                source="safe_default",
            ),
            DraftSuggestion(
                field="forbidden_effects",
                value=["No credential access or network communication."],
                source="safe_default",
            ),
            DraftSuggestion(
                field="forbidden_effect_codes",
                value=["credential_access", "network"],
                source="safe_default",
            ),
            DraftSuggestion(
                field="expires_in_minutes",
                value=60,
                source="safe_default",
            ),
        )
    )
    if operation is not None:
        suggestions.append(
            DraftSuggestion(
                field="allowed_effects",
                value=[operation],
                source="deterministic_derivation",
            )
        )
        if targets:
            suggestions.append(
                DraftSuggestion(
                    field="expected_side_effects",
                    value=[
                        f"{operation.capitalize()} exactly {target}."
                        for target in targets
                    ],
                    source="deterministic_derivation",
                )
            )
        if operation == "read":
            suggestions.extend(
                (
                    DraftSuggestion(
                        field="rollback_plan",
                        value="No rollback is needed for the reviewed read-only action.",
                        source="deterministic_derivation",
                    ),
                    DraftSuggestion(
                        field="dry_run_required",
                        value=False,
                        source="safe_default",
                    ),
                )
            )
        else:
            questions.extend(
                (
                    DraftQuestion(
                        question_id="rollback_plan",
                        field="rollback_plan",
                        prompt="How should this exact change be rolled back?",
                    ),
                    DraftQuestion(
                        question_id="dry_run_required",
                        field="dry_run_required",
                        prompt="Must the agent complete a dry run before the change?",
                    ),
                )
            )

    return CompiledDraftPreview(
        prompt_sha256=hashlib.sha256(encoded).hexdigest(),
        suggestions=tuple(suggestions),
        questions=tuple(questions),
    )


def _extract_operation(raw_prompt: str) -> str | None:
    matches = [
        operation
        for operation, pattern in _OPERATION_PATTERNS.items()
        if pattern.search(raw_prompt)
    ]
    return matches[0] if len(matches) == 1 else None


def _extract_workspace_targets(raw_prompt: str) -> list[str]:
    targets: list[str] = []
    for match in _ABSOLUTE_PATH.finditer(raw_prompt):
        target = match.group(1).rstrip(".!?")
        if target == "/workspace" or target.startswith("/workspace/"):
            if target not in targets:
                targets.append(target)
    return targets


def _extract_environment(raw_prompt: str) -> str | None:
    matches = [
        environment
        for environment in _ENVIRONMENTS
        if re.search(
            rf"\b{re.escape(environment)}\b",
            raw_prompt,
            re.IGNORECASE,
        )
    ]
    return matches[0] if len(matches) == 1 else None
