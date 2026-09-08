"""Documented capability boundary for the Cursor project-hook adapter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

EnforcementStatus = Literal["mandatory", "advisory", "unsupported"]


@dataclass(frozen=True)
class CursorCapability:
    action_family: str
    status: EnforcementStatus
    can_update_authority: bool
    mediated_execution: bool
    limitation: str


CURSOR_CAPABILITY_MATRIX: tuple[CursorCapability, ...] = (
    CursorCapability(
        action_family="prompt",
        status="advisory",
        can_update_authority=False,
        mediated_execution=False,
        limitation="beforeSubmitPrompt has no authenticated direct-user provenance.",
    ),
    CursorCapability(
        action_family="shell",
        status="advisory",
        can_update_authority=False,
        mediated_execution=False,
        limitation=(
            "beforeShellExecution can allow or deny the original host command, "
            "but cannot redirect it through Sentinel's Docker executor."
        ),
    ),
    CursorCapability(
        action_family="file",
        status="advisory",
        can_update_authority=False,
        mediated_execution=False,
        limitation="Project hooks are repository-controlled and do not own the file write path.",
    ),
    CursorCapability(
        action_family="mcp",
        status="advisory",
        can_update_authority=False,
        mediated_execution=False,
        limitation="The hook can gate Cursor's call but does not own every provider-side action path.",
    ),
    CursorCapability(
        action_family="subagent",
        status="unsupported",
        can_update_authority=False,
        mediated_execution=False,
        limitation="No task-authority enforcement path is implemented for subagents.",
    ),
)


def cursor_authority_boundary_passes() -> bool:
    """Return whether Cursor currently has a mandatory mediated action family."""

    return any(
        capability.status == "mandatory" and capability.mediated_execution
        for capability in CURSOR_CAPABILITY_MATRIX
    )
