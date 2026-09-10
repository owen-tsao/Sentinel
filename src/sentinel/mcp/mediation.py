"""Server-side canonicalization and deterministic decision for MCP fixture calls.

Nothing here trusts the caller. The tool name and raw arguments are turned
into a `CanonicalAction` that names every target, effect, and the exact
payload hash, then intersected with the startup ceiling and the active
contract. The result is composed from those two existing authorities; this
module is not a second policy engine.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

from sentinel.actions.models import CanonicalAction
from sentinel.decision.contract_policy import ContractMatchResult
from sentinel.supervision import CeilingDecision

McpVerdict = Literal["allow", "confirm_required", "block"]

TOOL_SPECS: dict[str, dict[str, Any]] = {
    "sentinel_issue_read": {
        "operation": "issue_read",
        "contract_operation": "read",
        "arguments": {"issue_id"},
    },
    "sentinel_issue_add_note": {
        "operation": "issue_add_note",
        "contract_operation": "write",
        "arguments": {"issue_id", "body"},
    },
}
MAX_ISSUE_ID_LENGTH = 64


class McpCanonicalizationError(ValueError):
    def __init__(self, reason_code: str, reason: str) -> None:
        self.reason_code = reason_code
        self.reason = reason
        super().__init__(reason_code)


@dataclass(frozen=True)
class McpActionFacts:
    tool: str
    operation: str
    contract_operation: str
    issue_id: str
    note_body: str | None
    note_bytes: int
    action: CanonicalAction

    def describe(self) -> str:
        if self.note_body is None:
            return f"{self.tool} {self.issue_id}"
        return f"{self.tool} {self.issue_id} {json.dumps(self.note_body, ensure_ascii=False)}"


def canonicalize_mcp_call(tool: str, arguments: dict[str, Any], *, environment: str) -> McpActionFacts:
    """Turn untrusted tool arguments into one complete canonical action or fail closed."""

    spec = TOOL_SPECS.get(tool)
    if spec is None:
        raise McpCanonicalizationError("mcp:unsupported_tool", "Sentinel does not mediate this tool.")
    if not isinstance(arguments, dict):
        raise McpCanonicalizationError("mcp:arguments_invalid", "Arguments must be an object.")
    expected: set[str] = spec["arguments"]
    if set(arguments) != expected:
        raise McpCanonicalizationError(
            "mcp:unknown_argument",
            f"{tool} accepts exactly {sorted(expected)}; received {sorted(arguments)}.",
        )
    issue_id = arguments["issue_id"]
    if not isinstance(issue_id, str) or not issue_id or len(issue_id) > MAX_ISSUE_ID_LENGTH:
        raise McpCanonicalizationError("mcp:issue_id_invalid", "issue_id must be a short non-empty string.")
    if issue_id != issue_id.strip() or any(ch.isspace() for ch in issue_id):
        raise McpCanonicalizationError("mcp:issue_id_invalid", "issue_id must not contain whitespace.")
    note_body: str | None = None
    payload_sha256: str | None = None
    if "body" in expected:
        body = arguments["body"]
        if not isinstance(body, str) or not body.strip():
            raise McpCanonicalizationError("mcp:note_body_invalid", "body must be a non-empty string.")
        note_body = body
        payload_sha256 = hashlib.sha256(body.encode("utf-8")).hexdigest()
    action = CanonicalAction(
        family="mcp",
        tool=tool,
        operation=spec["contract_operation"],
        targets=[issue_id],
        effects={spec["contract_operation"]},
        environment=environment,  # type: ignore[arg-type]
        payload_sha256=payload_sha256,
        canonical_command=f"{tool} {issue_id}",
    )
    return McpActionFacts(
        tool=tool,
        operation=spec["operation"],
        contract_operation=spec["contract_operation"],
        issue_id=issue_id,
        note_body=note_body,
        note_bytes=len(note_body.encode("utf-8")) if note_body is not None else 0,
        action=action,
    )


@dataclass(frozen=True)
class McpDecision:
    verdict: McpVerdict
    reason_code: str
    reason: str
    reason_codes: tuple[str, ...]
    guidance: str


def decide_mcp_action(ceiling: CeilingDecision, match: ContractMatchResult | None) -> McpDecision:
    """Compose the ceiling and the active-contract match. Ceiling first, then contract."""

    if ceiling.verdict == "forbidden":
        return McpDecision(
            "block", ceiling.reason_code, ceiling.reason, (ceiling.reason_code,),
            "This operation is outside the startup guardrails; no task can authorize it. Ask the user.",
        )
    if match is None:
        return McpDecision(
            "block", "contract:not_found", "No active task authorizes this action.", ("contract:not_found",),
            "Ask the user to activate a task for this fixture in the Sentinel control center, then retry.",
        )
    if not match.matches:
        return McpDecision(
            "block", match.reason_codes[0] if match.reason_codes else "contract:mismatch",
            "The action is outside the active task boundary.", tuple(match.reason_codes),
            "Stay within the active task's issues and operations, or ask the user to widen the task.",
        )
    if ceiling.verdict == "confirm_required":
        return McpDecision(
            "confirm_required", ceiling.reason_code, ceiling.reason, (ceiling.reason_code,),
            "Ask the user to approve this exact action in the Sentinel control center, then retry unchanged.",
        )
    return McpDecision(
        "allow", "mcp:matching_read", "The action is within the ceiling and the active task.", (),
        "",
    )
