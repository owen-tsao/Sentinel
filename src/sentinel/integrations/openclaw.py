"""Legacy advisory preflight for OpenClaw-shaped tool calls.

This spike deliberately does not invoke OpenClaw or execute tools. It translates
a proposed call, checks deterministic critical rules, and then compares the call
with a reviewed ActionContract. It is not exported as a production integration
and does not provide provider-side enforcement.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Mapping, Optional

from pydantic import BaseModel, Field, ValidationError

from sentinel.contracts import ActionContract, ActionOperation, InMemoryAcceptedContractStore
from sentinel.decision.rules import RuleDecision, evaluate_command

ContractPreflightStatus = Literal["not_required", "complete", "needs_clarification"]
GuardVerdict = Literal["allow", "warn", "confirm_required", "block"]

SHELL_TOOLS = {"bash", "exec", "process", "run", "shell"}
READ_TOOLS = {"read", "file_read"}
WRITE_TOOLS = {"write", "file_write", "edit", "file_edit"}
DELETE_TOOLS = {"delete", "file_delete", "remove"}
NETWORK_TOOLS = {"web_fetch", "fetch", "http_request", "browser"}
EXTERNAL_COMMUNICATION_TOOLS = {"send_message", "send_email", "notify", "slack"}
KNOWN_TOOLS = (
    SHELL_TOOLS
    | READ_TOOLS
    | WRITE_TOOLS
    | DELETE_TOOLS
    | NETWORK_TOOLS
    | EXTERNAL_COMMUNICATION_TOOLS
)

READ_ONLY_SHELL_COMMANDS = {
    "cat",
    "df",
    "du",
    "env",
    "find",
    "git",
    "grep",
    "head",
    "id",
    "ls",
    "printenv",
    "pwd",
    "rg",
    "sed",
    "stat",
    "test",
    "tail",
    "wc",
    "which",
    "whoami",
}
WRITE_SHELL_COMMANDS = {"cp", "mkdir", "mv", "tee", "touch"}
DELETE_SHELL_COMMANDS = {"rm", "rmdir", "unlink"}
NETWORK_SHELL_COMMANDS = {"curl", "ftp", "nc", "scp", "ssh", "wget"}
EXTERNAL_COMMUNICATION_TOKENS = {"notify", "send_email", "send_message", "slack"}
SENSITIVE_TARGET_PATTERN = re.compile(
    r"(^|/)(\.aws|\.env|\.gnupg|\.netrc|\.ssh)(/|$)|authorization|credential|token|secret|password|api[_-]?key|id_rsa|\.pem$",
    re.IGNORECASE,
)
PATH_TOKEN_PATTERN = re.compile(r"^(?:/|\.{1,2}/|~/)")
URL_PATTERN = re.compile(r"^https?://", re.IGNORECASE)
SHELL_CONTROL_PATTERN = re.compile(r"(?:&&|\|\||[;&|<>`\n\r]|\$\(|\$\{|\\\n)")
GLOB_PATTERN = re.compile(r"[*?\[]")
TRUSTED_WORKSPACE_ROOT = "/workspace"


class OpenClawToolCall(BaseModel):
    """Minimal OpenClaw tool-call envelope accepted by the spike."""

    name: str = Field(..., min_length=1, max_length=200)
    arguments: dict[str, Any] = Field(default_factory=dict)
    call_id: Optional[str] = Field(default=None, max_length=500)


class OpenClawGuardDecision(BaseModel):
    """Sentinel decision returned before any external tool is invoked."""

    verdict: GuardVerdict
    preflight_status: ContractPreflightStatus
    reason_codes: list[str]
    agent_message: str
    clarification_questions: list[str] = Field(default_factory=list)
    normalized_tool: str
    operations: set[ActionOperation] = Field(default_factory=set)
    targets: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class _NormalizedAction:
    tool: str
    operations: frozenset[ActionOperation]
    targets: tuple[str, ...]
    policy_command: str


def guard_openclaw_call(
    *,
    call: OpenClawToolCall | Mapping[str, Any],
    accepted_contract_id: str | None,
    contract_store: InMemoryAcceptedContractStore | None = None,
    recent_actions: list[dict[str, Any]] | None = None,
) -> OpenClawGuardDecision:
    """Evaluate an OpenClaw-shaped call without executing it."""

    try:
        if isinstance(call, OpenClawToolCall):
            if hasattr(call, "model_dump"):
                call_payload = call.model_dump(mode="python", warnings=False)
            else:
                call_payload = call.dict()
        else:
            call_payload = dict(call)
        parsed_call = OpenClawToolCall(**call_payload)
    except (TypeError, ValidationError):
        return _decision(
            verdict="block",
            status="needs_clarification",
            reasons=["adapter:malformed_call"],
            message="Sentinel blocked a malformed tool-call envelope.",
            tool="unknown",
        )

    record = contract_store.resolve(accepted_contract_id) if contract_store and accepted_contract_id else None
    accepted_contract = record.contract if record else None

    raw_command = _raw_shell_command(parsed_call)
    if raw_command:
        critical = evaluate_command(
            context=accepted_contract.objective if accepted_contract else "The user has not accepted an exact action contract.",
            command=raw_command,
            environment=accepted_contract.environment if accepted_contract else "sandbox",
            recent_actions=recent_actions or [],
        )
        if critical.verdict == "block":
            raw_action = _NormalizedAction(
                tool=_normalize_tool_name(parsed_call.name) or "unknown",
                operations=frozenset(),
                targets=(),
                policy_command=raw_command,
            )
            return _from_rule(critical, raw_action, status="not_required")

    normalized, normalization_error = _normalize_action(parsed_call, TRUSTED_WORKSPACE_ROOT)
    if normalization_error or normalized is None:
        return _decision(
            verdict="block",
            status="needs_clarification",
            reasons=[normalization_error or "adapter:uninspectable_action"],
            message="Sentinel blocked an unclassified or uninspectable tool call. Use a supported tool with explicit arguments.",
            tool=_normalize_tool_name(parsed_call.name),
        )

    rule_decision = evaluate_command(
        context=accepted_contract.objective if accepted_contract else "The user has not accepted an exact action contract.",
        command=normalized.policy_command,
        environment=accepted_contract.environment if accepted_contract else "sandbox",
        recent_actions=recent_actions or [],
    )
    if rule_decision.verdict == "block":
        return _from_rule(rule_decision, normalized, status="not_required")

    needs_contract = _requires_contract(normalized, TRUSTED_WORKSPACE_ROOT)
    if accepted_contract_id is None:
        if needs_contract:
            return _decision(
                verdict="confirm_required",
                status="needs_clarification",
                reasons=["contract:missing"],
                message="Sentinel needs an accepted action contract before this tool call can proceed.",
                questions=_missing_contract_questions(),
                action=normalized,
            )
        return _finish_rule_evaluation(rule_decision, normalized, contract_authorized=False)

    if accepted_contract is None:
        return _decision(
            verdict="confirm_required",
            status="needs_clarification",
            reasons=["contract:not_accepted"],
            message="Sentinel could not resolve this contract from the trusted acceptance store.",
            questions=["Ask the user to review and accept a fresh action contract through the separate approval path."],
            action=normalized,
        )

    if _is_expired(accepted_contract):
        return _decision(
            verdict="confirm_required",
            status="needs_clarification",
            reasons=["contract:expired"],
            message="The accepted action contract has expired. Ask the user to review a fresh contract.",
            questions=["Should Sentinel create a new contract with a fresh expiry for this exact action?"],
            action=normalized,
        )

    violation = _contract_violation(accepted_contract, normalized)
    if violation:
        return _decision(
            verdict="block",
            status="complete",
            reasons=[violation],
            message="Sentinel blocked this call because it exceeds the accepted action contract. Do not retry without a newly reviewed contract.",
            action=normalized,
        )

    if accepted_contract.dry_run_required and _is_mutating(normalized) and not _has_dry_run_evidence(normalized):
        return _decision(
            verdict="confirm_required",
            status="needs_clarification",
            reasons=["contract:dry_run_obligation_unsatisfied"],
            message="The contract requires a dry run, but this action would mutate state directly.",
            questions=["What non-mutating preview or dry-run command should run first?"],
            action=normalized,
        )

    final_decision = _finish_rule_evaluation(rule_decision, normalized, contract_authorized=True)
    if final_decision.verdict in {"allow", "warn"}:
        consumed = contract_store.consume(accepted_contract_id) if contract_store and accepted_contract_id else None
        if consumed is None:
            return _decision(
                verdict="confirm_required",
                status="needs_clarification",
                reasons=["contract:not_accepted"],
                message="The accepted contract was already used or is no longer available.",
                questions=["Ask the user to review and accept a fresh action contract."],
                action=normalized,
            )
    return final_decision


def _normalize_action(call: OpenClawToolCall, workspace_root: str) -> tuple[_NormalizedAction | None, str | None]:
    tool = _normalize_tool_name(call.name)
    if not tool or tool not in KNOWN_TOOLS:
        return None, "adapter:unknown_tool"

    if tool in SHELL_TOOLS:
        command = call.arguments.get("command", call.arguments.get("cmd"))
        if not isinstance(command, str) or not command.strip() or len(command) > 32_000:
            return None, "adapter:invalid_shell_command"
        cwd = call.arguments.get("cwd")
        if cwd is not None:
            if not isinstance(cwd, str) or Path(cwd).expanduser().resolve(strict=False) != Path(workspace_root).resolve(strict=False):
                return None, "adapter:cwd_overstep"
        if SHELL_CONTROL_PATTERN.search(command):
            return None, "adapter:compound_or_indirect_shell"
        try:
            operations = _classify_shell_operations(command)
            targets = _extract_shell_targets(command, workspace_root)
        except ValueError:
            return None, "adapter:unparseable_shell_command"
        if "network" in operations:
            return None, "adapter:network_shell_requires_structured_tool"
        if operations.difference({"read"}) and not targets:
            return None, "adapter:uninspectable_shell_target"
        return _NormalizedAction(tool, frozenset(operations), tuple(targets), command), None

    targets = _extract_explicit_targets(call.arguments)
    if not targets:
        return None, "adapter:missing_target"

    if tool in READ_TOOLS:
        operations: set[ActionOperation] = {"read"}
        policy_command = f"cat {shlex.quote(targets[0])}"
    elif tool in WRITE_TOOLS:
        operations = {"write"}
        policy_command = f"write {shlex.quote(targets[0])}"
    elif tool in DELETE_TOOLS:
        operations = {"delete"}
        policy_command = f"rm {shlex.quote(targets[0])}"
    elif tool in NETWORK_TOOLS:
        operations = {"network"}
        method = str(call.arguments.get("method", "GET")).upper()
        if method not in {"GET", "HEAD"}:
            operations.add("external_communication")
        if method == "DELETE":
            operations.add("delete")
        if _has_opaque_outbound_payload(call.arguments) or _payload_mentions_sensitive_material(call.arguments):
            operations.add("credential_access")
        policy_command = f"curl {shlex.quote(targets[0])}"
    else:
        operations = {"external_communication"}
        if _has_opaque_outbound_payload(call.arguments) or _payload_mentions_sensitive_material(call.arguments):
            operations.add("credential_access")
        policy_command = f"send_message {shlex.quote(targets[0])}"

    if any(SENSITIVE_TARGET_PATTERN.search(target) for target in targets):
        operations.add("credential_access")
    return _NormalizedAction(tool, frozenset(operations), tuple(targets), policy_command), None


def _classify_shell_operations(command: str) -> set[ActionOperation]:
    operations: set[ActionOperation] = set()
    tokens = shlex.split(command)
    if not tokens:
        raise ValueError("empty command")
    if "/" in tokens[0] or tokens[0] in {".", ".."}:
        raise ValueError("executable path is not trusted")
    executable = Path(tokens[0]).name.lower()
    if executable in READ_ONLY_SHELL_COMMANDS:
        operations.add("read")
    elif executable in WRITE_SHELL_COMMANDS:
        operations.add("write")
    elif executable in DELETE_SHELL_COMMANDS:
        operations.add("delete")
    elif executable in NETWORK_SHELL_COMMANDS:
        operations.add("network")
    else:
        operations.add("execute")

    lowered_tokens = {token.lower() for token in tokens[1:]}
    if executable == "git":
        subcommand = next((token.lower() for token in tokens[1:] if not token.startswith("-")), "")
        if subcommand not in {"diff", "log", "show", "status"}:
            operations.discard("read")
            operations.add("execute")
    if executable == "sed" and any(token == "-i" or token.startswith("-i") for token in tokens[1:]):
        operations.discard("read")
        operations.add("write")
    if executable == "find" and "-delete" in lowered_tokens:
        operations.discard("read")
        operations.add("delete")
    if executable == "find" and any(token in lowered_tokens for token in {"-exec", "-execdir", "-ok", "-okdir"}):
        operations.discard("read")
        operations.add("execute")
    if executable in {"env", "printenv"}:
        operations.add("credential_access")

    lower_command = command.lower()
    if any(token in lower_command for token in EXTERNAL_COMMUNICATION_TOKENS):
        operations.add("external_communication")
    if SENSITIVE_TARGET_PATTERN.search(command):
        operations.add("credential_access")
    return operations or {"execute"}


def _extract_shell_targets(command: str, workspace_root: str) -> list[str]:
    tokens = shlex.split(command)
    if not tokens:
        raise ValueError("empty command")
    targets: list[str] = []
    end_of_options = False
    for token in tokens[1:]:
        cleaned = token.strip("'\"(),")
        if not cleaned:
            continue
        if cleaned == "--" and not end_of_options:
            end_of_options = True
            continue
        if GLOB_PATTERN.search(cleaned) or "$" in cleaned:
            raise ValueError("dynamic target")
        if cleaned.startswith("-") and not end_of_options:
            if "=" in cleaned:
                option_value = cleaned.split("=", 1)[1]
                target = _normalize_target_token(option_value, workspace_root, allow_bare=False)
                if target:
                    targets.append(target)
            continue
        target_token = f"./{cleaned}" if end_of_options and cleaned.startswith("-") else cleaned
        target = _normalize_target_token(target_token, workspace_root, allow_bare=True)
        if target:
            targets.append(target)
    return list(dict.fromkeys(targets))


def _extract_explicit_targets(arguments: Mapping[str, Any]) -> list[str]:
    targets: list[str] = []
    for key in ("path", "file_path", "url", "target", "channel", "recipient"):
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            targets.append(value.strip())
        elif isinstance(value, list):
            targets.extend(item.strip() for item in value if isinstance(item, str) and item.strip())
    return list(dict.fromkeys(targets))


def _normalize_target_token(token: str, workspace_root: str, *, allow_bare: bool) -> str | None:
    if not token or any(character.isspace() for character in token):
        raise ValueError("invalid target token")
    if URL_PATTERN.match(token):
        return token
    if PATH_TOKEN_PATTERN.match(token):
        return str(Path(token).expanduser().resolve(strict=False))
    if allow_bare and not token.startswith("-"):
        return str((Path(workspace_root) / token).resolve(strict=False))
    return None


def _payload_mentions_sensitive_material(value: Any, *, key: str = "") -> bool:
    if SENSITIVE_TARGET_PATTERN.search(key):
        return True
    if isinstance(value, Mapping):
        return any(_payload_mentions_sensitive_material(item, key=str(item_key)) for item_key, item in value.items())
    if isinstance(value, list):
        return any(_payload_mentions_sensitive_material(item, key=key) for item in value)
    if isinstance(value, str):
        return bool(SENSITIVE_TARGET_PATTERN.search(value))
    return False


def _has_opaque_outbound_payload(arguments: Mapping[str, Any]) -> bool:
    for key in ("body", "content", "data", "form", "files", "headers", "json"):
        value = arguments.get(key)
        if value not in (None, "", {}, []):
            return True
    return False


def _requires_contract(action: _NormalizedAction, workspace_root: str) -> bool:
    if action.operations != frozenset({"read"}):
        return True
    return any(not _is_workspace_path(target, workspace_root) for target in action.targets)


def _contract_violation(contract: ActionContract, action: _NormalizedAction) -> str | None:
    allowed_tools = {_normalize_tool_name(tool) for tool in contract.allowed_tools if _normalize_tool_name(tool)}
    if action.tool not in allowed_tools:
        return "contract:tool_overstep"
    if not action.operations.issubset(contract.allowed_operations):
        return "contract:operation_overstep"
    if action.operations.intersection(contract.forbidden_operations):
        return "contract:forbidden_operation"
    if _requires_target_match(action) and not action.targets:
        return "contract:target_uninspectable"
    if any(not _target_allowed(target, contract) for target in action.targets):
        return "contract:target_overstep"
    return None


def _requires_target_match(action: _NormalizedAction) -> bool:
    return bool(action.operations.difference({"read"})) or bool(action.targets)


def _target_allowed(target: str, contract: ActionContract) -> bool:
    for allowed_target in contract.exact_targets:
        if URL_PATTERN.match(target) or URL_PATTERN.match(allowed_target):
            if target == allowed_target:
                return True
            continue

        if not Path(allowed_target).expanduser().is_absolute():
            if contract.maximum_scope == "exact" and target == allowed_target:
                return True
            continue
        normalized_target = Path(target).expanduser().resolve(strict=False)
        normalized_allowed = Path(allowed_target).expanduser().resolve(strict=False)
        if contract.maximum_scope == "exact" and normalized_target == normalized_allowed:
            return True
        if contract.maximum_scope in {"directory", "workspace"} and normalized_target.is_relative_to(normalized_allowed):
            return True
    return False


def _finish_rule_evaluation(
    rule_decision: RuleDecision,
    action: _NormalizedAction,
    *,
    contract_authorized: bool,
) -> OpenClawGuardDecision:
    if rule_decision.verdict == "block":
        return _from_rule(rule_decision, action, status="complete" if contract_authorized else "not_required")
    if rule_decision.verdict == "confirm_required" and rule_decision.reason_code != "unmatched_ambiguous_command":
        return _from_rule(rule_decision, action, status="complete" if contract_authorized else "needs_clarification")
    if rule_decision.verdict == "warn":
        return _from_rule(rule_decision, action, status="complete" if contract_authorized else "not_required")
    if rule_decision.verdict == "allow":
        return _from_rule(rule_decision, action, status="complete" if contract_authorized else "not_required")
    if contract_authorized:
        return _decision(
            verdict="allow",
            status="complete",
            reasons=["contract:explicitly_authorized", f"rule:{rule_decision.reason_code}"],
            message="Sentinel allows this call because its tool, operation, and target match the accepted action contract.",
            action=action,
        )
    return _decision(
        verdict="allow",
        status="not_required",
        reasons=["adapter:recognized_read_only_action", f"rule:{rule_decision.reason_code}"],
        message="Sentinel allows this recognized read-only workspace action.",
        action=action,
    )


def _from_rule(
    rule_decision: RuleDecision,
    action: _NormalizedAction,
    *,
    status: ContractPreflightStatus,
) -> OpenClawGuardDecision:
    messages = {
        "allow": f"Sentinel allows this call. {rule_decision.reason}",
        "warn": f"Sentinel allows this call with a warning. {rule_decision.reason}",
        "confirm_required": f"Sentinel requires confirmation before this call can proceed. {rule_decision.reason}",
        "block": f"Sentinel blocked this call. {rule_decision.reason}",
    }
    return _decision(
        verdict=rule_decision.verdict,
        status=status,
        reasons=[f"rule:{rule_decision.reason_code}"],
        message=messages[rule_decision.verdict],
        action=action,
    )


def _decision(
    *,
    verdict: GuardVerdict,
    status: ContractPreflightStatus,
    reasons: list[str],
    message: str,
    questions: list[str] | None = None,
    action: _NormalizedAction | None = None,
    tool: str = "unknown",
) -> OpenClawGuardDecision:
    return OpenClawGuardDecision(
        verdict=verdict,
        preflight_status=status,
        reason_codes=reasons,
        agent_message=message,
        clarification_questions=questions or [],
        normalized_tool=action.tool if action else tool,
        operations=set(action.operations) if action else set(),
        targets=list(action.targets) if action else [],
    )


def _normalize_tool_name(name: str) -> str:
    normalized = name.strip().lower()
    return normalized if re.fullmatch(r"[a-z][a-z0-9_]*", normalized) else ""


def _is_expired(contract: ActionContract) -> bool:
    expiry = contract.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry <= datetime.now(timezone.utc)


def _is_mutating(action: _NormalizedAction) -> bool:
    return bool(action.operations.intersection({"write", "delete", "execute", "external_communication"}))


def _has_dry_run_evidence(action: _NormalizedAction) -> bool:
    try:
        tokens = [token.lower() for token in shlex.split(action.policy_command)]
    except ValueError:
        return False
    option_tokens = tokens[1 : tokens.index("--")] if "--" in tokens else tokens[1:]
    if any(token in {"--dry-run", "--check"} for token in option_tokens):
        return True
    return len(tokens) >= 2 and tuple(tokens[:2]) in {("terraform", "plan"), ("kubectl", "diff")}


def _is_workspace_path(target: str, workspace_root: str) -> bool:
    if URL_PATTERN.match(target):
        return False
    return Path(target).expanduser().resolve(strict=False).is_relative_to(Path(workspace_root).resolve(strict=False))


def _raw_shell_command(call: OpenClawToolCall) -> str | None:
    if _normalize_tool_name(call.name) not in SHELL_TOOLS:
        return None
    command = call.arguments.get("command", call.arguments.get("cmd"))
    return command if isinstance(command, str) and command.strip() and len(command) <= 32_000 else None


def _missing_contract_questions() -> list[str]:
    return [
        "What exact operation is authorized?",
        "What exact target and maximum scope may the agent touch?",
        "Which side effects are expected or forbidden?",
        "Does the action require a dry run or rollback plan?",
    ]
