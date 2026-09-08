#!/usr/bin/env python3
"""Dependency-free Cursor hook adapter for the Sentinel integration spike.

The hook keeps only a derived action contract in a private temporary directory;
it never persists raw prompts or tool inputs. Cursor invokes a fresh process for
each event, so contracts are correlated by conversation and generation IDs.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from sentinel.decision.rules import evaluate_command  # noqa: E402


STATE_ROOT = Path(tempfile.gettempdir()) / "sentinel-cursor-hook-v1"
AUDIT_PATH = STATE_ROOT / "audit.jsonl"
MAX_INSPECTED_TEXT = 100_000

ENVIRONMENT_PATTERNS = {
    "production": re.compile(r"\b(prod|production|live)\b", re.IGNORECASE),
    "staging": re.compile(r"\b(staging|stage)\b", re.IGNORECASE),
    "dev": re.compile(r"\b(dev|development)\b", re.IGNORECASE),
    "sandbox": re.compile(r"\b(local|sandbox|test|testing)\b", re.IGNORECASE),
}

SENSITIVE_RESOURCE_PATTERN = re.compile(
    r"\b(database|db|table|schema|cluster|namespace|bucket|infrastructure|"
    r"terraform|kubernetes|k8s|aws|gcp|azure|credential|secret|api[ _-]?key|"
    r"main branch|master branch|customer data|backups?|volume|production)\b",
    re.IGNORECASE,
)
HIGH_IMPACT_ACTION_PATTERN = re.compile(
    r"\b(delete|drop|truncate|wipe|destroy|remove|reset|migrate|deploy|apply|"
    r"rotate|revoke|grant|force[ -]?push|clean up|cleanup|prune)\b",
    re.IGNORECASE,
)
EXPLICIT_OPERATION_PATTERN = re.compile(
    r"\b(delete|drop|truncate|destroy|migrate|deploy|apply|rotate|revoke|grant|"
    r"force[ -]?push|prune)\b",
    re.IGNORECASE,
)
VAGUE_OPERATION_PATTERN = re.compile(
    r"\b(clean up|cleanup|fix|handle|take care of|sort out|reset)\b",
    re.IGNORECASE,
)
READ_ONLY_INTENT_PATTERN = re.compile(
    r"\b(inspect|list|show|summarize|review|preview|diagnose|find|search|"
    r"report|dry[ -]?run|without changing|without applying|read[ -]?only)\b",
    re.IGNORECASE,
)
DIRECT_ACTION_REQUEST_PATTERN = re.compile(
    r"(?:^\s*(?:please\s+)?(?:delete|drop|truncate|wipe|destroy|remove|reset|"
    r"deploy|migrate|apply|rotate|revoke|grant|prune|clean up|cleanup)\b)|"
    r"(?:\b(?:can|could|would) you (?:please\s+)?(?:delete|drop|truncate|wipe|"
    r"destroy|remove|reset|deploy|migrate|apply|rotate|revoke|grant|prune|"
    r"clean up|cleanup)\b)|"
    r"(?:\b(?:i need you to|go ahead(?: and)?|run|execute|perform|make the change|"
    r"apply the change|force[ -]?push)\b)",
    re.IGNORECASE,
)
ROLLBACK_PATTERN = re.compile(
    r"\b(backup|snapshot|rollback|restore|transaction|dry[ -]?run|preview)\b",
    re.IGNORECASE,
)

TARGET_PATTERN = re.compile(
    r"\b(database|db|table|schema|cluster|namespace|bucket|service|branch|"
    r"volume)\s+(?:named\s+)?[`'\"]?([A-Za-z0-9_./:@-]+)",
    re.IGNORECASE,
)
TARGET_FLAG_PATTERN = re.compile(
    r"--(?:database|db|table|schema|cluster|context|namespace|project|bucket|"
    r"service|branch)(?:=|\s+)([A-Za-z0-9_./:@-]+)",
    re.IGNORECASE,
)
GENERIC_TARGET_WORDS = {
    "a",
    "all",
    "an",
    "current",
    "database",
    "dev",
    "development",
    "it",
    "local",
    "old",
    "production",
    "sandbox",
    "stage",
    "staging",
    "test",
    "that",
    "the",
    "this",
    "unused",
}

HIGH_IMPACT_COMMAND_PATTERN = re.compile(
    r"\b(rm\s+-rf|drop(?:db|\s+(?:database|table|schema))|truncate\s+table|"
    r"delete\s+from|terraform\s+(?:apply|destroy)|kubectl\s+(?:apply|delete)|"
    r"aws\s+\S+\s+(?:delete|rm)|git\s+push\s+--force|git\s+reset\s+--hard|"
    r"docker\s+system\s+prune|alembic\s+upgrade|psql\b.*\b(?:drop|delete|truncate))\b",
    re.IGNORECASE | re.DOTALL,
)
ROOT_DELETION_PATTERN = re.compile(r"""\brm\s+-rf\s+/(?:[\s'";]|$)""", re.IGNORECASE)
DROP_DATABASE_PATTERN = re.compile(r"\bdrop\s+database\b|\bdropdb\b", re.IGNORECASE)
UNQUALIFIED_DELETE_PATTERN = re.compile(
    r"\bdelete\s+from\s+[A-Za-z0-9_.\"`-]+\s*(?:;|$)",
    re.IGNORECASE | re.MULTILINE,
)
CREDENTIAL_EXPOSURE_PATTERN = re.compile(
    r"(?:cat|base64).*(?:\.env|\.aws/credentials|id_rsa|\.pem).*(?:curl|wget|"
    r"nc|scp|https?://)",
    re.IGNORECASE | re.DOTALL,
)
SHELL_METACHARACTER_PATTERN = re.compile(r"[;&|<>`\n]|\$\(")
READ_ONLY_MCP_PREFIXES = {"fetch", "get", "health", "inspect", "list", "read", "search", "snapshot", "view"}
MUTATING_MCP_TOKENS = {
    "apply",
    "click",
    "create",
    "delete",
    "deploy",
    "destroy",
    "drop",
    "edit",
    "execute",
    "fill",
    "grant",
    "merge",
    "modify",
    "move",
    "patch",
    "press",
    "prune",
    "purge",
    "remove",
    "replace",
    "reset",
    "revoke",
    "run",
    "save",
    "send",
    "set",
    "terminate",
    "truncate",
    "type",
    "update",
    "upload",
    "write",
}


def assess_prompt(prompt: str) -> dict[str, Any]:
    """Return a derived action contract or focused missing-field list."""
    compact = " ".join(prompt.split())
    high_impact = bool(
        HIGH_IMPACT_ACTION_PATTERN.search(compact)
        and SENSITIVE_RESOURCE_PATTERN.search(compact)
    )
    action_request = bool(DIRECT_ACTION_REQUEST_PATTERN.search(compact))

    if not (high_impact and action_request):
        return {
            "requires_clarification": False,
            "high_impact": False,
            "contract": _build_contract(compact),
        }

    environment = _infer_environment(compact)
    target = _extract_target(compact)
    missing: list[str] = []

    if environment == "unknown":
        missing.append("environment (local/dev/staging/production)")
    if target is None:
        missing.append("exact target (database, table, cluster, bucket, or branch name)")
    if VAGUE_OPERATION_PATTERN.search(compact) and not EXPLICIT_OPERATION_PATTERN.search(compact):
        missing.append("exact operation and intended scope")
    if environment == "production" and _is_irreversible(compact) and not ROLLBACK_PATTERN.search(compact):
        missing.append("dry-run, transaction, backup, or rollback requirement")

    return {
        "requires_clarification": bool(missing),
        "high_impact": True,
        "missing": missing,
        "contract": _build_contract(compact, environment=environment, target=target),
    }


def handle_before_submit_prompt(payload: dict[str, Any], state_root: Path = STATE_ROOT) -> dict[str, Any]:
    prompt = str(payload.get("prompt", ""))
    if not prompt.strip():
        return {
            "continue": False,
            "user_message": "Sentinel could not inspect an empty prompt. Please describe the intended action.",
        }

    assessment = assess_prompt(prompt)
    if assessment["requires_clarification"]:
        missing = "\n".join(f"- {field}" for field in assessment["missing"])
        return {
            "continue": False,
            "user_message": (
                "Sentinel paused this high-impact request because its action boundary is ambiguous.\n"
                "Please resend it with:\n"
                f"{missing}\n"
                "Example: “In staging, preview deleting rows older than 90 days from "
                "analytics_staging.session_events; use a transaction and do not commit.”"
            ),
        }

    _write_contract(payload, assessment["contract"], state_root)
    return {"continue": True}


def handle_before_shell_execution(payload: dict[str, Any], state_root: Path = STATE_ROOT) -> dict[str, Any]:
    command = str(payload.get("command", "")).strip()
    if not command:
        return _deny("Sentinel could not inspect an empty shell command.")

    contract = _read_contract(payload, state_root)
    environment = str(contract.get("environment", "unknown"))
    context = str(contract.get("context", "No action contract was recorded for this command."))
    rules_environment = environment if environment != "unknown" else "sandbox"
    decision = evaluate_command(
        context=context,
        command=command,
        environment=rules_environment,
        recent_actions=[],
    )

    if decision.verdict == "block":
        return _deny(f"Sentinel blocked this command: {decision.reason}")

    critical_reason = _critical_payload_reason(command, environment)
    if critical_reason:
        return _deny(f"Sentinel blocked this command: {critical_reason}")

    if decision.verdict == "confirm_required" and decision.reason_code != "unmatched_ambiguous_command":
        return _require_approval(decision.reason, decision.reason_code)

    if decision.verdict == "warn":
        return _require_approval(decision.reason, decision.reason_code)

    if HIGH_IMPACT_COMMAND_PATTERN.search(command):
        if not contract or environment == "unknown":
            return _require_approval(
                "No clear action contract identifies the exact target and environment. "
                "Ask the user to clarify both before retrying.",
                "missing_action_contract",
            )
        return _require_approval(
            "A related action contract exists, but this state-changing action still requires "
            "explicit approval at the execution boundary.",
            "high_impact_execution",
        )

    if not _is_strict_read_only_shell(command):
        return _require_approval(
            "The command is not a single, strictly read-only operation that Sentinel can "
            "verify deterministically.",
            "unclassified_shell_command",
        )
    return {"permission": "allow"}


def handle_pre_tool_use(payload: dict[str, Any], state_root: Path = STATE_ROOT) -> dict[str, Any]:
    tool_name = str(payload.get("tool_name", ""))
    normalized_tool_name = re.sub(r"[_-]+", "", tool_name).lower()
    if _targets_hook_configuration(payload.get("tool_input", {})):
        return _deny(
            "Sentinel blocks agent-driven changes to its active hook configuration and guard code."
        )
    if normalized_tool_name == "delete":
        return _deny("Sentinel blocks file deletion through an unscoped tool call.")
    if normalized_tool_name not in {"write", "edit", "applypatch"}:
        return {"permission": "allow"}

    inspected, truncated = _flatten_text(payload.get("tool_input", {}))
    if truncated:
        return _deny("Sentinel could not inspect the complete file mutation because its input is too large.")
    contract = _read_contract(payload, state_root)
    environment = str(contract.get("environment", "unknown"))
    critical_reason = _critical_payload_reason(inspected, environment)
    if critical_reason:
        return _deny(
            "Sentinel blocked an indirect destructive payload in a file edit: "
            f"{critical_reason} Use a scoped operation with an explicit target and rollback."
        )
    return {"permission": "allow"}


def handle_before_mcp_execution(payload: dict[str, Any], state_root: Path = STATE_ROOT) -> dict[str, Any]:
    tool_name = str(payload.get("tool_name", ""))
    tool_input_text, truncated = _flatten_text(payload.get("tool_input", ""))
    if truncated:
        return _deny("Sentinel could not inspect the complete MCP input because it is too large.")
    inspected = " ".join((tool_name, tool_input_text))
    contract = _read_contract(payload, state_root)
    environment = str(contract.get("environment", "unknown"))

    critical_reason = _critical_payload_reason(inspected, environment)
    if critical_reason:
        return _deny(f"Sentinel blocked this MCP call: {critical_reason}")

    normalized_tool_name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", tool_name)
    normalized_tool_name = re.sub(r"[_-]+", " ", normalized_tool_name).lower()
    tool_tokens = set(normalized_tool_name.split())
    if HIGH_IMPACT_COMMAND_PATTERN.search(inspected) or tool_tokens.intersection(MUTATING_MCP_TOKENS):
        return _require_approval(
            "This MCP tool can mutate external state and requires a separately verified "
            "approval flow that this spike does not yet implement.",
            "high_impact_mcp_call",
        )

    first_token = normalized_tool_name.split(maxsplit=1)[0] if normalized_tool_name else ""
    if first_token not in READ_ONLY_MCP_PREFIXES:
        return _require_approval(
            "This MCP tool is not on Sentinel's explicit read-only allowlist.",
            "unclassified_mcp_tool",
        )
    return {"permission": "allow"}


def handle_event(payload: dict[str, Any], state_root: Path = STATE_ROOT) -> dict[str, Any]:
    event = str(payload.get("hook_event_name", ""))
    if event == "beforeSubmitPrompt":
        return handle_before_submit_prompt(payload, state_root)
    if event == "beforeShellExecution":
        return handle_before_shell_execution(payload, state_root)
    if event == "preToolUse":
        return handle_pre_tool_use(payload, state_root)
    if event == "beforeMCPExecution":
        return handle_before_mcp_execution(payload, state_root)
    return _deny(f"Sentinel received an unsupported hook event: {event or 'missing event name'}.")


def _infer_environment(text: str) -> str:
    for environment, pattern in ENVIRONMENT_PATTERNS.items():
        if pattern.search(text):
            return environment
    return "unknown"


def _extract_target(text: str) -> str | None:
    flag_match = TARGET_FLAG_PATTERN.search(text)
    if flag_match:
        return flag_match.group(1)
    for match in TARGET_PATTERN.finditer(text):
        candidate = match.group(2).strip("`'\"").lower()
        if candidate and candidate not in GENERIC_TARGET_WORDS:
            return candidate
    return None


def _is_irreversible(text: str) -> bool:
    return bool(re.search(r"\b(delete|drop|truncate|wipe|destroy|prune)\b", text, re.IGNORECASE))


def _build_contract(
    prompt: str,
    *,
    environment: str | None = None,
    target: str | None = None,
) -> dict[str, Any]:
    inferred_environment = environment or _infer_environment(prompt)
    inferred_target = target if target is not None else _extract_target(prompt)
    context_parts = ["Cursor user request"]
    if READ_ONLY_INTENT_PATTERN.search(prompt):
        context_parts.append("preview inspect without changing or applying")
    if HIGH_IMPACT_ACTION_PATTERN.search(prompt):
        context_parts.append("high-impact action requested")
    if inferred_environment != "unknown":
        context_parts.append(f"{inferred_environment} environment")
    if inferred_target:
        context_parts.append("exact target specified")
    return {
        "environment": inferred_environment,
        "target_specified": inferred_target is not None,
        "read_only": bool(READ_ONLY_INTENT_PATTERN.search(prompt)),
        "high_impact": bool(HIGH_IMPACT_ACTION_PATTERN.search(prompt)),
        "context": "; ".join(context_parts),
        "created_at": int(time.time()),
    }


def _critical_payload_reason(text: str, environment: str) -> str | None:
    if ROOT_DELETION_PATTERN.search(text):
        return "recursive deletion of the root filesystem is never allowed"
    if CREDENTIAL_EXPOSURE_PATTERN.search(text):
        return "credential material may be sent to an external destination"
    if UNQUALIFIED_DELETE_PATTERN.search(text):
        return "unqualified DELETE can remove every row because it has no WHERE clause"
    if DROP_DATABASE_PATTERN.search(text) and environment == "production":
        return "dropping a production database is never allowed"
    return None


def _is_strict_read_only_shell(command: str) -> bool:
    if SHELL_METACHARACTER_PATTERN.search(command):
        return False
    try:
        arguments = shlex.split(command)
    except ValueError:
        return False
    if not arguments:
        return False

    executable = arguments[0]
    if executable in {"pwd", "id", "whoami"}:
        return len(arguments) == 1
    if executable == "git":
        blocked_options = {"--ext-diff", "--textconv"}
        writes_output = any(
            argument == "--output" or argument.startswith("--output=")
            for argument in arguments[2:]
        )
        return (
            len(arguments) >= 2
            and arguments[1] in {"status", "diff", "log", "show"}
            and not blocked_options.intersection(arguments[2:])
            and not writes_output
        )
    if executable == "rg":
        return "--pre" not in arguments and not any(arg.startswith("--pre=") for arg in arguments)
    if executable == "ls":
        return not any(
            argument == "--recursive"
            or (
                argument.startswith("-")
                and not argument.startswith("--")
                and "R" in argument[1:]
            )
            for argument in arguments[1:]
        )
    return executable in {"cat", "grep", "df", "wc", "which", "ps"}


def _targets_hook_configuration(value: Any) -> bool:
    candidates: list[str] = []

    def collect(item: Any) -> None:
        if isinstance(item, dict):
            for key, nested in item.items():
                if str(key).lower() in {
                    "file",
                    "file_path",
                    "filepath",
                    "path",
                    "target_file",
                    "target_path",
                } and isinstance(nested, str):
                    candidates.append(nested)
                collect(nested)
        elif isinstance(item, (list, tuple)):
            for nested in item:
                collect(nested)
        elif isinstance(item, str):
            candidates.extend(
                re.findall(
                    r"^\*{3} (?:Add|Update|Delete) File:\s*(.+?)\s*$",
                    item,
                    flags=re.MULTILINE,
                )
            )

    collect(value)
    hooks_file = (REPO_ROOT / ".cursor" / "hooks.json").resolve()
    hooks_directory = (REPO_ROOT / ".cursor" / "hooks").resolve()
    for candidate in candidates:
        candidate_path = Path(candidate.strip())
        if not candidate_path.is_absolute():
            candidate_path = REPO_ROOT / candidate_path
        normalized = candidate_path.resolve()
        if normalized == hooks_file or normalized == hooks_directory or hooks_directory in normalized.parents:
            return True
    return False


def _flatten_text(value: Any) -> tuple[str, bool]:
    parts: list[str] = []
    inspected_length = 0

    def visit(item: Any) -> None:
        nonlocal inspected_length
        if inspected_length > MAX_INSPECTED_TEXT:
            return
        if isinstance(item, str):
            parts.append(item)
            inspected_length += len(item)
        elif isinstance(item, dict):
            for key, nested in item.items():
                key_text = str(key)
                parts.append(key_text)
                inspected_length += len(key_text)
                visit(nested)
        elif isinstance(item, (list, tuple)):
            for nested in item:
                visit(nested)
        elif item is not None:
            item_text = str(item)
            parts.append(item_text)
            inspected_length += len(item_text)

    visit(value)
    return "\n".join(parts)[:MAX_INSPECTED_TEXT], inspected_length > MAX_INSPECTED_TEXT


def _state_key(payload: dict[str, Any]) -> str | None:
    conversation_id = str(payload.get("conversation_id", "")).strip()
    generation_id = str(payload.get("generation_id", "")).strip()
    if not conversation_id or not generation_id:
        return None
    raw = f"{conversation_id}\0{generation_id}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _write_contract(payload: dict[str, Any], contract: dict[str, Any], state_root: Path) -> None:
    key = _state_key(payload)
    if key is None:
        return
    state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = state_root / f"{key}.json"
    temporary = state_root / f".{key}.{os.getpid()}.tmp"
    temporary.write_text(json.dumps(contract, sort_keys=True), encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def _read_contract(payload: dict[str, Any], state_root: Path) -> dict[str, Any]:
    key = _state_key(payload)
    if key is None:
        return {}
    path = state_root / f"{key}.json"
    try:
        contract = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    if not isinstance(contract, dict):
        return {}
    created_at = contract.get("created_at")
    if not isinstance(created_at, int) or time.time() - created_at > 86_400:
        try:
            path.unlink()
        except OSError:
            pass
        return {}
    return contract


def _require_approval(reason: str, reason_code: str) -> dict[str, Any]:
    return {
        "permission": "deny",
        "user_message": f"Sentinel review required ({reason_code}): {reason}",
        "agent_message": (
            f"Sentinel denied this action pending a new user turn: {reason} Ask the user "
            "a focused clarification or approval question before proposing a safer retry."
        ),
    }


def _deny(reason: str) -> dict[str, Any]:
    return {
        "permission": "deny",
        "user_message": reason,
        "agent_message": (
            f"{reason} Do not retry through an indirect command or generated script. "
            "Ask the user for a safer, explicitly scoped alternative."
        ),
    }


def _audit_decision(payload: dict[str, Any], response: dict[str, Any]) -> None:
    """Append event identifiers and outcomes; never persist action content."""
    event = str(payload.get("hook_event_name", "unknown"))
    record = {
        "timestamp": int(time.time()),
        "event": event,
        "conversation_hash": _short_hash(payload.get("conversation_id", "")),
        "generation_hash": _short_hash(payload.get("generation_id", "")),
        "outcome": response.get("permission", response.get("continue", "unknown")),
    }
    STATE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    encoded = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(AUDIT_PATH, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, encoded)
    finally:
        os.close(descriptor)


def _short_hash(value: Any) -> str:
    if not isinstance(value, str):
        value = json.dumps(value, sort_keys=True, default=str)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def main() -> int:
    payload: Any = {}
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise ValueError("hook input must be a JSON object")
        response = handle_event(payload)
    except Exception:
        response = {
            "permission": "deny",
            "continue": False,
            "user_message": "Sentinel hook failed closed because it could not inspect the action.",
            "agent_message": "Do not execute the action; ask the user to review it manually.",
        }
    try:
        _audit_decision(payload if isinstance(payload, dict) else {}, response)
    except Exception:
        pass
    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
