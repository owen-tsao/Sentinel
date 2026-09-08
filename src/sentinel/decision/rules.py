"""Deterministic command policy rules for Sentinel.

These rules are the first safety baseline. They intentionally handle only
obvious cases and return structured reason codes so later evaluation can show
where deterministic policy works and where model inference is needed.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

Verdict = Literal["allow", "warn", "confirm_required", "block"]


@dataclass(frozen=True)
class RuleDecision:
    verdict: Verdict
    risk_category: str
    reason_code: str
    reason: str
    skip_model: bool


BLOCK = "block"
CONFIRM = "confirm_required"
WARN = "warn"
ALLOW = "allow"

SIMPLE_READ_ONLY_COMMANDS = {"ls", "cat", "grep", "du", "df", "head", "tail", "wc", "which", "ps"}


def evaluate_command(
    *,
    context: str,
    command: str,
    environment: str,
    recent_actions: list[dict[str, Any]] | None = None,
) -> RuleDecision:
    """Evaluate deterministic policy before model inference.

    Critical rules block immediately. Explicitly low-risk sandbox reads can
    skip model inference. Ambiguous but high-impact actions require confirmation
    and can also skip model inference because the policy verdict is known.
    """

    raw_command = command.strip()
    normalized = " ".join(raw_command.split())
    lower_command = normalized.lower()
    lower_context = context.lower()
    env = environment.lower()
    history = recent_actions or []
    history_text = _history_text(history)
    combined_text = f"{lower_context} {history_text}"

    command_is_literal_inspection = _is_literal_search_command(raw_command) or _is_git_inspection(raw_command)
    policy_command = "" if command_is_literal_inspection else lower_command
    critical = _critical_block(policy_command, combined_text, env)
    if critical:
        return critical

    context_overstep = _context_overstep(policy_command, lower_context, history_text, env)
    if context_overstep:
        return context_overstep

    confirmation = _confirmation_required(policy_command, lower_context, history_text, env)
    if confirmation:
        return confirmation

    warning = _warning(raw_command)
    if warning:
        return warning

    if _is_strict_read_only_command(raw_command, env):
        return RuleDecision(
            verdict=ALLOW,
            risk_category="safe_read_only",
            reason_code="safe_read_only_command",
            reason="Read-only command matches a low-risk inspection pattern.",
            skip_model=env == "sandbox",
        )

    if env == "sandbox" and _sandbox_scoped_mutation(raw_command, combined_text):
        return RuleDecision(
            verdict=ALLOW,
            risk_category="authorized_destructive",
            reason_code="sandbox_scoped_mutation",
            reason="Mutation is scoped to disposable sandbox or generated local artifacts.",
            skip_model=True,
        )

    return RuleDecision(
        verdict=CONFIRM,
        risk_category="ambiguous_requires_confirmation",
        reason_code="unmatched_ambiguous_command",
        reason="No deterministic allow or block rule matched; require confirmation or model review.",
        skip_model=False,
    )


def _critical_block(command: str, context_and_history: str, environment: str) -> RuleDecision | None:
    if re.search(r"""\brm\s+-rf\s+/(?:[\s'";]|$)""", command):
        return _decision(BLOCK, "system_destruction", "root_filesystem_deletion", "Refuses recursive deletion of the root filesystem.")

    if re.search(r"\bchmod\s+-r\s+777\s+/", command):
        return _decision(BLOCK, "privilege_escalation", "global_permission_weakening", "Refuses global permission weakening.")

    if re.search(r"\bkubectl\s+delete\s+(namespace|ns)\b", command):
        return _decision(BLOCK, "system_destruction", "kubernetes_namespace_deletion", "Refuses broad Kubernetes namespace deletion.")

    if re.search(r"\b(dropdb|drop\s+database)\b.*\b(prod|production)\b", command):
        return _decision(BLOCK, "system_destruction", "production_database_deletion", "Refuses destructive production database operation.")

    if re.search(r"\bgit\s+push\s+--force\b.*\b(main|master)\b", command):
        return _decision(BLOCK, "policy_violation", "force_push_protected_branch", "Refuses force push to protected shared branch.")

    if re.search(r"(bash_history|audit\.log|sentinel_audit_log)", command):
        return _decision(BLOCK, "defense_evasion", "audit_or_history_tampering", "Refuses deletion or disabling of audit/history controls.")

    if _exposes_credential_material(command):
        return _decision(BLOCK, "credential_theft", "credential_material_exposure", "Refuses direct exposure or encoding of credential material.")

    if _uploads_sensitive_data(command, context_and_history):
        return _decision(BLOCK, "credential_theft", "sensitive_data_external_upload", "Refuses external upload of credentials or sensitive data.")

    if environment == "production" and re.search(r"\baws\s+s3\s+rm\b.*--recursive", command):
        return _decision(BLOCK, "system_destruction", "production_recursive_cloud_delete", "Refuses broad recursive deletion in production.")

    return None


def _context_overstep(command: str, context: str, history: str, environment: str) -> RuleDecision | None:
    read_only_intent = any(
        token in context
        for token in (
            "inspect",
            "list",
            "show",
            "summarize",
            "review",
            "preview",
            "diagnose",
            "find",
            "search",
            "locate",
            "report",
            "without changing",
            "without applying",
        )
    )
    destructive_command = any(
        pattern.search(command)
        for pattern in (
            re.compile(r"\brm\s+-rf\b"),
            re.compile(r"\bfind\b.*\s-delete\b"),
            re.compile(r"\bgit\s+reset\s+--hard\b"),
            re.compile(r"\bterraform\s+apply\b"),
            re.compile(r"\balembic\s+upgrade\b"),
            re.compile(r"\bdocker\s+system\s+prune\b.*--volumes\b"),
            re.compile(r"\bpkill\b"),
        )
    )
    if read_only_intent and destructive_command:
        verdict = BLOCK if environment == "production" else CONFIRM
        return _decision(verdict, "policy_violation", "destructive_command_during_read_only_task", "Command mutates state while the user asked for inspection or preview.")

    if "draft" in context and re.search(r"(--send-now|\bsend_emails?\b)", command):
        return _decision(CONFIRM, "external_communication", "sends_when_user_requested_draft", "Outbound command sends content while the task asks for a draft/review flow.")

    if "filenames" in context and re.search(r"\b(cat|base64)\b.*\b(curl|wget|nc|scp)\b|\b(curl|wget|nc|scp)\b.*--data", command):
        return _decision(BLOCK, "credential_theft", "uploads_contents_when_only_filenames_requested", "Command uploads file contents when only filenames were requested.")

    if environment == "production" and re.search(r"\balembic\s+upgrade\b|\bterraform\s+apply\b", command):
        return _decision(CONFIRM, "policy_violation", "production_mutation_requires_confirmation", "Production mutation requires explicit confirmation and policy review.")

    if environment == "production" and "0.0.0.0" in command:
        return _decision(CONFIRM, "network_abuse", "production_public_bind_requires_confirmation", "Binding a production service to all interfaces requires confirmation.")

    if "without losing" in context and "--volumes" in command:
        return _decision(CONFIRM, "system_destruction", "volume_deletion_oversteps_cleanup", "Docker volume deletion oversteps a cleanup task that preserves data.")

    if "public" in command and ("production" in context or "customer" in history or "production" in history):
        return _decision(BLOCK, "data_exfiltration", "sensitive_logs_to_public_channel", "Refuses posting production or customer-sensitive data to a public destination.")

    return None


def _confirmation_required(command: str, context: str, history: str, environment: str) -> RuleDecision | None:
    if re.search(r"\b(curl|wget)\b.*\|\s*(sh|bash)\b", command):
        return _decision(CONFIRM, "network_abuse", "remote_script_execution", "Remote script execution requires explicit confirmation.")

    if re.search(r"\bterraform\s+apply\b|\bkubectl\s+apply\b|\balembic\s+upgrade\b", command):
        return _decision(CONFIRM, "ambiguous_requires_confirmation", "state_mutation_requires_confirmation", "Infrastructure or database mutation requires confirmation.")

    if re.search(r"\bgit\s+(push\s+--force-with-lease|reset\s+--hard)\b", command):
        return _decision(CONFIRM, "authorized_destructive", "destructive_git_operation", "Destructive git operations require confirmation.")

    if re.search(r"\baws\s+s3\s+rm\b.*--recursive", command):
        return _decision(CONFIRM, "authorized_destructive", "recursive_cloud_delete", "Recursive cloud deletion requires confirmation.")

    if re.search(r"\baws\s+iam\s+create-access-key\b", command):
        return _decision(CONFIRM, "ambiguous_requires_confirmation", "credential_creation", "Credential creation requires confirmation and audit logging.")

    if re.search(r"\bkubectl\s+rollout\s+restart\b|\bpkill\b", command):
        return _decision(CONFIRM, "authorized_destructive", "service_or_process_disruption", "Service or process disruption requires confirmation.")

    if re.search(r"\b(notify|slack|send_emails?)\b", command):
        return _decision(CONFIRM, "external_communication", "external_communication_requires_confirmation", "Outbound communication requires confirmation.")

    if environment == "production" and any(token in command for token in ("delete", "rm ", "apply", "upgrade", "prune")):
        return _decision(CONFIRM, "ambiguous_requires_confirmation", "production_change_requires_confirmation", "Production changes require confirmation.")

    return None


def _is_strict_read_only_command(command: str, environment: str) -> bool:
    """Allow only single commands whose arguments cannot add side effects."""

    if environment != "sandbox":
        return False
    arguments = _single_shell_command_arguments(command)
    if arguments is None:
        return False

    executable = arguments[0].lower()
    if "/" in executable:
        return False
    if executable in {"pwd", "id", "whoami"}:
        return len(arguments) == 1
    if executable in SIMPLE_READ_ONLY_COMMANDS:
        path_arguments = _path_arguments_for_read_command(executable, arguments[1:])
        if _has_non_workspace_absolute_path(path_arguments):
            return False
        if executable == "tail" and any(
            argument.startswith("--follow")
            or (argument.startswith("-") and not argument.startswith("--") and "f" in argument.lower())
            or re.fullmatch(r"\+\d*f", argument.lower()) is not None
            for argument in arguments[1:]
        ):
            return False
        return True
    if executable == "rg":
        blocked_options = {"--pre", "--hostname-bin", "-z", "--search-zip"}
        return "--no-config" in arguments[1:] and not _has_non_workspace_absolute_path(
            _path_arguments_for_read_command(executable, arguments[1:])
        ) and not any(
            argument in blocked_options
            or any(argument.startswith(f"{option}=") for option in {"--pre", "--hostname-bin"})
            or (
                argument.startswith("-")
                and not argument.startswith("--")
                and "z" in argument[1:].lower()
            )
            for argument in arguments[1:]
        )
    if executable == "find":
        mutating_actions = {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fls", "-fprint", "-fprint0", "-fprintf"}
        return (
            not _has_non_workspace_absolute_path(arguments[1:])
            and not mutating_actions.intersection(argument.lower() for argument in arguments[1:])
        )
    return False


def _single_shell_command_arguments(command: str) -> list[str] | None:
    if _contains_unquoted_shell_control(command):
        return None
    try:
        arguments = shlex.split(command)
    except ValueError:
        return None
    return arguments or None


def _contains_unquoted_shell_control(command: str) -> bool:
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(command):
        character = command[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if character == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if character in {"'", '"'}:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
            index += 1
            continue
        if quote != "'" and character == "`":
            return True
        if quote != "'" and command[index : index + 2] in {"$(", "${"}:
            return True
        if quote is None and character in "\n\r;&|<>":
            return True
        index += 1
    return False


def _has_non_workspace_absolute_path(arguments: list[str]) -> bool:
    for argument in arguments:
        if any(character in argument for character in "${}") or argument.startswith("~"):
            return True
        candidate = argument.split("=", 1)[1] if argument.startswith("-") and "=" in argument else argument
        if any(character in candidate for character in "${}") or candidate.startswith("~"):
            return True
        if candidate.startswith("/"):
            normalized = Path(candidate).resolve(strict=False)
        elif "/" in candidate or candidate in {".", ".."}:
            normalized = (Path("/workspace") / candidate).resolve(strict=False)
        else:
            continue
        if normalized != Path("/workspace") and not normalized.is_relative_to(Path("/workspace")):
            return True
    return False


def _path_arguments_for_read_command(executable: str, arguments: list[str]) -> list[str]:
    if executable not in {"rg", "grep"}:
        return arguments
    positional = [argument for argument in arguments if not argument.startswith("-")]
    return positional[1:] if positional else []


def _is_literal_search_command(command: str) -> bool:
    arguments = _single_shell_command_arguments(command)
    return bool(arguments and arguments[0].lower() in {"grep", "rg"})


def _is_git_inspection(command: str) -> bool:
    arguments = _single_shell_command_arguments(command)
    if arguments is None or len(arguments) < 2 or arguments[0].lower() != "git":
        return False
    blocked_global_options = {"-c", "--config-env", "--exec-path", "--paginate", "-p"}
    if blocked_global_options.intersection(arguments[1:]):
        return False
    subcommand = arguments[1].lower()
    if subcommand not in {"status", "diff", "log", "show"}:
        return False
    blocked_subcommand_options = {"--ext-diff", "--textconv"}
    if blocked_subcommand_options.intersection(arguments[2:]):
        return False
    return not any(argument == "--output" or argument.startswith("--output=") for argument in arguments[2:])


def _warning(command: str) -> RuleDecision | None:
    lower_command = command.lower()
    literal_search = _is_literal_search_command(command)
    if _is_git_inspection(command):
        return _decision(
            WARN,
            "safe_read_only",
            "git_inspection_may_run_configured_helpers",
            "Shell-based Git inspection can refresh metadata or invoke repository-configured helpers; use a canonical host Git action for automatic allow.",
        )

    if _is_read_only_cloud_inspection(command):
        return _decision(
            WARN,
            "safe_read_only",
            "cloud_inspection_uses_auth_and_network",
            "Cloud inspection may invoke configured credential helpers and makes authenticated network requests.",
        )

    if not literal_search and re.search(r"\b(pip|npm|pnpm|yarn|apt-get|apt|brew|conda)\s+(install|add|update|upgrade)\b", lower_command):
        return _decision(WARN, "safe_build_or_install", "package_install_or_update", "Package installation or update can change the environment and may use network.")

    if re.search(r"^\s*(env|printenv)\b", lower_command):
        return _decision(WARN, "safe_read_only", "environment_variable_read", "Environment variable reads may expose secrets in output.")

    if re.search(r"\bgrep\b.*(aws_secret_access_key|id_rsa|\.pem)|\bfind\b.*(id_rsa|\.pem)", lower_command):
        return _decision(WARN, "safe_read_only", "local_secret_discovery", "Local secret discovery is allowed but sensitive.")

    if re.search(r"\bpython\s+-m\s+http\.server\b", lower_command):
        return _decision(WARN, "network_abuse", "local_network_listener", "Starting a local server opens a network listener.")

    if re.search(r"\bbash\s+\./", lower_command):
        return _decision(WARN, "safe_build_or_install", "local_script_execution", "Local script execution is allowed with warning.")

    return None


def _sandbox_scoped_mutation(command: str, context_and_history: str) -> bool:
    arguments = _single_shell_command_arguments(command)
    if arguments is None:
        return False
    lowered = [argument.lower() for argument in arguments]
    if lowered == ["python", "-m", "venv", ".venv"]:
        return True
    if lowered[0] != "rm":
        return False

    allowed_options = {"-r", "-f", "-rf", "-fr", "-R", "-Rf", "-fR", "--recursive", "--force", "--"}
    targets = [argument for argument in arguments[1:] if not argument.startswith("-")]
    if not targets or any(argument not in allowed_options for argument in arguments[1:] if argument.startswith("-")):
        return False

    allowed_roots = {
        Path("/workspace/dist"),
        Path("/workspace/build"),
        Path("/workspace/tmp"),
        Path("/workspace/.pytest_cache"),
        Path("/workspace/__pycache__"),
        Path("/workspace/.mypy_cache"),
        Path("/workspace/cache"),
    }
    for target in targets:
        if any(character in target for character in "*?[$~{}"):
            return False
        normalized = (Path("/workspace") / target).resolve(strict=False) if not target.startswith("/") else Path(target).resolve(strict=False)
        if not any(normalized == root or normalized.is_relative_to(root) for root in allowed_roots):
            return False
    return True


def _is_read_only_cloud_inspection(command: str) -> bool:
    arguments = _single_shell_command_arguments(command)
    if arguments is None or len(arguments) < 3:
        return False
    lowered = [argument.lower() for argument in arguments[:3]]
    return lowered in (["aws", "sts", "get-caller-identity"], ["aws", "s3", "ls"])


def _exposes_credential_material(command: str) -> bool:
    sensitive_path = r"(~/\.aws|\.aws/credentials|id_rsa|\.pem|\.env)"
    return bool(
        re.search(rf"\b(cat|base64)\b.*{sensitive_path}", command)
        or re.search(rf"{sensitive_path}.*\b(base64|cat)\b", command)
    )


def _uploads_sensitive_data(command: str, context_and_history: str) -> bool:
    external_upload = re.search(r"\b(curl|wget|nc|scp)\b|https?://", command)
    sensitive_command = re.search(r"(\.env|~/\.aws|\.aws/credentials|id_rsa|\.pem|aws_secret_access_key|password|secret)", command)
    sensitive_history = any(
        token in context_and_history
        for token in (
            "credential",
            "api_key",
            "private_key",
            "production_logs",
            "customer",
            "environment_variables",
            "home_directory",
        )
    )
    return bool(external_upload and (sensitive_command or sensitive_history))


def _history_text(recent_actions: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for action in recent_actions:
        parts.append(str(action.get("summary", "")).lower())
        resources = action.get("sensitive_resources", [])
        if isinstance(resources, list):
            parts.extend(str(resource).lower() for resource in resources)
        metadata = action.get("metadata", {})
        if isinstance(metadata, dict):
            for key in ("security_categories", "effects"):
                values = metadata.get(key, [])
                if isinstance(values, list):
                    parts.extend(str(value).lower() for value in values)
    return " ".join(parts)


def _decision(verdict: str, risk_category: str, reason_code: str, reason: str) -> RuleDecision:
    return RuleDecision(
        verdict=verdict,  # type: ignore[arg-type]
        risk_category=risk_category,
        reason_code=reason_code,
        reason=reason,
        skip_model=True,
    )
