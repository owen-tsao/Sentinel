"""Strict canonicalization for the first enforced action family: shell."""

from __future__ import annotations

import shlex
import posixpath

from sentinel.actions.models import CanonicalAction
from sentinel.contracts import ActionOperation, ContractEnvironment

READ_COMMANDS = {
    "cat",
    "df",
    "head",
    "ls",
    "pwd",
    "stat",
    "tail",
    "wc",
}
WRITE_COMMANDS = {"mkdir", "tee", "touch"}
DELETE_COMMANDS = {"rm", "rmdir", "unlink"}
NO_TARGET_COMMANDS = {"pwd"}
IMPLICIT_CWD_COMMANDS = {"ls", "pwd"}
NO_VALUE_LONG_OPTIONS: dict[str, set[str]] = {
    "cat": {"--number", "--number-nonblank", "--show-all", "--show-ends", "--show-tabs", "--squeeze-blank"},
    "df": {"--human-readable", "--inodes", "--local", "--portability", "--total"},
    "head": {"--quiet", "--silent", "--verbose", "--zero-terminated"},
    "ls": {"--all", "--almost-all", "--directory", "--human-readable", "--inode", "--long", "--recursive", "--reverse"},
    "mkdir": {"--parents", "--verbose"},
    "rm": {"--dir", "--force", "--one-file-system", "--recursive", "--verbose"},
    "rmdir": {"--ignore-fail-on-non-empty", "--parents", "--verbose"},
    "stat": {"--dereference", "--file-system", "--terse"},
    "tail": {"--quiet", "--silent", "--verbose", "--zero-terminated"},
    "tee": {"--append", "--ignore-interrupts"},
    "touch": {"--no-create"},
    "wc": {"--bytes", "--chars", "--lines", "--max-line-length", "--words"},
}
SCALAR_LONG_OPTIONS: dict[str, set[str]] = {
    "df": {"--block-size", "--exclude-type", "--output", "--type"},
    "head": {"--bytes", "--lines"},
    "ls": {"--block-size", "--format", "--sort", "--time", "--time-style"},
    "mkdir": {"--mode"},
    "stat": {"--format", "--printf"},
    "tail": {"--bytes", "--lines", "--max-unchanged-stats", "--pid", "--sleep-interval"},
    "touch": {"--date", "--time"},
}
OPTIONAL_SCALAR_LONG_OPTIONS: dict[str, set[str]] = {
    "ls": {"--color"},
}
SHORT_FLAG_OPTIONS: dict[str, set[str]] = {
    "cat": set("AbEnstuvT"),
    "df": set("ahiklmPT"),
    "head": set("qvz"),
    "ls": set("AaCdFhilRrStux1"),
    "mkdir": set("pv"),
    "pwd": set("LP"),
    "rm": set("dfRrv"),
    "rmdir": set("pv"),
    "stat": set("fLt"),
    "tail": set("qvz"),
    "tee": set("ai"),
    "touch": set("c"),
    "wc": set("clmwL"),
}
SCALAR_SHORT_OPTIONS: dict[str, set[str]] = {
    "df": {"B", "t", "x"},
    "head": {"c", "n"},
    "ls": {"T", "w"},
    "mkdir": {"m"},
    "stat": {"c"},
    "tail": {"c", "n", "s"},
    "touch": {"d", "t"},
}
REJECTED_INDIRECT_OPTIONS = {
    "--files0-from",
    "--reference",
    "--file",
    "--follow",
}
SCOPE_EXPANDING_LONG_OPTIONS = {"--parents", "--recursive"}
SUPPORTED_COMMANDS = READ_COMMANDS | WRITE_COMMANDS | DELETE_COMMANDS


class ShellCanonicalizationError(ValueError):
    """A shell command cannot be represented safely as one canonical action."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def canonicalize_shell_action(
    command: str,
    *,
    environment: ContractEnvironment,
    cwd: str = "/workspace",
    environment_context: dict[str, str] | None = None,
    rollback_available: bool = False,
    transaction: bool = False,
    backup_available: bool = False,
) -> CanonicalAction:
    """Parse one direct command and preserve every inspectable path target."""

    if not command.strip() or len(command) > 32_000:
        raise ShellCanonicalizationError("action:invalid_shell_command")
    if _contains_unquoted_control(command):
        raise ShellCanonicalizationError("action:compound_shell_unsupported")
    try:
        tokens = shlex.split(command)
    except ValueError as error:
        raise ShellCanonicalizationError("action:unparseable_shell_command") from error
    if not tokens:
        raise ShellCanonicalizationError("action:invalid_shell_command")
    if "/" in tokens[0] or tokens[0] in {".", ".."}:
        raise ShellCanonicalizationError("action:untrusted_executable_path")

    executable = tokens[0].lower()
    if executable not in SUPPORTED_COMMANDS:
        raise ShellCanonicalizationError("action:unsupported_shell_command")
    operation = _classify_operation(executable, tokens[1:])
    effects = _classify_effects(executable, operation)
    targets = _extract_targets(executable, tokens[1:], cwd)
    if not targets:
        raise ShellCanonicalizationError("action:uninspectable_shell_target")

    dry_run = _has_dry_run(tokens)
    return CanonicalAction(
        family="shell",
        tool="shell",
        operation=operation,
        targets=targets,
        effects=effects,
        environment=environment,
        environment_context=environment_context or {},
        dry_run=dry_run,
        rollback_available=rollback_available,
        transaction=transaction,
        backup_available=backup_available,
        canonical_command=shlex.join(tokens),
        raw_command=command,
    )


def _classify_operation(executable: str, arguments: list[str]) -> ActionOperation:
    if executable in READ_COMMANDS:
        return "read"
    if executable in WRITE_COMMANDS:
        return "write"
    if executable in DELETE_COMMANDS:
        return "delete"
    raise ShellCanonicalizationError("action:unsupported_shell_command")


def _classify_effects(executable: str, operation: ActionOperation) -> set[str]:
    return {operation}


def _extract_targets(executable: str, arguments: list[str], cwd: str) -> list[str]:
    targets: list[str] = []
    end_of_options = False
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if any(character in token for character in "*?$`{}[]"):
            raise ShellCanonicalizationError("action:dynamic_shell_target")
        if token == "--" and not end_of_options:
            end_of_options = True
            index += 1
            continue
        if not end_of_options and token.startswith("--"):
            option, separator, attached_value = token.partition("=")
            if option in SCOPE_EXPANDING_LONG_OPTIONS:
                raise ShellCanonicalizationError(
                    "action:recursive_scope_unsupported"
                )
            if option in REJECTED_INDIRECT_OPTIONS:
                raise ShellCanonicalizationError("action:indirect_shell_target")
            if option in OPTIONAL_SCALAR_LONG_OPTIONS.get(executable, set()):
                if separator:
                    _validate_scalar_option(attached_value)
                index += 1
                continue
            if option in SCALAR_LONG_OPTIONS.get(executable, set()):
                if not separator:
                    index += 1
                    if index >= len(arguments):
                        raise ShellCanonicalizationError("action:missing_option_value")
                    _validate_scalar_option(arguments[index])
                else:
                    _validate_scalar_option(attached_value)
                index += 1
                continue
            if option in NO_VALUE_LONG_OPTIONS.get(executable, set()) and not separator:
                index += 1
                continue
            raise ShellCanonicalizationError("action:unsupported_shell_option")
        if not end_of_options and token.startswith("-") and token != "-":
            short = token[1:]
            if (
                executable in {"mkdir", "rmdir"}
                and "p" in short
                or executable == "rm"
                and any(character in short for character in {"r", "R"})
                or executable == "ls"
                and "R" in short
            ):
                raise ShellCanonicalizationError(
                    "action:recursive_scope_unsupported"
                )
            if token in REJECTED_INDIRECT_OPTIONS:
                raise ShellCanonicalizationError("action:indirect_shell_target")
            scalar_options = SCALAR_SHORT_OPTIONS.get(executable, set())
            if short and short[0] in scalar_options:
                value = short[1:]
                if not value:
                    index += 1
                    if index >= len(arguments):
                        raise ShellCanonicalizationError("action:missing_option_value")
                    value = arguments[index]
                _validate_scalar_option(value)
                index += 1
                continue
            if short and all(character in SHORT_FLAG_OPTIONS.get(executable, set()) for character in short):
                index += 1
                continue
            raise ShellCanonicalizationError("action:unsupported_shell_option")
        if executable in NO_TARGET_COMMANDS:
            raise ShellCanonicalizationError("action:unexpected_shell_argument")
        targets.append(_normalize_path(token, cwd))
        index += 1
    if not targets and executable in IMPLICIT_CWD_COMMANDS:
        targets.append(_normalize_path(".", cwd))
    return sorted(set(targets))


def _validate_scalar_option(value: str) -> None:
    if (
        not value
        or any(character.isspace() for character in value)
        or "://" in value
        or any(character in value for character in "*?$`{}[]")
    ):
        raise ShellCanonicalizationError("action:invalid_option_value")


def _normalize_path(value: str, cwd: str) -> str:
    if not value or any(character.isspace() for character in value):
        raise ShellCanonicalizationError("action:invalid_shell_target")
    if "://" in value:
        raise ShellCanonicalizationError("action:network_requires_structured_action")
    if value.startswith("~"):
        raise ShellCanonicalizationError("action:home_expansion_unsupported")
    candidate = value if value.startswith("/") else posixpath.join(cwd, value)
    normalized = posixpath.normpath(candidate)
    if not normalized.startswith("/"):
        raise ShellCanonicalizationError("action:invalid_shell_target")
    return normalized


def _has_dry_run(tokens: list[str]) -> bool:
    # None of the deliberately small supported-command set has portable,
    # trustworthy dry-run semantics. A future adapter may set this only after
    # canonicalizing a command family that does.
    return False


def _contains_unquoted_control(command: str) -> bool:
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
