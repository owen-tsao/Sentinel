"""The floor for a single absolute path: the file tools.

Claude Code delivers `file_path` already absolute for Write, Edit, and Read,
so there is nothing to parse; the zone function alone decides. The mapping
is docs/Week 16 Plan.md §3.4:

- protected_config -> block (F2 by name, F1 by zone: hook and Sentinel files)
- credential -> block (writing key material is as bad as reading it)
- home carve-outs (shell rc files, `~/.config`, launch agents) -> block
- other home / root / system -> confirm_required
- everything else -> allow

A write tool whose path cannot be resolved is denied, never allowed by the
else branch: an unknown field name must not be a bypass.
"""

from __future__ import annotations


from sentinel.floor.extract import guess_home, home_carve_out, normpath, zone_of
from sentinel.floor.rules import Finding, History


def resolve_tool_path(path: object, home: str) -> str | None:
    """A file-tool path as the normalised absolute path the floor judges, or None.

    Only `/...` and `~...` forms resolve; a relative path has no server-owned
    base here (the host adapter joins relative paths to the launch directory
    before the floor sees them), so it stays unresolved and the caller denies.
    """
    if not path or not isinstance(path, str) or not path.startswith(("/", "~")):
        return None
    if path.startswith("~"):
        path = home + path[1:]
    return normpath(path)


def decide_path(
    path: str | None,
    operation: str,
    *,
    launch_cwd: str,
    home: str | None = None,
    history: History | None = None,
    tool: str = "file tool",
) -> Finding:
    """Judge one file-tool call on an absolute path.

    `operation` is `read`, `write`, or `delete`. `history` is accepted for
    signature parity with `decide_shell`; file-tool verdicts use no history.
    """
    home = home or guess_home(launch_cwd)
    resolved = resolve_tool_path(path, home)
    if resolved is None:
        if operation == "read":
            return Finding("allow", "", "", [])
        return Finding("block", f"F1.{operation}_unresolved", f"{tool} did not provide an absolute path Sentinel can judge; the {operation} cannot be checked, so it is not allowed. Provide a full path.", [str(path or "")])
    zone = zone_of(resolved, launch_cwd, home)

    if operation == "read":
        if zone == "credential":
            # Denied, so nothing leaked: the F4 taint is set by the service
            # only if the host reports this read executed anyway.
            return Finding("block", "F3.credential_read", f"Reads a credential store ({resolved}). Sentinel does not allow agents to read key material; ask the user to provide what is needed.", [resolved])
        # Reading settings is fine: the agent reads its own guardrail (Gate 1).
        return Finding("allow", "", "", [resolved])

    verb = "Destructive operation" if operation == "delete" else "Write"
    if zone == "protected_config":
        return Finding("block", f"F1.{operation}_protected_config", f"{verb} targets a hook or Sentinel configuration file ({resolved}). Hook and supervisor configuration is not the agent's to change; ask the user.", [resolved])
    if zone == "credential":
        return Finding("block", f"F1.{operation}_credential", f"{verb} targets a credential store ({resolved}). Key material is not the agent's to change; ask the user.", [resolved])
    if zone == "host_artifact":
        # The host's own store for the agent's output (plans, canvases): a
        # write is ordinary work; a delete still asks, since the same tree
        # holds the transcripts (Week 18 amendment).
        if operation == "delete":
            return Finding("confirm_required", "F5.destructive_outside", f"{verb} targets {resolved}, inside the host's artefact store. Deleting agent artefacts needs the user.", [resolved])
        return Finding("allow", "", "", [resolved])
    carve = home_carve_out(resolved, home)
    if carve is not None:
        return Finding("block", f"F1.{operation}_home", f"{verb} targets {resolved}, under the home directory in a place that runs code at login or holds tool configuration ({carve}). Ask the user.", [resolved])
    if zone in {"home", "root", "system"}:
        if operation == "delete":
            return Finding("block", f"F1.delete_{zone}", f"{verb} targets {resolved}. Stay inside {launch_cwd} or ask the user.", [resolved])
        return Finding("confirm_required", "F5.write_outside", f"{verb} to {resolved}, outside the working directory ({launch_cwd}).", [resolved])
    if zone == "cwd_root":
        if operation == "delete":
            return Finding("confirm_required", "F5.destructive_cwd_root", f"{verb} to the working directory itself ({resolved}).", [resolved])
        return Finding("allow", "", "", [resolved])
    if zone == "outside":
        rule = "F5.destructive_outside" if operation == "delete" else "F5.write_outside"
        return Finding("confirm_required", rule, f"{verb} to {resolved}, outside the working directory ({launch_cwd}).", [resolved])
    return Finding("allow", "", "", [resolved])
