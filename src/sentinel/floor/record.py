"""Turn a floor `Finding` into the `DecisionRecord` the audit store persists.

This is the one place the floor's vocabulary meets the audit record's
(docs/Decision Record.md).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from sentinel.decisions import (
    ActionDescription,
    DecisionRecord,
    FilesystemFacts,
    Judgment,
    ResolvedTarget,
    ResourceFacts,
)
from sentinel.floor.rules import Finding, History

KIND = {"delete": "delete", "write": "write", "read": "read", "execute": "execute"}
RESOURCE_TYPES = {
    "F8.schema_change_prod": "database_schema", "F8.infra_destroy": "database",
    "F8.expose_network": "network_listener", "F2.supervisor_disable": "supervisor_process",
    "F2.session_escape": "agent_session",
}


def payload_sha256(tool_input: Any) -> str:
    """Hash the hook's `tool_input` so a record can be matched to the exact call without storing it."""
    canonical = json.dumps(tool_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _targets_for(finding: Finding, zone_hint: str | None = None) -> list[ResolvedTarget]:
    """Build the record's target list from whichever source the floor used.

    Preference order: the extractor's `Report.targets`; failing that, the
    finding's own targets (Windows recognizer, literal fallback, or a
    file-tool path, none of which go through the parser); failing that, a
    resource target for the F2/F8 rules that name no path. Capped at 200.
    """
    targets: list[ResolvedTarget] = []
    report = finding.report
    if report is not None:
        for t in report.targets:
            judged_by = "directory" if "glob" in t.note else "parser"
            targets.append(ResolvedTarget(
                raw=(t.raw or ".")[:4096], kind=KIND.get(t.kind, "write"), surface="filesystem",
                filesystem=FilesystemFacts(resolved=t.resolved, zone=t.zone, judged_by=judged_by, note=(t.note or None) and t.note[:500]),
            ))
    if not targets and finding.targets and finding.rule and not finding.rule.startswith(("F8.", "F2.")):
        # The floor found a target the extractor did not list: the Windows
        # recognizer (pre-parser), the literal fallback (post-parser), or a
        # file-tool path (no parser at all).
        judged_by = "windows_recognizer" if finding.windows else "literal" if finding.literal else "parser"
        for resolved in finding.targets:
            zone = zone_hint or ("root" if "root" in finding.rule else "home" if "home" in finding.rule else
                                 "protected_config" if "protected_config" in finding.rule else
                                 "credential" if "credential" in finding.rule else "outside")
            kind = "read" if "credential_read" in finding.rule else "write" if "write" in finding.rule else "delete"
            targets.append(ResolvedTarget(
                raw=resolved[:4096] or ".", kind=kind, surface="filesystem",
                filesystem=FilesystemFacts(resolved=resolved if finding.windows or judged_by != "literal" else None,
                                           zone=zone if (finding.windows or judged_by != "literal") else "dynamic",
                                           judged_by=judged_by),
            ))
    if not targets and finding.rule in RESOURCE_TYPES:
        resource_type = RESOURCE_TYPES[finding.rule]
        targets.append(ResolvedTarget(
            raw=finding.rule, kind="network" if resource_type == "network_listener" else "execute" if resource_type in {"supervisor_process", "agent_session"} else "write",
            surface="resource", resource=ResourceFacts(resource_type=resource_type, resource_id=resource_type),
        ))
    return targets[:200]


def shell_record(
    finding: Finding,
    host: str = "claude_code",
    *,
    command: str,
    tool: str,
    launch_cwd: str,
    working_directory_source: str,
    environment: str,
    ceiling_version: int,
    enforcement: str,
    history: History,
    tool_input: Any,
    message: str,
    latency_ms: float | None,
    agent_guidance: str | None = None,
) -> DecisionRecord:
    """Record a shell-command verdict. `parse_status` is `unparseable` whenever the parser was bypassed."""
    report = finding.report
    unparseable = finding.windows or finding.literal or (report is not None and report.status == "unparseable")
    return DecisionRecord(
        action=ActionDescription(
            family="shell", host=host, tool=tool, raw=command,
            payload_sha256=payload_sha256(tool_input),
            working_directory=launch_cwd, working_directory_source=working_directory_source,  # type: ignore[arg-type]
            parse_status="unparseable" if unparseable else "parsed",
            opaque=(report.opaque[:50] if report else []), targets=_targets_for(finding),
        ),
        judgment=_judgment(finding, ceiling_version, enforcement, history, message, latency_ms, agent_guidance),
    )


def path_record(
    finding: Finding,
    host: str = "claude_code",
    *,
    family: str,
    tool: str,
    launch_cwd: str,
    working_directory_source: str,
    ceiling_version: int,
    enforcement: str,
    history: History,
    tool_input: Any,
    message: str,
    latency_ms: float | None,
    zone: str | None = None,
    agent_guidance: str | None = None,
) -> DecisionRecord:
    """Record a file-tool or MCP verdict; `zone` labels the target when no parser ran."""
    return DecisionRecord(
        action=ActionDescription(
            family=family, host=host, tool=tool, raw=None,  # type: ignore[arg-type]
            payload_sha256=payload_sha256(tool_input),
            working_directory=launch_cwd, working_directory_source=working_directory_source,  # type: ignore[arg-type]
            parse_status="not_applicable", targets=_targets_for(finding, zone_hint=zone),
        ),
        judgment=_judgment(finding, ceiling_version, enforcement, history, message, latency_ms, agent_guidance),
    )


def _judgment(finding: Finding, ceiling_version: int, enforcement: str, history: History,
              message: str, latency_ms: float | None, agent_guidance: str | None) -> Judgment:
    interrupting = finding.verdict in {"block", "confirm_required"}
    return Judgment(
        verdict=finding.verdict,  # type: ignore[arg-type]
        floor_verdict=finding.verdict,  # type: ignore[arg-type]
        decided_by="floor", rule_id=finding.rule or None, ceiling_version=ceiling_version,
        enforcement=enforcement,  # type: ignore[arg-type]
        reason=(finding.reason or "No floor rule matched.")[:2000],
        agent_guidance=((agent_guidance or finding.reason)[:2000] if interrupting else None),
        history_facts=history.facts(), message=message,  # type: ignore[arg-type]
        latency_ms=latency_ms,
    )
