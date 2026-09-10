"""Host-neutral records for agent connections, adapter sessions, and coverage.

Coverage is reported per action family and never summarised as "protected".
The adapter session bearer identifies the adapter kind and binds calls to the
one supervision session; it is not proof of provenance (Week 12 Phase 0).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

CoverageStatus = Literal["mandatory", "advisory", "unsupported", "unavailable"]
ConnectionStatus = Literal["never_connected", "connected", "disconnected"]


@dataclass(frozen=True)
class ActionFamilyCoverage:
    """One measured action family and the honest status Sentinel can claim."""

    family: str
    status: CoverageStatus
    basis: str
    conditions: tuple[str, ...] = ()
    known_bypasses: tuple[str, ...] = ()


@dataclass(frozen=True)
class CapabilityProfile:
    """Measured coverage for one host, fixed from recorded evidence."""

    host: str
    measured_on: str
    host_version: str
    families: tuple[ActionFamilyCoverage, ...]

    def family(self, name: str) -> ActionFamilyCoverage | None:
        for entry in self.families:
            if entry.family == name:
                return entry
        return None


@dataclass(frozen=True)
class AdapterSession:
    """One process-lifetime binding between an adapter and the supervision session."""

    adapter_session_id: str
    adapter_kind: str
    tool_family: str
    supervision_session_id: str
    capability_sha256: str
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None

    def is_active(self, now: datetime) -> bool:
        return self.revoked_at is None and now < self.expires_at


@dataclass(frozen=True)
class IssuedAdapterCapability:
    """Returned exactly once to the trusted launcher; never stored in clear."""

    capability: str
    session: AdapterSession


@dataclass
class AgentConnection:
    """Observed connection state for one host, derived from authenticated calls."""

    host: str
    status: ConnectionStatus = "never_connected"
    last_seen_at: datetime | None = None
    last_tool: str | None = None
    last_verdict: str | None = None
    mediated_calls: int = 0
    rejected_calls: int = 0
    notes: list[str] = field(default_factory=list)


CURSOR_WEEK12_PROFILE = CapabilityProfile(
    host="cursor",
    measured_on="2026-09-09",
    host_version="3.19.19 (macOS 26.6)",
    families=(
        ActionFamilyCoverage(
            family="sentinel_issue_fixture",
            status="mandatory",
            basis="Week 12 Phase 0 live run and harness: every effect passed through Sentinel; fail closed when unavailable.",
            conditions=(
                "Cursor agent sandbox enabled",
                "Sentinel hooks profile installed with failClosed",
                "no out-of-sandbox escalation approved for Sentinel paths",
            ),
            known_bypasses=(
                "same-user agent can read Sentinel state and capabilities (no effect possible)",
            ),
        ),
        ActionFamilyCoverage(
            family="shell",
            status="advisory",
            basis="beforeShellExecution can deny by command text but cannot redirect execution into Sentinel.",
            known_bypasses=("path or command obfuscation defeats string matching",),
        ),
        ActionFamilyCoverage(
            family="file_edit",
            status="advisory",
            basis="preToolUse can deny Write/Delete on protected paths; content classification is not enforced.",
        ),
        ActionFamilyCoverage(
            family="prompt",
            status="advisory",
            basis="beforeSubmitPrompt carries no authenticated direct-user provenance.",
        ),
        ActionFamilyCoverage(
            family="other_mcp_servers",
            status="unsupported",
            basis="Only the declared fixture family is mediated; other servers are not routed through Sentinel.",
        ),
        ActionFamilyCoverage(
            family="browser",
            status="unsupported",
            basis="Hook coverage of the browser tool is undocumented and untested.",
        ),
        ActionFamilyCoverage(
            family="network",
            status="unsupported",
            basis="Sandbox network allowlist is a Cursor setting Sentinel cannot verify.",
        ),
        ActionFamilyCoverage(
            family="subagents",
            status="unsupported",
            basis="Whether hooks fire inside subagents is undocumented and untested.",
        ),
    ),
)
