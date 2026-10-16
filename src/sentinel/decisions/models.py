"""The decision record: one typed shape for every verdict Sentinel writes.

Design and invariants: docs/Decision Record.md. In short, a record says what
was asked (`ActionDescription`), what it touches (`ResolvedTarget`, one per
affected thing, with a facts block for the surface it lives on) and why the
verdict came out as it did (`Judgment`).

This module imports nothing from the rest of Sentinel except the audience
kind literal, so a per-action hook can import it cheaply.
"""

from __future__ import annotations

import hashlib
import json
import re
from bisect import bisect_left
from typing import Annotated, Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from sentinel.platforms.models import AudienceKind, AudienceSnapshot, ProviderName

SCHEMA_VERSION = 1

Verdict = Literal["allow", "warn", "confirm_required", "block"]
ActionFamily = Literal["shell", "file", "mcp", "git", "database", "cloud", "deployment", "web"]
TargetKind = Literal["read", "write", "delete", "execute", "send", "network"]
Surface = Literal["filesystem", "audience", "resource"]
Zone = Literal[
    "inside",
    "cwd_root",
    "outside",
    "temp",
    "home",
    "root",
    "system",
    "protected_config",
    "credential",
    "host_artifact",
    "dynamic",
]
JudgedBy = Literal["parser", "directory", "literal", "windows_recognizer"]
ParseStatus = Literal["parsed", "unparseable", "not_applicable"]
WorkingDirectorySource = Literal["launch", "hook_payload", "cursor_forwarder", "cursor_workspace_root"]
DecidedBy = Literal["floor", "ceiling", "detector", "model"]
Enforcement = Literal["mandatory", "advisory", "unsupported", "unknown"]
MessageOutcome = Literal["none", "sent", "suppressed_budget"]

SEVERITY: dict[str, int] = {"allow": 0, "warn": 1, "confirm_required": 2, "block": 3}
HISTORY_FACT_PREFIX = "session:"
RAW_MAX_LENGTH = 32_000
HEREDOC_BODY_PLACEHOLDER = "[heredoc body omitted]"
# `<<` not preceded by `<` (so `<<<` here-strings do not match), optional `-`,
# then a delimiter: quoted, or a run of shell-word characters.
_HEREDOC_OPEN_RE = re.compile(r"(?<!<)<<(-?)\s*(?:'([^']+)'|\"([^\"]+)\"|([^\s<>|&;'\"]+))")
_SINGLE_QUOTED_RE = re.compile(r"'[^']*'")
_SCAN_MAX_LENGTH = 1_000_000
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def strip_heredoc_bodies(command: str, *, truncate: bool = True) -> str:
    """Replace every heredoc body with a placeholder; keep everything else.

    The body of a heredoc is data (often a whole file), not the command. The
    operator line (`cat <<EOF > .env | sudo tee x`) says where the data went
    and is evidence, so it stays. Done here, not in writers, so two writers
    cannot diverge.

    Semantics follow bash: the terminator is a whole line equal to the
    delimiter (`<<-` also allows leading tabs); an unterminated heredoc runs
    to the end of input, so everything after its opener line is body. Strip
    first, then truncate: truncating first would cut the terminator off the
    largest heredocs and leave exactly those bodies in place.

    `truncate` caps the result at the audit `raw` field's size. The floor
    passes `truncate=False`: it must judge the whole command, since a
    destructive segment placed after the cap would otherwise be dropped
    before the parser saw it (review finding, October 15).

    Linear: terminator positions are indexed once; each opener does a bisect.
    """
    if truncate and len(command) > _SCAN_MAX_LENGTH:
        command = command[:_SCAN_MAX_LENGTH]
    if "<<" not in command:
        return command[:RAW_MAX_LENGTH] if truncate else command
    lines = command.split("\n")
    exact: dict[str, list[int]] = {}
    tab_stripped: dict[str, list[int]] = {}
    for index, line in enumerate(lines):
        text = line.rstrip("\r")
        exact.setdefault(text, []).append(index)
        tab_stripped.setdefault(text.lstrip("\t"), []).append(index)

    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        # `<<` that begins inside a single-quoted span is text, not an operator
        # (`echo '<<X'`); `<<'EOF'` begins before its quotes and is an operator.
        # Spans are sorted by construction; bisect rather than scan, since a
        # line of 20k quoted openers took 10 s (review finding, October 15).
        quoted = [(m.start(), m.end()) for m in _SINGLE_QUOTED_RE.finditer(line)]
        quoted_starts = [start for start, _ in quoted]
        for match in _HEREDOC_OPEN_RE.finditer(line):
            k = bisect_left(quoted_starts, match.start())
            if k and quoted[k - 1][0] < match.start() < quoted[k - 1][1]:
                continue
            delimiter = match.group(2) or match.group(3) or match.group(4)
            table = tab_stripped if match.group(1) == "-" else exact
            candidates = table.get(delimiter, [])
            k = bisect_left(candidates, i)
            if k == len(candidates):
                out.append(HEREDOC_BODY_PLACEHOLDER)  # unterminated: the rest is body
                i = len(lines)
                break
            end = candidates[k]
            out.append(HEREDOC_BODY_PLACEHOLDER)
            out.append(lines[end])
            i = end + 1
    joined = "\n".join(out)
    return joined[:RAW_MAX_LENGTH] if truncate else joined


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FilesystemFacts(_Strict):
    """Where a path landed after resolution, and how Sentinel knows."""

    resolved: Optional[str] = Field(default=None, max_length=4_096)
    zone: Zone
    judged_by: JudgedBy = "parser"
    note: Optional[str] = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _dynamic_means_unresolved(self) -> "FilesystemFacts":
        if (self.zone == "dynamic") != (self.resolved is None):
            raise ValueError("zone 'dynamic' is used exactly when the path could not be resolved")
        return self


class AudienceFacts(_Strict):
    """Who a send reaches. Counts and flags only; never recipient ids."""

    resource_id: str = Field(..., min_length=1, max_length=1_000)
    canonical_target: str = Field(..., min_length=1, max_length=1_000)
    kind: AudienceKind
    recipient_count: int = Field(..., ge=0, le=100_000)
    external_recipient_count: int = Field(default=0, ge=0, le=100_000)
    guest_recipient_count: int = Field(default=0, ge=0, le=100_000)
    is_public: bool = False
    is_external_shared: bool = False
    is_broadcast: bool = False
    resolution_complete: bool = True

    @model_validator(mode="after")
    def _subsets(self) -> "AudienceFacts":
        if self.external_recipient_count > self.recipient_count:
            raise ValueError("external recipients cannot exceed recipients")
        if self.guest_recipient_count > self.recipient_count:
            raise ValueError("guest recipients cannot exceed recipients")
        return self

    @classmethod
    def from_snapshot(cls, snapshot: AudienceSnapshot) -> "AudienceFacts":
        return cls(
            resource_id=snapshot.resource_id,
            canonical_target=snapshot.canonical_target,
            kind=snapshot.kind,
            recipient_count=snapshot.recipient_count,
            external_recipient_count=len(snapshot.external_recipient_ids),
            guest_recipient_count=len(snapshot.guest_recipient_ids),
            is_public=snapshot.is_public,
            is_external_shared=snapshot.is_external_shared,
            is_broadcast=snapshot.is_broadcast,
            resolution_complete=snapshot.resolution_complete,
        )


class ResourceFacts(_Strict):
    """A provider object that is neither a path nor an audience (an issue, a row)."""

    provider: Optional[ProviderName] = None
    resource_type: str = Field(..., min_length=1, max_length=200)
    resource_id: str = Field(..., min_length=1, max_length=1_000)


class ResolvedTarget(_Strict):
    """One thing the action touches, with the facts for its surface."""

    raw: str = Field(..., min_length=1, max_length=4_096)
    kind: TargetKind
    surface: Surface
    filesystem: Optional[FilesystemFacts] = None
    audience: Optional[AudienceFacts] = None
    resource: Optional[ResourceFacts] = None

    @model_validator(mode="after")
    def _exactly_one_facts_block(self) -> "ResolvedTarget":
        present = {
            name
            for name in ("filesystem", "audience", "resource")
            if getattr(self, name) is not None
        }
        if present != {self.surface}:
            raise ValueError(
                f"target surface {self.surface!r} requires exactly that facts block; got {sorted(present)}"
            )
        return self

    @property
    def zone(self) -> Optional[Zone]:
        return self.filesystem.zone if self.filesystem is not None else None


class ActionDescription(_Strict):
    """What was asked, and what it touches."""

    family: ActionFamily
    host: str = Field(..., min_length=1, max_length=100)
    tool: str = Field(..., min_length=1, max_length=200)
    raw: Optional[str] = Field(default=None, max_length=RAW_MAX_LENGTH)
    payload_sha256: Optional[str] = Field(default=None, max_length=64)
    working_directory: Optional[str] = Field(default=None, max_length=4_096)
    working_directory_source: Optional[WorkingDirectorySource] = None
    parse_status: ParseStatus = "not_applicable"
    opaque: list[Annotated[str, StringConstraints(max_length=200)]] = Field(default_factory=list, max_length=50)
    targets: list[ResolvedTarget] = Field(default_factory=list, max_length=200)

    @field_validator("raw", mode="before")
    @classmethod
    def _strip_heredoc_bodies(cls, value: Any) -> Any:
        if isinstance(value, str):
            return strip_heredoc_bodies(value)
        return value

    @field_validator("payload_sha256")
    @classmethod
    def _sha256_hex(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        lowered = value.lower()
        if not _SHA256_RE.match(lowered):
            raise ValueError("payload_sha256 must be 64 lowercase hex characters")
        return lowered

    @field_validator("opaque")
    @classmethod
    def _opaque_entries(cls, value: list[str]) -> list[str]:
        return [item.strip() for item in value if item.strip()]

    @model_validator(mode="after")
    def _working_directory_has_source(self) -> "ActionDescription":
        if (self.working_directory is None) != (self.working_directory_source is None):
            raise ValueError("working_directory and working_directory_source are set together")
        return self

    @property
    def zones(self) -> list[Zone]:
        seen: dict[str, None] = {}
        for target in self.targets:
            if target.filesystem is not None:
                seen.setdefault(target.filesystem.zone)
        return sorted(seen)  # type: ignore[return-value]


class Judgment(_Strict):
    """Why the verdict came out as it did, in a shape a program can read."""

    verdict: Verdict
    floor_verdict: Optional[Verdict] = None
    decided_by: DecidedBy = "floor"
    rule_id: Optional[str] = Field(default=None, max_length=100)
    ceiling_version: int = Field(..., ge=1)
    enforcement: Enforcement
    reason: str = Field(..., min_length=1, max_length=2_000)
    agent_guidance: Optional[str] = Field(default=None, max_length=2_000)
    history_facts: list[Annotated[str, StringConstraints(max_length=200)]] = Field(default_factory=list, max_length=50)
    approval_reference: Optional[str] = Field(default=None, min_length=1, max_length=200)
    message: MessageOutcome = "none"
    latency_ms: Optional[float] = Field(default=None, ge=0, allow_inf_nan=False)

    @field_validator("rule_id")
    @classmethod
    def _rule_id_has_content(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            raise ValueError("rule_id must not be blank")
        return stripped

    @field_validator("history_facts")
    @classmethod
    def _history_is_server_owned(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item.startswith(HISTORY_FACT_PREFIX) or not item[len(HISTORY_FACT_PREFIX):].strip():
                raise ValueError(
                    f"history facts are server-owned and must start with {HISTORY_FACT_PREFIX!r}"
                )
        return value

    @model_validator(mode="after")
    def _invariants(self) -> "Judgment":
        interrupting = self.verdict in {"block", "confirm_required"}
        if interrupting:
            # A well-behaved agent must be able to recover instead of retrying.
            if not (self.agent_guidance and self.agent_guidance.strip()):
                raise ValueError(f"{self.verdict} requires agent_guidance")
            if self.rule_id is None:
                raise ValueError(f"{self.verdict} requires rule_id")
        if self.approval_reference is not None and self.verdict == "warn":
            raise ValueError("approval_reference is meaningless on a warn")
        if self.decided_by in {"detector", "model"}:
            # Detectors and the inferred boundary may raise warn or confirm,
            # never allow or block, and never without the floor's own verdict.
            if self.floor_verdict is None:
                raise ValueError(f"decided_by={self.decided_by} requires floor_verdict")
            if self.verdict not in {"warn", "confirm_required"}:
                raise ValueError(f"decided_by={self.decided_by} may only produce warn or confirm_required")
        if self.floor_verdict is not None and SEVERITY[self.verdict] < SEVERITY[self.floor_verdict]:
            # The one legitimate downgrade: the floor asked (confirm_required),
            # the person approved, the row is allow. A floor block is never
            # approvable, and a detector or model never lowers anything.
            approved_retry = (
                self.approval_reference is not None
                and self.floor_verdict == "confirm_required"
                and self.verdict == "allow"
                and self.decided_by not in {"detector", "model"}
            )
            if not approved_retry:
                raise ValueError(
                    "a verdict below the floor's is only possible as an approved retry: "
                    "floor confirm_required -> allow with an approval_reference"
                )
        if (
            self.decided_by == "floor"
            and self.floor_verdict is not None
            and self.floor_verdict != self.verdict
            and self.approval_reference is None
        ):
            raise ValueError("a floor decision cannot disagree with its own floor_verdict")
        return self


class DecisionRecord(_Strict):
    schema_version: Literal[1] = SCHEMA_VERSION
    action: ActionDescription
    judgment: Judgment

    @model_validator(mode="after")
    def _unparseable_targets_have_non_parser_provenance(self) -> "DecisionRecord":
        if self.action.parse_status != "unparseable":
            return self
        for target in self.action.targets:
            facts = target.filesystem
            if facts is not None and facts.zone != "dynamic" and facts.judged_by == "parser":
                raise ValueError(
                    "an unparseable command cannot have a parser-resolved target; "
                    "set judged_by to the recognizer that produced it"
                )
        return self

    def canonical_json(self) -> str:
        payload = self.model_dump(mode="json")
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def content_sha256(self) -> str:
        """Hash of the canonical JSON. Writers must hash the redacted record
        (what the store persists), or readers will never reproduce it."""
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


__all__ = [
    "SCHEMA_VERSION",
    "SEVERITY",
    "HISTORY_FACT_PREFIX",
    "ActionDescription",
    "ActionFamily",
    "AudienceFacts",
    "DecidedBy",
    "DecisionRecord",
    "Enforcement",
    "FilesystemFacts",
    "JudgedBy",
    "Judgment",
    "MessageOutcome",
    "ParseStatus",
    "ResolvedTarget",
    "ResourceFacts",
    "Surface",
    "TargetKind",
    "Verdict",
    "WorkingDirectorySource",
    "Zone",
]
