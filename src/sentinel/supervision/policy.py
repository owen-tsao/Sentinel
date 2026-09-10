"""Immutable startup guardrail ceiling for one supervision process.

The ceiling is fixed before the API serves and cannot be edited at runtime.
It restricts what an activated task may authorize for one adapter tool family;
it never activates a task or grants authority by itself. Every mediated action
is intersected with this ceiling before contract and policy evaluation.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Protocol

from sentinel.control.workspace import SupervisionBinding

CeilingVerdict = Literal["ordinary", "confirm_required", "forbidden"]

# Week 12 supports exactly one environment: the disposable local demo.
SUPPORTED_ENVIRONMENTS = frozenset({"sandbox"})
FORBIDDEN_BASELINE = frozenset(
    {
        "issue_delete",
        "network_access",
        "credential_access",
        "command_execution",
        "fixture_admin",
    }
)


class SupervisionPolicyError(RuntimeError):
    """The startup ceiling is invalid or conflicts with durable state."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class CeilingDecision:
    verdict: CeilingVerdict
    reason_code: str
    reason: str


@dataclass(frozen=True)
class SupervisionPolicy:
    """Values fixed before startup; none can be selected by an HTTP request."""

    adapter_kind: str
    tool_family: str
    fixture_project: str
    issue_id_pattern: str
    ordinary_operations: frozenset[str]
    confirm_operations: frozenset[str]
    environment: str = "sandbox"
    max_process_lifetime: timedelta = timedelta(hours=8)
    max_note_bytes: int = 2_000
    forbidden_operations: frozenset[str] = field(default=FORBIDDEN_BASELINE)

    def __post_init__(self) -> None:
        for name in ("adapter_kind", "tool_family", "fixture_project"):
            value = getattr(self, name)
            if not value or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value.lower()):
                raise SupervisionPolicyError(f"supervision:invalid_{name}")
        if self.environment not in SUPPORTED_ENVIRONMENTS:
            raise SupervisionPolicyError("supervision:unsupported_environment")
        if self.max_process_lifetime <= timedelta(0) or self.max_process_lifetime > timedelta(days=1):
            raise SupervisionPolicyError("supervision:invalid_lifetime")
        if self.max_note_bytes <= 0 or self.max_note_bytes > 65_536:
            raise SupervisionPolicyError("supervision:invalid_note_limit")
        if not self.ordinary_operations and not self.confirm_operations:
            raise SupervisionPolicyError("supervision:no_operations")
        if (
            self.ordinary_operations & self.confirm_operations
            or self.ordinary_operations & self.forbidden_operations
            or self.confirm_operations & self.forbidden_operations
        ):
            raise SupervisionPolicyError("supervision:overlapping_operations")
        if not FORBIDDEN_BASELINE <= self.forbidden_operations:
            raise SupervisionPolicyError("supervision:forbidden_baseline_weakened")
        # The pattern must be anchored so a permissive prefix cannot widen scope.
        if not (self.issue_id_pattern.startswith("^") and self.issue_id_pattern.endswith("$")):
            raise SupervisionPolicyError("supervision:issue_pattern_unanchored")
        try:
            compiled = re.compile(self.issue_id_pattern)
        except re.error as exc:
            raise SupervisionPolicyError("supervision:issue_pattern_invalid") from exc
        if compiled.fullmatch("") is not None or compiled.fullmatch("OTHER-1") is not None:
            raise SupervisionPolicyError("supervision:issue_pattern_too_broad")

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    def canonical_json(self) -> str:
        payload = {
            "adapter_kind": self.adapter_kind,
            "tool_family": self.tool_family,
            "fixture_project": self.fixture_project,
            "issue_id_pattern": self.issue_id_pattern,
            "ordinary_operations": sorted(self.ordinary_operations),
            "confirm_operations": sorted(self.confirm_operations),
            "forbidden_operations": sorted(self.forbidden_operations),
            "environment": self.environment,
            "max_process_lifetime_seconds": int(self.max_process_lifetime.total_seconds()),
            "max_note_bytes": self.max_note_bytes,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def issue_in_scope(self, issue_id: str) -> bool:
        return bool(re.compile(self.issue_id_pattern).fullmatch(issue_id))

    def classify(
        self,
        *,
        adapter_kind: str,
        tool_family: str,
        operation: str,
        issue_id: str,
        environment: str,
        note_bytes: int = 0,
    ) -> CeilingDecision:
        """Intersect one canonical action with the ceiling. Never returns allow."""

        if adapter_kind != self.adapter_kind or tool_family != self.tool_family:
            return CeilingDecision("forbidden", "supervision:outside_tool_family",
                                   "This adapter or tool family is outside the startup ceiling.")
        if environment != self.environment:
            return CeilingDecision("forbidden", "supervision:environment_mismatch",
                                   "The action targets an environment the ceiling does not cover.")
        if operation in self.forbidden_operations or operation not in (
            self.ordinary_operations | self.confirm_operations
        ):
            return CeilingDecision("forbidden", "supervision:operation_forbidden",
                                   "The startup ceiling forbids this operation.")
        if not self.issue_in_scope(issue_id):
            return CeilingDecision("forbidden", "supervision:issue_out_of_scope",
                                   "The issue is outside the ceiling's allowed identifiers.")
        if note_bytes > self.max_note_bytes:
            return CeilingDecision("forbidden", "supervision:note_too_large",
                                   "The note exceeds the ceiling's size limit.")
        if operation in self.confirm_operations:
            return CeilingDecision("confirm_required", "supervision:confirm_operation",
                                   "The ceiling requires exact human approval for this operation.")
        return CeilingDecision("ordinary", "supervision:ordinary_operation",
                               "The ceiling permits an active task to authorize this operation.")


@dataclass(frozen=True)
class SupervisionPolicyBinding:
    """The ceiling durably bound to one workspace, session, and process lifetime."""

    policy: SupervisionPolicy
    content_sha256: str
    session_id: str
    workspace_identity_sha256: str
    bound_at: datetime
    expires_at: datetime

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or datetime.now(timezone.utc)) >= self.expires_at


class SupervisionPolicyStore(Protocol):
    def bind(self, policy: SupervisionPolicy, binding: SupervisionBinding) -> SupervisionPolicyBinding:
        ...

    def close(self) -> None:
        ...


def _build_binding(policy: SupervisionPolicy, binding: SupervisionBinding, now: datetime) -> SupervisionPolicyBinding:
    return SupervisionPolicyBinding(
        policy=policy,
        content_sha256=policy.content_sha256,
        session_id=binding.session_id,
        workspace_identity_sha256=binding.workspace.identity_sha256,
        bound_at=now,
        expires_at=now + policy.max_process_lifetime,
    )


class InMemorySupervisionPolicyStore:
    """Process-local binding used only by focused tests."""

    def __init__(self) -> None:
        self._bound: SupervisionPolicyBinding | None = None
        self._lock = threading.Lock()

    def bind(self, policy: SupervisionPolicy, binding: SupervisionBinding) -> SupervisionPolicyBinding:
        with self._lock:
            now = datetime.now(timezone.utc)
            if self._bound is None:
                self._bound = _build_binding(policy, binding, now)
            elif (
                self._bound.content_sha256 != policy.content_sha256
                or self._bound.session_id != binding.session_id
                or self._bound.workspace_identity_sha256 != binding.workspace.identity_sha256
            ):
                raise SupervisionPolicyError("supervision:policy_binding_mismatch")
            return self._bound

    def close(self) -> None:
        return None


class SQLiteSupervisionPolicyStore:
    """Persist the ceiling's content binding beside the workspace binding.

    The first process to bind writes the hash. Every later process must present
    a ceiling with the same hash for the same session and workspace, so a
    weaker ceiling cannot be introduced by editing configuration and restarting.
    """

    def __init__(self, database: str | Path, *, timeout_seconds: float = 5.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(str(database), timeout=timeout_seconds, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(f"PRAGMA busy_timeout={int(timeout_seconds * 1_000)}")
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS supervision_policy_binding (
                    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                    content_sha256 TEXT NOT NULL,
                    canonical_json TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    workspace_identity_sha256 TEXT NOT NULL,
                    first_bound_at TEXT NOT NULL
                )
                """
            )

    def bind(self, policy: SupervisionPolicy, binding: SupervisionBinding) -> SupervisionPolicyBinding:
        with self._lock:
            now = datetime.now(timezone.utc)
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT content_sha256, session_id, workspace_identity_sha256 "
                    "FROM supervision_policy_binding WHERE singleton_id = 1"
                ).fetchone()
                if row is None:
                    self._connection.execute(
                        """
                        INSERT INTO supervision_policy_binding (
                            singleton_id, content_sha256, canonical_json, session_id,
                            workspace_identity_sha256, first_bound_at
                        ) VALUES (1, ?, ?, ?, ?, ?)
                        """,
                        (
                            policy.content_sha256,
                            policy.canonical_json(),
                            binding.session_id,
                            binding.workspace.identity_sha256,
                            now.isoformat(timespec="microseconds"),
                        ),
                    )
                elif (
                    row["content_sha256"] != policy.content_sha256
                    or row["session_id"] != binding.session_id
                    or row["workspace_identity_sha256"] != binding.workspace.identity_sha256
                ):
                    raise SupervisionPolicyError("supervision:policy_binding_mismatch")
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
            return _build_binding(policy, binding, now)

    def close(self) -> None:
        with self._lock:
            self._connection.close()


def week12_fixture_policy(**overrides: object) -> SupervisionPolicy:
    """The one ceiling Week 12 ships: local issue fixture, read ordinary, note confirm."""

    values: dict[str, object] = {
        "adapter_kind": "cursor_mcp",
        "tool_family": "sentinel_issue_fixture",
        "fixture_project": "spike",
        "issue_id_pattern": r"^SPIKE-[1-9][0-9]{0,3}$",
        "ordinary_operations": frozenset({"issue_read"}),
        "confirm_operations": frozenset({"issue_add_note"}),
    }
    values.update(overrides)
    return SupervisionPolicy(**values)  # type: ignore[arg-type]
