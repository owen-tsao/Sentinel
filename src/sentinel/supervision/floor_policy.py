"""Ceiling v2 for hook hosts: the floor policy.

The Week 12 `SupervisionPolicy` is the ceiling for the MCP fixture tool
family. Hook hosts have no tool family and no issue ids; what they need fixed
before startup is the environment each launch directory counts as, which
floor rules are live, which MCP server sources are trusted, how the hook must
be configured for Sentinel to claim enforcement, and how often detectors may
speak. Those are this object. Like the v1 ceiling it is frozen, hashed, and
bound to the state database so a weaker policy cannot be introduced by
editing configuration and restarting.

What this policy can never do: disable a floor rule. A rule may be set to
`log_only` for diagnosis, except the protected families (F1-F4 and the
supervisor-disable rule), and even then the row is still written with the
floor's real verdict.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from sentinel.floor.rules import ALL_RULES, PROTECTED_RULES

FLOOR_POLICY_VERSION = 2
Environment = Literal["dev", "sandbox", "staging", "production"]
ENVIRONMENTS = frozenset({"dev", "sandbox", "staging", "production"})
NEVER_LOG_ONLY = frozenset({"F2.supervisor_disable"})
DEFAULT_HOOK_TOOLS = frozenset({
    "Bash", "PowerShell", "Write", "Edit", "MultiEdit", "NotebookEdit", "Read", "Grep", "Glob",
    "WebFetch", "WebSearch", "mcp__.*",
})
DEFAULT_MCP_SOURCES = frozenset({"user", "project", "local", "plugin", "sdk", "managed", "enterprise"})


class FloorPolicyError(RuntimeError):
    def __init__(self, reason_code: str, detail: str = "") -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code}: {detail}" if detail else reason_code)


@dataclass(frozen=True)
class HookExpectations:
    """What the managed settings must say for Sentinel to claim `mandatory`."""

    server_url: str = "http://127.0.0.1:8000/hooks/claude-code/pre-tool-use"
    tools: frozenset[str] = DEFAULT_HOOK_TOOLS
    max_timeout_seconds: int = 10
    min_claude_version: tuple[int, int, int] = (2, 1, 295)


@dataclass(frozen=True)
class FloorPolicy:
    version: int = FLOOR_POLICY_VERSION
    default_environment: str = "dev"
    # launch directory -> environment. Longest matching prefix wins.
    environments: dict[str, str] = field(default_factory=dict)
    log_only_rules: frozenset[str] = frozenset()
    accepted_mcp_sources: frozenset[str] = DEFAULT_MCP_SOURCES
    message_budget_per_boundary: int = 3
    hook: HookExpectations = field(default_factory=HookExpectations)
    # Permission modes in which the host does not render a hook `ask`; a
    # confirm is delivered as a deny with guidance there (plan §3.3 fallback).
    ask_fallback_modes: frozenset[str] = frozenset()
    sentinel_port: int = 8000

    def __post_init__(self) -> None:
        if self.version != FLOOR_POLICY_VERSION:
            raise FloorPolicyError("floor_policy:unsupported_version", str(self.version))
        if self.default_environment not in ENVIRONMENTS:
            raise FloorPolicyError("floor_policy:unsupported_environment", self.default_environment)
        for directory, environment in self.environments.items():
            if not directory.startswith("/") or posixpath.normpath(directory) != directory:
                raise FloorPolicyError("floor_policy:environment_path_not_normalized", directory)
            if environment not in ENVIRONMENTS:
                raise FloorPolicyError("floor_policy:unsupported_environment", environment)
        known = set(ALL_RULES)
        for rule in self.log_only_rules:
            if rule not in known:
                raise FloorPolicyError("floor_policy:unknown_rule", rule)
            if rule.split(".")[0] in PROTECTED_RULES or rule in NEVER_LOG_ONLY:
                raise FloorPolicyError("floor_policy:protected_rule_cannot_be_log_only", rule)
        if not (0 <= self.message_budget_per_boundary <= 100):
            raise FloorPolicyError("floor_policy:invalid_budget", str(self.message_budget_per_boundary))
        if not re.fullmatch(r"http://127\.0\.0\.1:\d{2,5}/hooks/claude-code/pre-tool-use", self.hook.server_url):
            raise FloorPolicyError("floor_policy:hook_url_not_loopback", self.hook.server_url)
        if not (1 <= self.hook.max_timeout_seconds <= 60):
            raise FloorPolicyError("floor_policy:invalid_hook_timeout", str(self.hook.max_timeout_seconds))
        if not (1 <= self.sentinel_port <= 65535):
            raise FloorPolicyError("floor_policy:invalid_port", str(self.sentinel_port))

    def environment_for(self, launch_cwd: str) -> str:
        best = ""
        chosen = self.default_environment
        normalized = posixpath.normpath(launch_cwd)
        for directory, environment in self.environments.items():
            if (normalized == directory or normalized.startswith(directory.rstrip("/") + "/")) and len(directory) > len(best):
                best, chosen = directory, environment
        return chosen

    def is_log_only(self, rule_id: str | None) -> bool:
        return bool(rule_id) and rule_id in self.log_only_rules

    def canonical_json(self) -> str:
        payload = {
            "version": self.version,
            "default_environment": self.default_environment,
            "environments": dict(sorted(self.environments.items())),
            "log_only_rules": sorted(self.log_only_rules),
            "accepted_mcp_sources": sorted(self.accepted_mcp_sources),
            "message_budget_per_boundary": self.message_budget_per_boundary,
            "hook": {
                "server_url": self.hook.server_url,
                "tools": sorted(self.hook.tools),
                "max_timeout_seconds": self.hook.max_timeout_seconds,
                "min_claude_version": list(self.hook.min_claude_version),
            },
            "ask_fallback_modes": sorted(self.ask_fallback_modes),
            "sentinel_port": self.sentinel_port,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


class SQLiteFloorPolicyStore:
    """Bind the floor policy's hash to the state database.

    The first process writes the hash; later processes must present the same
    policy. A database that carries only the Week 12 contract-model binding
    (`supervision_policy_binding`) and no floor binding is a v1 state file;
    it is refused with a message naming the file, because the two models do
    not share state and silently reusing the file would mix them.
    """

    def __init__(self, database: str | Path, *, timeout_seconds: float = 5.0) -> None:
        self._path = str(database)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self._path, timeout=timeout_seconds, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(f"PRAGMA busy_timeout={int(timeout_seconds * 1_000)}")
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS floor_policy_binding (
                    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                    version INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    canonical_json TEXT NOT NULL,
                    first_bound_at TEXT NOT NULL
                )
                """
            )

    def _is_v1_database(self) -> bool:
        has_v1 = self._connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='supervision_policy_binding'"
        ).fetchone()
        if has_v1 is None:
            return False
        bound_v1 = self._connection.execute("SELECT 1 FROM supervision_policy_binding WHERE singleton_id = 1").fetchone()
        bound_v2 = self._connection.execute("SELECT 1 FROM floor_policy_binding WHERE singleton_id = 1").fetchone()
        return bound_v1 is not None and bound_v2 is None

    def bind(self, policy: FloorPolicy) -> str:
        from datetime import datetime, timezone

        with self._lock:
            if self._is_v1_database():
                raise FloorPolicyError(
                    "floor_policy:v1_state_database",
                    f"{self._path} holds a Week 12 contract-model binding and no floor policy. "
                    f"Archive it (mv {self._path} {self._path}.v1) and start again; v1 state is not migrated.",
                )
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT version, content_sha256 FROM floor_policy_binding WHERE singleton_id = 1"
                ).fetchone()
                if row is None:
                    self._connection.execute(
                        "INSERT INTO floor_policy_binding (singleton_id, version, content_sha256, canonical_json, first_bound_at) "
                        "VALUES (1, ?, ?, ?, ?)",
                        (policy.version, policy.content_sha256, policy.canonical_json(),
                         datetime.now(timezone.utc).isoformat(timespec="microseconds")),
                    )
                elif row["version"] != policy.version or row["content_sha256"] != policy.content_sha256:
                    raise FloorPolicyError(
                        "floor_policy:binding_mismatch",
                        f"{self._path} was bound to floor policy {row['content_sha256'][:12]} (v{row['version']}); "
                        f"this process presents {policy.content_sha256[:12]} (v{policy.version}). "
                        "Start with the same policy or archive the state file.",
                    )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
            return policy.content_sha256

    def close(self) -> None:
        with self._lock:
            self._connection.close()


__all__ = [
    "DEFAULT_HOOK_TOOLS",
    "ENVIRONMENTS",
    "FLOOR_POLICY_VERSION",
    "FloorPolicy",
    "FloorPolicyError",
    "HookExpectations",
    "SQLiteFloorPolicyStore",
]
