"""Server-side state for one Claude Code session.

The host's `session_id` is the key. What a session holds is small: the launch
directory (the boundary default), where it came from, the environment, the
enforcement claim, server-owned history facts, and the settings snapshots
`ConfigChange` compares against.

Who may set the launch directory, and how, is the security property here
(plan §3.6): the first host-authored `PreToolUse` or the `SessionStart` hook
creates it; afterwards a `SessionStart` report may only narrow it. A forged
report, or a nested `claude -p` started from `/`, cannot widen what counts
as "inside".
"""

from __future__ import annotations

import posixpath
import threading
import time
from collections import OrderedDict, deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from sentinel.audit.base import AuditStore
from sentinel.audit.models import AuditQuery
from sentinel.detectors.stuck import StuckState
from sentinel.floor.rules import History
from sentinel.hosts.claude_code.settings_check import EnforcementReport

MAX_SESSIONS = 2_000
MAX_REMEMBERED_TOOL_USES = 2_000
ADVISORY_MESSAGE_BUDGET = 2
# The budget is a rate, not a lifetime count (Week 18, gate C-H5): a Cursor
# boundary is the workspace root for as long as the conversation lives, so a
# budget that only refilled on narrowing went permanently silent after two
# messages. Two messages in any rolling window of this length instead.
ADVISORY_MESSAGE_WINDOW_SECONDS = 30 * 60
MAX_CAUTIONED_TARGETS = 500


@dataclass
class Boundary:
    """The advisory boundary (docs/Week 17 Plan.md §3.4, amended Week 18):
    the launch directory and its environment for the life of the session. A
    prompt never moves it; a folder a prompt names is a per-prompt focus hint
    carried on the context line and the row, not here. The floor never reads
    this."""

    root: str
    environment: str
    source: str = "default"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def containing_repository(path: str) -> str:
    """The nearest ancestor (or the path itself) holding a `.git`; else the path."""
    current = Path(posixpath.normpath(path))
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return str(candidate)
    return str(current)


def _epoch(stamp: Any) -> float:
    """Row timestamps as epoch seconds; a naive datetime is taken as UTC, which
    is how the store writes them. Anything unreadable counts as "now" so a
    bad row can only make the budget stricter, never looser."""
    if isinstance(stamp, datetime):
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        return stamp.timestamp()
    if isinstance(stamp, str):
        try:
            return _epoch(datetime.fromisoformat(stamp.replace("Z", "+00:00")))
        except ValueError:
            pass
    return time.time()


@dataclass
class HookSession:
    session_id: str
    launch_cwd: str
    working_directory_source: str  # launch | hook_payload | cursor_forwarder | cursor_workspace_root
    environment: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    permission_mode: Optional[str] = None
    claude_version: Optional[str] = None
    history: History = field(default_factory=History)
    enforcement: Optional[EnforcementReport] = None
    enforcement_checked_at: Optional[datetime] = None
    seen_pre_tool_use: bool = False
    config_snapshots: dict[str, Optional[dict[str, Any]]] = field(default_factory=dict)
    web_hosts_seen: set[str] = field(default_factory=set)
    pre_tool_use_ids: deque[str] = field(default_factory=lambda: deque(maxlen=MAX_REMEMBERED_TOOL_USES))
    # Ids judged by *this process*. Unlike `pre_tool_use_ids` this is never
    # rebuilt from rows: a held ask lives only in memory, so a call judged
    # before a restart must be re-judged on the enforcing event rather than
    # treated as "already answered" (review finding, October 15).
    judged_ids: deque[str] = field(default_factory=lambda: deque(maxlen=MAX_REMEMBERED_TOOL_USES))
    asked_tool_use_ids: deque[str] = field(default_factory=lambda: deque(maxlen=MAX_REMEMBERED_TOOL_USES))
    # Calls the floor denied as credential reads. If the host later reports
    # one of these *executed* (deny not honoured, or hook timed out), the F4
    # taint is set from that moment (Week 18 amendment).
    credential_read_tool_use_ids: deque[str] = field(default_factory=lambda: deque(maxlen=MAX_REMEMBERED_TOOL_USES))
    messages_sent: int = 0
    # Week 17 advisory layer. None until first read so the default can be built from launch facts.
    boundary: Optional[Boundary] = None
    stuck: StuckState = field(default_factory=StuckState)
    cautioned_targets: set[str] = field(default_factory=set)     # sha256 of realpaths, or "env:<name>"
    advisory_messages_sent: int = 0                               # lifetime count under this boundary (audit rows)
    advisory_message_times: list[float] = field(default_factory=list)   # epoch seconds; decides the budget
    last_pre_seq: int = 0
    widening_rejected_logged: bool = False
    # Week 18 (spike C2): on hosts where the judging event cannot ask the
    # person, the confirm is held here by tool_use_id until the host's
    # ask-capable event for the same call arrives. Bounded like the id rings.
    pending_asks: dict[str, str] = field(default_factory=dict)

    def defer_ask(self, tool_use_id: str, user_message: str) -> None:
        self.pending_asks[tool_use_id] = user_message
        while len(self.pending_asks) > MAX_REMEMBERED_TOOL_USES:
            self.pending_asks.pop(next(iter(self.pending_asks)))

    def take_ask(self, tool_use_id: Optional[str]) -> Optional[str]:
        """The held confirm for this call, removed so it is delivered once."""
        if tool_use_id is None:
            return None
        return self.pending_asks.pop(tool_use_id, None)

    def current_boundary(self) -> Boundary:
        """The registry builds the boundary when the session is created, so
        this is a read in normal operation; the fallback only covers sessions
        constructed directly in tests."""
        if self.boundary is None:
            self.boundary = Boundary(root=self.launch_cwd, environment=self.environment)
        return self.boundary

    def reset_advisory_budget(self) -> None:
        self.advisory_messages_sent = 0
        self.advisory_message_times.clear()

    def advisory_budget_left(self, now: Optional[float] = None) -> bool:
        """True while fewer than `ADVISORY_MESSAGE_BUDGET` person-facing
        messages were sent in the last `ADVISORY_MESSAGE_WINDOW_SECONDS`."""
        cutoff = (time.time() if now is None else now) - ADVISORY_MESSAGE_WINDOW_SECONDS
        self.advisory_message_times = [t for t in self.advisory_message_times if t > cutoff]
        return len(self.advisory_message_times) < ADVISORY_MESSAGE_BUDGET

    def spend_advisory_message(self, now: Optional[float] = None) -> None:
        self.advisory_messages_sent += 1
        self.advisory_message_times.append(time.time() if now is None else now)

    def remember_caution(self, key: str) -> bool:
        """True if this target has not been cautioned under the current boundary."""
        if key in self.cautioned_targets:
            return False
        if len(self.cautioned_targets) < MAX_CAUTIONED_TARGETS:
            self.cautioned_targets.add(key)   # at the cap: still caution, just stop remembering
        return True

    def narrow_launch_cwd(self, candidate: str, *, source: str = "launch",
                          environment_for: Optional[Callable[[str], str]] = None) -> bool:
        """Accept `candidate` only if it is inside (or equal to) the current
        launch directory. Returns whether it was applied. `source` names who
        supplied it (`launch`, or the Cursor forwarder's two sources).

        The environment is re-derived from the narrowed directory when
        `environment_for` is given (review B1): a session created from a wide
        first event (`/`, or a parent of a production repo) must not keep
        `dev` once the launch directory narrows into the production tree.
        `environment_for` is longest-prefix, so re-deriving on a narrow is
        itself monotonic."""
        normalized = posixpath.normpath(candidate)
        current = posixpath.normpath(self.launch_cwd)
        if normalized == current:
            self.working_directory_source = source
            return True
        if normalized.startswith(current.rstrip("/") + "/"):
            self.launch_cwd = normalized
            self.working_directory_source = source
            if environment_for is not None:
                new_environment = environment_for(normalized)
                if new_environment != self.environment:
                    self.environment = new_environment
                    if self.boundary is not None:
                        self.boundary.environment = new_environment
            # The advisory boundary must never sit outside the floor's launch
            # directory. If the launch narrowed past it, re-anchor (review #7).
            if self.boundary is not None and not (self.boundary.root == normalized
                                                   or self.boundary.root.startswith(normalized + "/")):
                self.boundary = Boundary(root=normalized, environment=self.environment)
                self.stuck.reset()
                self.cautioned_targets.clear()
                self.reset_advisory_budget()
            return True
        return False


class SessionRegistry:
    """Bounded, lock-protected map of live sessions with per-session locks."""

    def __init__(self, *, audit_store: Optional[AuditStore] = None, max_sessions: int = MAX_SESSIONS,
                 host: str = "claude_code") -> None:
        self.host = host
        self._guard = threading.Lock()
        self._sessions: OrderedDict[str, HookSession] = OrderedDict()
        self._locks: dict[str, tuple[threading.RLock, int]] = {}
        self._audit_store = audit_store
        self._max = max_sessions

    def get(self, session_id: str) -> Optional[HookSession]:
        with self._guard:
            session = self._sessions.get(session_id)
            if session is not None:
                self._sessions.move_to_end(session_id)
            return session

    def ensure(self, session_id: str, *, launch_cwd: str, source: str, environment: str,
               environment_for: Optional[Callable[[str], str]] = None) -> HookSession:
        """Return the session, creating it from these facts if unknown. A
        session first seen after a server restart is rebuilt from its rows;
        `environment_for` re-derives the environment from the launch directory
        the rows record, since the one the caller derived came from whatever
        cwd this process happens to see now."""
        with self._guard:
            session = self._sessions.get(session_id)
            if session is not None:
                self._sessions.move_to_end(session_id)
                return session
            session = HookSession(session_id=session_id, launch_cwd=posixpath.normpath(launch_cwd),
                                  working_directory_source=source, environment=environment)
            self._rebuild_from_audit(session, environment_for)
            session.current_boundary()   # built under the registry guard, before anyone can read it
            self._sessions[session_id] = session
            while len(self._sessions) > self._max:
                self._sessions.popitem(last=False)
            return session

    def _rebuild_from_audit(self, session: HookSession, environment_for: Optional[Callable[[str], str]] = None) -> None:
        """A session first seen by this process (restart, or evicted and back)
        is rebuilt from its own rows. The rows are server-written, so the
        latest row's launch directory (the boundary in force when the last
        row was written; narrowing is monotonic) is authoritative over the
        cwd this process happens to see now, which the agent may have `cd`'d
        out of."""
        if self._audit_store is None:
            return
        try:
            rows = self._audit_store.query(AuditQuery(session_id=session.session_id, limit=10_000))
        except Exception:  # noqa: BLE001 - a broken store must not stop the hook; the row write will say so
            return
        latest: tuple[int, str, str] | None = None
        counted: list[float] = []   # epoch seconds of every budgeted message; the window ages them out
        for index, row in enumerate(rows):
            details = row.details or {}
            if row.event_type == "boundary" and details.get("host") == self.host:
                if details.get("message_counted"):
                    counted.append(_epoch(row.timestamp))
            elif (row.event_type == "decision" and details.get("host") == self.host
                  and (details.get("detector") or {}).get("message_sent")):
                counted.append(_epoch(row.timestamp))
            # Only a literal True arms the taint: a redacted or malformed value
            # ("[REDACTED]", "true") must not turn every row into a leak.
            if (row.event_type == "post_execution" and details.get("host") == self.host
                    and details.get("credential_read_executed") is True):
                at = _epoch(row.timestamp)
                if session.history.credential_read_at is None or at > session.history.credential_read_at:
                    session.history.credential_read_at = at
            decision = row.decision
            if decision is None or decision.action.host != self.host:
                continue
            if decision.action.working_directory and decision.action.working_directory_source:
                key = row.sequence_id if row.sequence_id is not None else index
                if latest is None or key > latest[0]:
                    latest = (key, decision.action.working_directory, decision.action.working_directory_source)
            if row.request_id:
                session.pre_tool_use_ids.append(row.request_id)
        if latest is not None:
            _, recorded, source = latest
            session.launch_cwd = posixpath.normpath(recorded)
            session.working_directory_source = source
            # The environment follows the launch directory (review B1 for the
            # live narrowing path; this is the restart path). A session whose
            # rows say production must not come back as dev with F8 dormant.
            if environment_for is not None:
                session.environment = environment_for(session.launch_cwd)
        # The budget survives a restart; the stuck ring does not (its in-flight
        # pairs are gone with the process). The budget is rebuilt as timestamps
        # so the rolling window keeps working across the restart.
        session.current_boundary()
        counted.sort()
        session.advisory_messages_sent = len(counted)
        session.advisory_message_times = counted

    @contextmanager
    def lock(self, session_id: str) -> Iterator[None]:
        with self._guard:
            lock, references = self._locks.get(session_id, (threading.RLock(), 0))
            self._locks[session_id] = (lock, references + 1)
        lock.acquire()
        try:
            yield
        finally:
            lock.release()
            with self._guard:
                current, count = self._locks[session_id]
                if count == 1:
                    del self._locks[session_id]
                else:
                    self._locks[session_id] = (current, count - 1)

    def __len__(self) -> int:
        with self._guard:
            return len(self._sessions)
