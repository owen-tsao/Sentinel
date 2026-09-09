"""Fixed startup workspace identity for the protected local control plane."""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol
from uuid import uuid4


class WorkspaceBindingError(RuntimeError):
    """The startup workspace cannot safely use the existing control state."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class ReviewedWorkspace:
    """Canonical, process-fixed identity for one reviewed Git repository."""

    path: Path
    display_name: str
    identity_sha256: str
    device: int
    inode: int


@dataclass(frozen=True)
class SupervisionBinding:
    """The server-owned session durably bound to one workspace identity."""

    session_id: str
    workspace: ReviewedWorkspace
    created_at: datetime


class WorkspaceBindingStore(Protocol):
    def bind(self, workspace: ReviewedWorkspace) -> SupervisionBinding:
        ...

    def close(self) -> None:
        ...


def review_workspace(path: str | Path) -> ReviewedWorkspace:
    """Resolve and fingerprint one repository before the API begins serving."""

    candidate = Path(path).expanduser()
    try:
        canonical = candidate.resolve(strict=True)
    except OSError as exc:
        raise WorkspaceBindingError("control:workspace_unavailable") from exc
    if not canonical.is_dir():
        raise WorkspaceBindingError("control:workspace_not_directory")
    if canonical.parent == canonical:
        raise WorkspaceBindingError("control:workspace_root_forbidden")

    git_marker = canonical / ".git"
    if not git_marker.exists():
        raise WorkspaceBindingError("control:workspace_not_repository")
    if git_marker.is_symlink():
        raise WorkspaceBindingError("control:workspace_git_marker_symlink")

    try:
        stat = canonical.stat()
    except OSError as exc:
        raise WorkspaceBindingError("control:workspace_unavailable") from exc
    identity = _workspace_identity(canonical, stat.st_dev, stat.st_ino)
    return ReviewedWorkspace(
        path=canonical,
        display_name=canonical.name,
        identity_sha256=identity,
        device=stat.st_dev,
        inode=stat.st_ino,
    )


def resolve_workspace_target(
    workspace: ReviewedWorkspace,
    relative_path: str | Path,
    *,
    reject_hardlinks: bool = True,
) -> Path:
    """Resolve a relative target without traversal, symlink, or hardlink escape."""

    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise WorkspaceBindingError("control:workspace_parent_traversal")
    if not relative.parts:
        raise WorkspaceBindingError("control:workspace_target_required")

    current = workspace.path
    for part in relative.parts:
        if part in {"", "."}:
            continue
        current = current / part
        if current.is_symlink():
            raise WorkspaceBindingError("control:workspace_symlink_target")

    try:
        resolved = current.resolve(strict=False)
    except OSError as exc:
        raise WorkspaceBindingError("control:workspace_target_unavailable") from exc
    if resolved != workspace.path and not resolved.is_relative_to(workspace.path):
        raise WorkspaceBindingError("control:workspace_target_escape")
    if reject_hardlinks and resolved.exists() and resolved.is_file():
        try:
            if resolved.stat().st_nlink > 1:
                raise WorkspaceBindingError("control:workspace_hardlink_target")
        except OSError as exc:
            raise WorkspaceBindingError("control:workspace_target_unavailable") from exc
    return resolved


class InMemoryWorkspaceBindingStore:
    """Process-local binding used only by focused tests."""

    def __init__(self) -> None:
        self._binding: SupervisionBinding | None = None
        self._lock = threading.Lock()

    def bind(self, workspace: ReviewedWorkspace) -> SupervisionBinding:
        with self._lock:
            if self._binding is None:
                self._binding = SupervisionBinding(
                    session_id=str(uuid4()),
                    workspace=workspace,
                    created_at=datetime.now(timezone.utc),
                )
            elif self._binding.workspace != workspace:
                raise WorkspaceBindingError("control:workspace_identity_mismatch")
            return self._binding

    def close(self) -> None:
        return None


class SQLiteWorkspaceBindingStore:
    """Persist the singleton supervision session in Sentinel's state database."""

    def __init__(
        self,
        database: str | Path,
        *,
        timeout_seconds: float = 5.0,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            str(database),
            timeout=timeout_seconds,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(
            f"PRAGMA busy_timeout={int(timeout_seconds * 1_000)}"
        )
        self._create_schema()

    def bind(self, workspace: ReviewedWorkspace) -> SupervisionBinding:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    """
                    SELECT session_id, canonical_path, identity_sha256,
                           device, inode, created_at
                    FROM control_runtime_binding
                    WHERE singleton_id = 1
                    """
                ).fetchone()
                if row is None:
                    binding = SupervisionBinding(
                        session_id=str(uuid4()),
                        workspace=workspace,
                        created_at=datetime.now(timezone.utc),
                    )
                    self._connection.execute(
                        """
                        INSERT INTO control_runtime_binding (
                            singleton_id, session_id, canonical_path,
                            identity_sha256, device, inode, created_at
                        ) VALUES (1, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            binding.session_id,
                            str(workspace.path),
                            workspace.identity_sha256,
                            workspace.device,
                            workspace.inode,
                            binding.created_at.isoformat(timespec="microseconds"),
                        ),
                    )
                    self._connection.commit()
                    return binding

                if not _stored_workspace_matches(row, workspace):
                    raise WorkspaceBindingError(
                        "control:workspace_identity_mismatch"
                    )
                binding = SupervisionBinding(
                    session_id=row["session_id"],
                    workspace=workspace,
                    created_at=datetime.fromisoformat(row["created_at"]).astimezone(
                        timezone.utc
                    ),
                )
                self._connection.commit()
                return binding
            except Exception:
                self._connection.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _create_schema(self) -> None:
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS control_runtime_binding (
                    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                    session_id TEXT NOT NULL UNIQUE,
                    canonical_path TEXT NOT NULL,
                    identity_sha256 TEXT NOT NULL,
                    device INTEGER NOT NULL,
                    inode INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )


def _workspace_identity(path: Path, device: int, inode: int) -> str:
    payload = b"\0".join(
        (
            str(path).encode("utf-8", errors="surrogateescape"),
            str(device).encode("ascii"),
            str(inode).encode("ascii"),
        )
    )
    return hashlib.sha256(payload).hexdigest()


def _stored_workspace_matches(
    row: sqlite3.Row,
    workspace: ReviewedWorkspace,
) -> bool:
    return (
        row["canonical_path"] == str(workspace.path)
        and row["identity_sha256"] == workspace.identity_sha256
        and row["device"] == workspace.device
        and row["inode"] == workspace.inode
    )
