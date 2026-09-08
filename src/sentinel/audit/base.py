"""Swappable audit storage contract."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, TextIO, runtime_checkable

from .models import AuditEvent, AuditHealth, AuditQuery


class AuditStoreError(RuntimeError):
    """Base error for audit persistence failures."""


class AuditFallbackFullError(AuditStoreError):
    """Raised when neither SQLite nor the bounded fallback can retain an event."""


@runtime_checkable
class AuditStore(Protocol):
    """Backend-independent append and review operations."""

    @property
    def health(self) -> AuditHealth:
        ...

    def write(self, event: AuditEvent) -> None:
        ...

    def write_required(self, event: AuditEvent) -> None:
        """Durably commit admission/lifecycle evidence or raise."""

        ...

    def query(self, filters: AuditQuery | None = None, **filter_values: object) -> list[AuditEvent]:
        ...

    def export_jsonl(
        self,
        destination: str | Path | TextIO,
        filters: AuditQuery | None = None,
        **filter_values: object,
    ) -> int:
        ...
