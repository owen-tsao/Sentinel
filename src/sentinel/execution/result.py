"""Execution result contracts for sandboxed command runs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ExecutionResult:
    """Internal result returned by a sandbox executor."""

    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool
    duration_ms: int
    error: str | None = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False

    def to_response_payload(self) -> dict[str, object]:
        return {
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
        }


class CommandExecutor(Protocol):
    """Executor boundary used by the API without depending on Docker details."""

    def run(self, *, command: str, shell_type: str) -> ExecutionResult:
        raise NotImplementedError
