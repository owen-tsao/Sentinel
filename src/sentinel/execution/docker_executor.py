"""Docker-backed sandbox executor for approved Sentinel commands."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from sentinel.execution.result import ExecutionResult

Runner = Callable[..., subprocess.CompletedProcess[str]]
ContainerNameFactory = Callable[[], str]


@dataclass(frozen=True)
class DockerExecutor:
    """Run approved commands in an ephemeral, restricted Docker container."""

    image: str = "sentinel-executor:local"
    workspace: Path = field(default_factory=Path.cwd)
    docker_binary: str = "docker"
    container_workspace: str = "/workspace"
    timeout_seconds: int = 10
    memory_limit: str = "256m"
    cpu_limit: str = "0.5"
    pids_limit: int = 128
    output_limit_bytes: int = 64 * 1024
    tmpfs_size: str = "64m"
    read_only_workspace: bool = False
    runner: Runner = subprocess.run
    container_name_factory: ContainerNameFactory | None = None

    def run(self, *, command: str, shell_type: str) -> ExecutionResult:
        """Execute a command with fail-closed Docker sandbox behavior."""

        start = perf_counter()
        container_name = self._new_container_name()
        try:
            docker_command = self.build_command(command=command, shell_type=shell_type, container_name=container_name)
            completed = self.runner(
                docker_command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except ValueError as exc:
            return self._error_result(str(exc), start)
        except FileNotFoundError:
            return self._error_result(f"Docker executable not found: {self.docker_binary}", start)
        except subprocess.TimeoutExpired as exc:
            self._remove_container(container_name)
            stdout, stdout_truncated = _cap_output(exc.stdout, self.output_limit_bytes)
            stderr, stderr_truncated = _cap_output(exc.stderr, self.output_limit_bytes)
            return ExecutionResult(
                stdout=stdout,
                stderr=stderr,
                exit_code=None,
                timed_out=True,
                duration_ms=_elapsed_ms(start),
                error=f"Command timed out after {self.timeout_seconds} seconds.",
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
            )

        stdout, stdout_truncated = _cap_output(completed.stdout, self.output_limit_bytes)
        stderr, stderr_truncated = _cap_output(completed.stderr, self.output_limit_bytes)
        return ExecutionResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=completed.returncode,
            timed_out=False,
            duration_ms=_elapsed_ms(start),
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )

    def build_command(self, *, command: str, shell_type: str, container_name: str | None = None) -> list[str]:
        """Build the `docker run` invocation for a single sandboxed execution."""

        workspace = self._resolved_workspace()
        mount = f"type=bind,source={workspace},target={self.container_workspace}"
        if self.read_only_workspace:
            mount = f"{mount},readonly"

        return [
            self.docker_binary,
            "run",
            "--rm",
            "--name",
            container_name or self._new_container_name(),
            "--network",
            "none",
            "--memory",
            self.memory_limit,
            "--cpus",
            self.cpu_limit,
            "--pids-limit",
            str(self.pids_limit),
            "--read-only",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,size={self.tmpfs_size}",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--workdir",
            self.container_workspace,
            "--env",
            f"SENTINEL_SHELL_TYPE={shell_type}",
            "--mount",
            mount,
            self.image,
            "sh",
            "-lc",
            command,
        ]

    def _resolved_workspace(self) -> Path:
        try:
            workspace = self.workspace.expanduser().resolve(strict=True)
        except OSError as exc:
            raise ValueError(f"Invalid executor workspace {self.workspace}: {exc}") from exc
        if not workspace.is_dir():
            raise ValueError(f"Workspace is not a directory: {workspace}")
        if workspace.parent == workspace:
            raise ValueError("Refusing to mount the filesystem root as the executor workspace.")
        return workspace

    def _new_container_name(self) -> str:
        factory = self.container_name_factory
        if factory is not None:
            return factory()
        return f"sentinel-exec-{uuid4().hex}"

    def _remove_container(self, container_name: str) -> None:
        try:
            self.runner(
                [self.docker_binary, "rm", "-f", container_name],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except Exception:
            return

    def _error_result(self, error: str, start: float) -> ExecutionResult:
        return ExecutionResult(
            stdout="",
            stderr="",
            exit_code=None,
            timed_out=False,
            duration_ms=_elapsed_ms(start),
            error=error,
        )


def _cap_output(value: str | bytes | None, limit_bytes: int) -> tuple[str, bool]:
    if value is None:
        return "", False
    if isinstance(value, bytes):
        data = value
    else:
        data = value.encode("utf-8")
    if len(data) <= limit_bytes:
        return data.decode("utf-8", errors="replace"), False
    return data[:limit_bytes].decode("utf-8", errors="replace"), True


def _elapsed_ms(start: float) -> int:
    return max(0, int((perf_counter() - start) * 1000))
