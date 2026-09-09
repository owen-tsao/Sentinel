"""Docker-backed sandbox executor for approved Sentinel commands."""

from __future__ import annotations

import os
import stat
import subprocess
import threading
import posixpath
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from time import perf_counter
from typing import TYPE_CHECKING, Any, BinaryIO
from uuid import uuid4

from sentinel.contracts import ActionOperation
from sentinel.execution.result import ExecutionResult

if TYPE_CHECKING:
    from sentinel.actions import CanonicalAction

Runner = Callable[..., subprocess.CompletedProcess[Any]]
ContainerNameFactory = Callable[[], str]

_SENSITIVE_SYSTEM_MOUNT_ROOTS = (
    Path("/dev"),
    Path("/etc"),
    Path("/proc"),
    Path("/run"),
    Path("/sys"),
    Path("/var/run"),
    Path("/private/etc"),
    Path("/private/var/run"),
)
_SENSITIVE_HOME_MOUNT_ROOTS = (".aws", ".docker", ".gnupg", ".kube", ".ssh")


@dataclass(frozen=True)
class _BoundedProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool


class _BoundedTimeoutExpired(subprocess.TimeoutExpired):
    def __init__(
        self,
        cmd: list[str],
        timeout: float,
        *,
        stdout: bytes,
        stderr: bytes,
        stdout_truncated: bool,
        stderr_truncated: bool,
    ) -> None:
        super().__init__(cmd, timeout, output=stdout, stderr=stderr)
        self.stdout_truncated = stdout_truncated
        self.stderr_truncated = stderr_truncated


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
    read_only_workspace: bool = True
    writable_subdirectory: str | None = None
    container_user: str = "65532:65532"
    runner: Runner = subprocess.run
    container_name_factory: ContainerNameFactory | None = None

    def runtime_ready(self) -> bool:
        """Return whether the configured Docker daemon accepts local commands."""

        try:
            self.validate_configuration()
            completed = self.runner(
                [self.docker_binary, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=min(self.timeout_seconds, 3),
            )
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return False
        return completed.returncode == 0

    def run(self, *, command: str, shell_type: str) -> ExecutionResult:
        """Execute a command with fail-closed Docker sandbox behavior."""

        start = perf_counter()
        container_name = self._new_container_name()
        try:
            docker_command = self.build_command(command=command, shell_type=shell_type, container_name=container_name)
            if self.runner is subprocess.run:
                # subprocess.run buffers complete pipes before returning. The
                # default path drains both binary streams concurrently while
                # retaining at most output_limit_bytes from each one.
                completed = _run_subprocess_bounded(
                    docker_command,
                    timeout=self.timeout_seconds,
                    output_limit_bytes=self.output_limit_bytes,
                )
            else:
                # Preserve the injectable runner boundary used by unit tests
                # and embedders; its returned output is still capped below.
                completed = self.runner(
                    docker_command,
                    capture_output=True,
                    text=False,
                    timeout=self.timeout_seconds,
                )
        except ValueError as exc:
            return self._error_result(str(exc), start)
        except FileNotFoundError:
            return self._error_result(f"Docker executable not found: {self.docker_binary}", start)
        except subprocess.TimeoutExpired as exc:
            cleanup_ok = self._remove_container(container_name)
            stdout, stdout_truncated = _cap_output(exc.stdout, self.output_limit_bytes)
            stderr, stderr_truncated = _cap_output(exc.stderr, self.output_limit_bytes)
            stdout_truncated = stdout_truncated or bool(getattr(exc, "stdout_truncated", False))
            stderr_truncated = stderr_truncated or bool(getattr(exc, "stderr_truncated", False))
            error = f"Command timed out after {self.timeout_seconds} seconds."
            if not cleanup_ok:
                error = f"{error} Container cleanup may have failed; check for orphaned container {container_name}."
            return ExecutionResult(
                stdout=stdout,
                stderr=stderr,
                exit_code=None,
                timed_out=True,
                duration_ms=_elapsed_ms(start),
                error=error,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
            )
        except OSError as exc:
            # Fail closed on any other OS-level launch failure (permissions, argv
            # limits, resource exhaustion) instead of leaking a raw 500 to callers.
            return self._error_result(f"Sandbox could not start: {exc}", start)
        except BaseException:
            # Cancellation must propagate, but the named container may outlive
            # the interrupted Docker CLI process unless it is removed explicitly.
            try:
                self._remove_container(container_name)
            except BaseException:
                pass
            raise

        stdout, stdout_truncated = _cap_output(completed.stdout, self.output_limit_bytes)
        stderr, stderr_truncated = _cap_output(completed.stderr, self.output_limit_bytes)
        stdout_truncated = stdout_truncated or bool(getattr(completed, "stdout_truncated", False))
        stderr_truncated = stderr_truncated or bool(getattr(completed, "stderr_truncated", False))
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
        container_user = self._validated_container_user()
        container_workspace = self._validated_container_workspace()
        if not self.read_only_workspace:
            raise ValueError(
                "Writable repository execution is unsupported; "
                "read_only_workspace must remain enabled."
            )
        _validate_mount_value(str(workspace), name="executor workspace")
        mount = (
            f"type=bind,source={workspace},target={container_workspace},readonly"
        )
        mounts = ["--mount", mount]
        writable_directory = self._resolved_writable_directory(workspace)
        if writable_directory is not None:
            writable_mount = (
                f"type=bind,source={writable_directory},"
                f"target={self._writable_container_root(container_workspace)}"
            )
            _validate_mount_value(
                str(writable_directory),
                name="writable executor directory",
            )
            mounts.extend(["--mount", writable_mount])

        return [
            self.docker_binary,
            "run",
            "--rm",
            "--name",
            container_name or self._new_container_name(),
            "--user",
            container_user,
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
            container_workspace,
            "--env",
            f"SENTINEL_SHELL_TYPE={shell_type}",
            *mounts,
            self.image,
            "sh",
            "-lc",
            command,
        ]

    def validate_configuration(self) -> None:
        """Validate static sandbox settings before spending one-use authority."""

        workspace = self._resolved_workspace()
        self._validated_container_user()
        self._validated_container_workspace()
        _validate_mount_value(str(workspace), name="executor workspace")
        if not self.read_only_workspace:
            raise ValueError(
                "Writable repository execution is unsupported; "
                "read_only_workspace must remain enabled."
            )
        self._resolved_writable_directory(workspace)

    def validate_operation(self, operation: ActionOperation) -> None:
        """Reject canonical mutations that the configured sandbox cannot perform."""

        if (
            self.writable_subdirectory is not None
            and operation not in {"read", "write"}
        ):
            raise ValueError(
                "Scoped writable executor supports only canonical read and write operations."
            )
        if (
            self.read_only_workspace
            and operation in {"write", "delete"}
            and self.writable_subdirectory is None
        ):
            raise ValueError(
                f"Read-only executor cannot perform canonical {operation} operations."
            )

    def validate_targets(self, targets: list[str]) -> None:
        """Ensure authorized container paths map to ordinary workspace paths."""

        workspace = self._resolved_workspace()
        container_root = self._validated_container_workspace()
        for target in targets:
            normalized = posixpath.normpath(target)
            if not (
                normalized == container_root
                or normalized.startswith(container_root.rstrip("/") + "/")
            ):
                raise ValueError(f"Target is outside the mounted workspace: {target}")
            relative = Path(normalized.removeprefix(container_root).lstrip("/"))
            current = workspace
            for part in relative.parts:
                current = current / part
                if current.is_symlink():
                    raise ValueError(f"Target traverses a symbolic link: {target}")
            resolved = (workspace / relative).resolve(strict=False)
            if resolved != workspace and not resolved.is_relative_to(workspace):
                raise ValueError(f"Target resolves outside the mounted workspace: {target}")
            if resolved.exists() and resolved.is_file() and resolved.stat().st_nlink > 1:
                raise ValueError(f"Target is a multiply-linked file: {target}")

    def validate_action(self, action: CanonicalAction) -> None:
        """Confine mutations to descendants of the explicit writable subtree."""

        if action.operation not in {"write", "delete"}:
            return
        workspace = self._resolved_workspace()
        writable_directory = self._resolved_writable_directory(workspace)
        if writable_directory is None:
            raise ValueError(
                f"Read-only executor cannot perform canonical {action.operation} operations."
            )
        writable_root = self._writable_container_root(
            self._validated_container_workspace()
        )
        prefix = writable_root.rstrip("/") + "/"
        for target in action.targets:
            normalized = posixpath.normpath(target)
            if not normalized.startswith(prefix):
                raise ValueError(
                    f"Mutation target is outside the writable subtree: {target}"
                )

    def _resolved_workspace(self) -> Path:
        try:
            workspace = self.workspace.expanduser().resolve(strict=True)
        except OSError as exc:
            raise ValueError(f"Invalid executor workspace {self.workspace}: {exc}") from exc
        if not workspace.is_dir():
            raise ValueError(f"Workspace is not a directory: {workspace}")
        if workspace.parent == workspace:
            raise ValueError("Refusing to mount the filesystem root as the executor workspace.")
        if _is_sensitive_host_path(workspace):
            raise ValueError(f"Refusing to mount sensitive host path as the executor workspace: {workspace}")
        return workspace

    def _validated_container_user(self) -> str:
        uid, separator, gid = self.container_user.partition(":")
        if separator != ":" or not uid.isdigit() or not gid.isdigit():
            raise ValueError("container_user must be an explicit numeric UID:GID")
        if int(uid) == 0 or int(gid) == 0:
            raise ValueError("container_user UID and GID must both be non-root")
        return self.container_user

    def _validated_container_workspace(self) -> str:
        if (
            not isinstance(self.container_workspace, str)
            or not self.container_workspace.startswith("/")
        ):
            raise ValueError("container_workspace must be an absolute container path")
        normalized = posixpath.normpath(self.container_workspace)
        _validate_mount_value(normalized, name="container_workspace")
        return normalized

    def _resolved_writable_directory(self, workspace: Path) -> Path | None:
        raw = self.writable_subdirectory
        if raw is None:
            return None
        relative = Path(raw)
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise ValueError(
                "writable_subdirectory must be a confined relative path"
            )
        current = workspace
        for part in relative.parts:
            if part in {"", "."}:
                continue
            current = current / part
            if current.is_symlink():
                raise ValueError(
                    "Writable executor directory cannot traverse symbolic links."
                )
        try:
            resolved = current.resolve(strict=True)
        except OSError as exc:
            raise ValueError(
                f"Invalid writable executor directory {current}: {exc}"
            ) from exc
        if (
            not resolved.is_dir()
            or resolved == workspace
            or not resolved.is_relative_to(workspace)
        ):
            raise ValueError(
                "Writable executor directory must be a strict workspace descendant."
            )
        metadata = resolved.stat()
        if hasattr(os, "getuid"):
            owner_uid = os.getuid()
            owner_gid = os.getgid()
            if owner_uid == 0:
                raise ValueError(
                    "Scoped writable execution cannot run as the root host user."
                )
            if self.container_user != f"{owner_uid}:{owner_gid}":
                raise ValueError(
                    "Scoped writable executor must use the Sentinel process UID and GID."
                )
            _validate_private_directory(resolved, metadata, owner_uid)
            _validate_writable_tree(resolved, owner_uid=owner_uid)
        else:
            _validate_writable_tree(resolved, owner_uid=None)
        return resolved

    def _writable_container_root(self, container_workspace: str) -> str:
        raw = self.writable_subdirectory
        if raw is None:
            raise ValueError("writable_subdirectory is not configured")
        relative = Path(raw)
        return posixpath.normpath(
            posixpath.join(container_workspace, *relative.parts)
        )

    def _new_container_name(self) -> str:
        factory = self.container_name_factory
        if factory is not None:
            return factory()
        return f"sentinel-exec-{uuid4().hex}"

    def _remove_container(self, container_name: str) -> bool:
        """Force-remove a timed-out container. Returns False if removal may have failed."""
        try:
            completed = self.runner(
                [self.docker_binary, "rm", "-f", container_name],
                capture_output=True,
                text=False,
                timeout=5,
            )
        except Exception:
            return False
        if completed.returncode == 0:
            return True
        # "No such container" means it already exited and --rm reaped it: cleanup done.
        stderr, _ = _cap_output(completed.stderr, 8 * 1024)
        return "no such container" in stderr.lower()

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


def _run_subprocess_bounded(
    command: list[str],
    *,
    timeout: float,
    output_limit_bytes: int,
) -> _BoundedProcessResult:
    """Run one process with binary-safe, memory-bounded stdout/stderr retention.

    Both pipes are continuously drained to avoid deadlock, but only the first
    configured number of bytes per stream are retained. This bounds Sentinel's
    capture memory without requiring a streaming runner API.
    """

    if output_limit_bytes < 0:
        raise ValueError("output_limit_bytes must be non-negative")

    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    buffers: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    truncated: dict[str, bool] = {"stdout": False, "stderr": False}

    def drain(name: str, stream: BinaryIO) -> None:
        while True:
            chunk = stream.read(8 * 1024)
            if not chunk:
                return
            remaining = output_limit_bytes - len(buffers[name])
            if remaining > 0:
                buffers[name].extend(chunk[:remaining])
            if len(chunk) > max(0, remaining):
                truncated[name] = True

    assert process.stdout is not None
    assert process.stderr is not None
    threads = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
    ]
    for thread in threads:
        thread.start()

    def terminate_and_reap() -> None:
        try:
            process.kill()
        except BaseException:
            pass
        try:
            process.wait()
        except BaseException:
            pass

    def finish_drains() -> None:
        for thread in threads:
            thread.join()
        for stream in (process.stdout, process.stderr):
            if not stream.closed:
                stream.close()

    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        terminate_and_reap()
        finish_drains()
        raise _BoundedTimeoutExpired(
            command,
            timeout,
            stdout=bytes(buffers["stdout"]),
            stderr=bytes(buffers["stderr"]),
            stdout_truncated=truncated["stdout"],
            stderr_truncated=truncated["stderr"],
        ) from None
    except BaseException:
        terminate_and_reap()
        finish_drains()
        raise

    finish_drains()
    return _BoundedProcessResult(
        returncode=returncode,
        stdout=bytes(buffers["stdout"]),
        stderr=bytes(buffers["stderr"]),
        stdout_truncated=truncated["stdout"],
        stderr_truncated=truncated["stderr"],
    )


def _is_sensitive_host_path(workspace: Path) -> bool:
    if any(
        workspace == root
        or workspace.is_relative_to(root)
        or root.is_relative_to(workspace)
        for root in _SENSITIVE_SYSTEM_MOUNT_ROOTS
    ):
        return True

    home = Path.home().resolve()
    return any(
        workspace == (home / relative).resolve()
        or workspace.is_relative_to((home / relative).resolve())
        or (home / relative).resolve().is_relative_to(workspace)
        for relative in _SENSITIVE_HOME_MOUNT_ROOTS
    )


def _validate_mount_value(value: str, *, name: str) -> None:
    if "," in value:
        raise ValueError(
            f"{name} contains a comma that Docker --mount cannot represent safely."
        )


def _validate_writable_tree(root: Path, *, owner_uid: int | None) -> None:
    """Reject aliases and special files that could mutate outside the subtree."""

    try:
        entries = list(os.scandir(root))
    except OSError as exc:
        raise ValueError(
            f"Writable executor directory cannot be inspected: {exc}"
        ) from exc
    for entry in entries:
        if entry.is_symlink():
            raise ValueError(
                f"Writable executor directory contains a symbolic link: {entry.name}"
            )
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise ValueError(
                f"Writable executor entry cannot be inspected: {entry.name}"
            ) from exc
        if stat.S_ISDIR(metadata.st_mode):
            if owner_uid is not None:
                _validate_private_directory(
                    Path(entry.path),
                    metadata,
                    owner_uid,
                )
            _validate_writable_tree(Path(entry.path), owner_uid=owner_uid)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(
                f"Writable executor directory contains a special file: {entry.name}"
            )
        if metadata.st_nlink != 1:
            raise ValueError(
                f"Writable executor directory contains a hard-linked file: {entry.name}"
            )
        if owner_uid is not None and metadata.st_uid != owner_uid:
            raise ValueError(
                f"Writable executor file has an unexpected owner: {entry.name}"
            )


def _validate_private_directory(
    path: Path,
    metadata: os.stat_result,
    owner_uid: int,
) -> None:
    if metadata.st_uid != owner_uid:
        raise ValueError(
            f"Writable executor directory has an unexpected owner: {path}"
        )
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ValueError(
            f"Writable executor directory cannot be group/world writable: {path}"
        )


def _elapsed_ms(start: float) -> int:
    return max(0, int((perf_counter() - start) * 1000))
