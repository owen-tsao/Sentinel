from __future__ import annotations

import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.execution import DockerExecutor  # noqa: E402
from sentinel.execution.docker_executor import _run_subprocess_bounded  # noqa: E402


class RecordingRunner:
    def __init__(
        self,
        *,
        stdout: str | bytes = "",
        stderr: str | bytes = "",
        returncode: int = 0,
        error: BaseException | None = None,
    ) -> None:
        self.calls: list[list[str]] = []
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.error = error
        self.kwargs: list[dict[str, Any]] = []

    def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        self.calls.append(args)
        self.kwargs.append(kwargs)
        if self.error is not None and args[1] == "run":
            raise self.error
        return subprocess.CompletedProcess(args=args, returncode=self.returncode, stdout=self.stdout, stderr=self.stderr)


class TrackingBytesIO(io.BytesIO):
    def __init__(self, value: bytes) -> None:
        super().__init__(value)
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        super().close()


class DockerExecutorTests(unittest.TestCase):
    def test_build_command_uses_restricted_docker_flags(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            executor = DockerExecutor(workspace=Path(workspace), image="sentinel-executor:test")

            command = executor.build_command(
                command="git status --short",
                shell_type="bash",
                container_name="sentinel-test",
            )

        self.assertEqual(command[:4], ["docker", "run", "--rm", "--name"])
        self.assertIn("--network", command)
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertEqual(command[command.index("--user") + 1], "65532:65532")
        self.assertIn("--memory", command)
        self.assertIn("--cpus", command)
        self.assertIn("--pids-limit", command)
        self.assertIn("--read-only", command)
        self.assertIn("--cap-drop", command)
        self.assertEqual(command[command.index("--cap-drop") + 1], "ALL")
        self.assertIn("--security-opt", command)
        self.assertEqual(command[command.index("--security-opt") + 1], "no-new-privileges:true")
        self.assertIn("--tmpfs", command)
        self.assertIn("--mount", command)
        mount = command[command.index("--mount") + 1]
        self.assertIn("target=/workspace", mount)
        self.assertTrue(mount.endswith(",readonly"))
        self.assertNotIn("/var/run/docker.sock", " ".join(command))
        self.assertEqual(command[-3:], ["sh", "-lc", "git status --short"])

    def test_build_command_can_make_workspace_mount_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            executor = DockerExecutor(workspace=Path(workspace), read_only_workspace=True)

            command = executor.build_command(command="ls", shell_type="bash", container_name="sentinel-test")

        self.assertTrue(command[command.index("--mount") + 1].endswith(",readonly"))

    def test_writable_repository_execution_is_explicitly_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            executor = DockerExecutor(workspace=Path(workspace), read_only_workspace=False)

            with self.assertRaisesRegex(ValueError, "unsupported"):
                executor.build_command(
                    command="touch output.txt",
                    shell_type="bash",
                    container_name="sentinel-test",
                )

    def test_read_only_capability_rejects_canonical_mutations(self) -> None:
        executor = DockerExecutor(read_only_workspace=True)

        executor.validate_operation("read")
        for operation in ("write", "delete"):
            with self.subTest(operation=operation), self.assertRaisesRegex(
                ValueError,
                "Read-only executor",
            ):
                executor.validate_operation(operation)  # type: ignore[arg-type]

    def test_run_returns_exit_code_and_truncates_output(self) -> None:
        runner = RecordingRunner(stdout="abcdef", stderr="xyz", returncode=7)
        with tempfile.TemporaryDirectory() as workspace:
            executor = DockerExecutor(
                workspace=Path(workspace),
                runner=runner,
                output_limit_bytes=3,
                container_name_factory=lambda: "sentinel-test",
            )

            result = executor.run(command="python script.py", shell_type="python")

        self.assertEqual(result.stdout, "abc")
        self.assertTrue(result.stdout_truncated)
        self.assertEqual(result.stderr, "xyz")
        self.assertFalse(result.stderr_truncated)
        self.assertEqual(result.exit_code, 7)
        self.assertFalse(result.timed_out)
        self.assertIsNone(result.error)
        self.assertEqual(len(runner.calls), 1)
        self.assertFalse(runner.kwargs[0]["text"])

    def test_run_decodes_invalid_binary_output_without_crashing(self) -> None:
        runner = RecordingRunner(stdout=b"ok\xffdone", stderr=b"\x80error")
        with tempfile.TemporaryDirectory() as workspace:
            result = DockerExecutor(workspace=Path(workspace), runner=runner).run(
                command="emit binary",
                shell_type="bash",
            )

        self.assertEqual(result.stdout, "ok\ufffddone")
        self.assertEqual(result.stderr, "\ufffderror")

    def test_subprocess_capture_retains_only_configured_bytes(self) -> None:
        completed = _run_subprocess_bounded(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'a' * 100000); sys.stderr.buffer.write(b'b' * 90000)"],
            timeout=5,
            output_limit_bytes=17,
        )

        self.assertEqual(completed.stdout, b"a" * 17)
        self.assertEqual(completed.stderr, b"b" * 17)
        self.assertTrue(completed.stdout_truncated)
        self.assertTrue(completed.stderr_truncated)

    def test_bounded_subprocess_cleans_up_on_base_exception(self) -> None:
        class InterruptingProcess:
            def __init__(self) -> None:
                self.stdout = TrackingBytesIO(b"partial stdout")
                self.stderr = TrackingBytesIO(b"partial stderr")
                self.kill_calls = 0
                self.wait_calls = 0

            def wait(self, timeout: float | None = None) -> int:
                self.wait_calls += 1
                if timeout is not None:
                    raise KeyboardInterrupt()
                return -9

            def kill(self) -> None:
                self.kill_calls += 1

        process = InterruptingProcess()
        with patch(
            "sentinel.execution.docker_executor.subprocess.Popen",
            return_value=process,
        ), self.assertRaises(KeyboardInterrupt):
            _run_subprocess_bounded(
                ["ignored"],
                timeout=1,
                output_limit_bytes=100,
            )

        self.assertEqual(process.kill_calls, 1)
        self.assertEqual(process.wait_calls, 2)
        self.assertEqual(process.stdout.close_calls, 1)
        self.assertEqual(process.stderr.close_calls, 1)

    def test_bounded_subprocess_timeout_cleans_up_once(self) -> None:
        class TimingOutProcess:
            def __init__(self) -> None:
                self.stdout = TrackingBytesIO(b"partial stdout")
                self.stderr = TrackingBytesIO(b"partial stderr")
                self.kill_calls = 0
                self.wait_calls = 0

            def wait(self, timeout: float | None = None) -> int:
                self.wait_calls += 1
                if timeout is not None:
                    raise subprocess.TimeoutExpired(["ignored"], timeout)
                return -9

            def kill(self) -> None:
                self.kill_calls += 1

        process = TimingOutProcess()
        with patch(
            "sentinel.execution.docker_executor.subprocess.Popen",
            return_value=process,
        ), self.assertRaises(subprocess.TimeoutExpired) as raised:
            _run_subprocess_bounded(
                ["ignored"],
                timeout=1,
                output_limit_bytes=100,
            )

        self.assertEqual(raised.exception.stdout, b"partial stdout")
        self.assertEqual(raised.exception.stderr, b"partial stderr")
        self.assertEqual(process.kill_calls, 1)
        self.assertEqual(process.wait_calls, 2)
        self.assertEqual(process.stdout.close_calls, 1)
        self.assertEqual(process.stderr.close_calls, 1)

    def test_timeout_kills_container_and_returns_partial_output(self) -> None:
        timeout = subprocess.TimeoutExpired(
            cmd=["docker", "run"],
            timeout=1,
            output="partial stdout",
            stderr=b"partial stderr",
        )
        runner = RecordingRunner(error=timeout)
        with tempfile.TemporaryDirectory() as workspace:
            executor = DockerExecutor(
                workspace=Path(workspace),
                runner=runner,
                timeout_seconds=1,
                container_name_factory=lambda: "sentinel-timeout",
            )

            result = executor.run(command="sleep 60", shell_type="bash")

        self.assertTrue(result.timed_out)
        self.assertIsNone(result.exit_code)
        self.assertEqual(result.stdout, "partial stdout")
        self.assertEqual(result.stderr, "partial stderr")
        self.assertIn("timed out", result.error or "")
        self.assertEqual(runner.calls[-1], ["docker", "rm", "-f", "sentinel-timeout"])

    def test_missing_docker_returns_error_without_host_fallback(self) -> None:
        runner = RecordingRunner(error=FileNotFoundError())
        with tempfile.TemporaryDirectory() as workspace:
            executor = DockerExecutor(workspace=Path(workspace), runner=runner)

            result = executor.run(command="echo hello", shell_type="bash")

        self.assertIsNone(result.exit_code)
        self.assertFalse(result.timed_out)
        self.assertIn("Docker executable not found", result.error or "")
        self.assertEqual(len(runner.calls), 1)

    def test_permission_error_returns_structured_error_not_crash(self) -> None:
        runner = RecordingRunner(error=PermissionError(13, "Permission denied"))
        with tempfile.TemporaryDirectory() as workspace:
            executor = DockerExecutor(workspace=Path(workspace), runner=runner)

            result = executor.run(command="echo hello", shell_type="bash")

        self.assertIsNone(result.exit_code)
        self.assertIn("Sandbox could not start", result.error or "")

    def test_os_error_returns_structured_error_not_crash(self) -> None:
        runner = RecordingRunner(error=OSError(7, "Argument list too long"))
        with tempfile.TemporaryDirectory() as workspace:
            executor = DockerExecutor(workspace=Path(workspace), runner=runner)

            result = executor.run(command="echo hello", shell_type="bash")

        self.assertIsNone(result.exit_code)
        self.assertIn("Sandbox could not start", result.error or "")

    def test_timeout_reports_failed_container_cleanup(self) -> None:
        class FailingCleanupRunner(RecordingRunner):
            def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
                self.calls.append(args)
                if args[1] == "run":
                    raise subprocess.TimeoutExpired(cmd=args, timeout=1)
                return subprocess.CompletedProcess(args=args, returncode=1, stdout="", stderr="daemon busy")

        runner = FailingCleanupRunner()
        with tempfile.TemporaryDirectory() as workspace:
            executor = DockerExecutor(
                workspace=Path(workspace),
                runner=runner,
                timeout_seconds=1,
                container_name_factory=lambda: "sentinel-stuck",
            )

            result = executor.run(command="sleep 60", shell_type="bash")

        self.assertTrue(result.timed_out)
        self.assertIn("cleanup may have failed", result.error or "")
        self.assertIn("sentinel-stuck", result.error or "")

    def test_base_exception_removes_named_container_and_propagates(self) -> None:
        runner = RecordingRunner(error=KeyboardInterrupt())
        with tempfile.TemporaryDirectory() as workspace:
            executor = DockerExecutor(
                workspace=Path(workspace),
                runner=runner,
                container_name_factory=lambda: "sentinel-interrupted",
            )

            with self.assertRaises(KeyboardInterrupt):
                executor.run(command="sleep 60", shell_type="bash")

        self.assertEqual(
            runner.calls[-1],
            ["docker", "rm", "-f", "sentinel-interrupted"],
        )

    def test_timeout_cleanup_treats_already_removed_container_as_success(self) -> None:
        class GoneContainerRunner(RecordingRunner):
            def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
                self.calls.append(args)
                if args[1] == "run":
                    raise subprocess.TimeoutExpired(cmd=args, timeout=1)
                return subprocess.CompletedProcess(
                    args=args, returncode=1, stdout="", stderr="Error: No such container: sentinel-gone"
                )

        runner = GoneContainerRunner()
        with tempfile.TemporaryDirectory() as workspace:
            executor = DockerExecutor(
                workspace=Path(workspace),
                runner=runner,
                timeout_seconds=1,
                container_name_factory=lambda: "sentinel-gone",
            )

            result = executor.run(command="sleep 60", shell_type="bash")

        self.assertTrue(result.timed_out)
        self.assertNotIn("cleanup may have failed", result.error or "")

    def test_invalid_workspace_returns_error_without_running_docker(self) -> None:
        runner = RecordingRunner()
        with tempfile.TemporaryDirectory() as workspace:
            missing_workspace = Path(workspace) / "missing"
            executor = DockerExecutor(workspace=missing_workspace, runner=runner)

            result = executor.run(command="echo hello", shell_type="bash")

        self.assertIsNone(result.exit_code)
        self.assertIn("Invalid executor workspace", result.error or "")
        self.assertEqual(runner.calls, [])

    def test_symlinked_workspace_resolves_to_real_path_in_mount(self) -> None:
        with tempfile.TemporaryDirectory() as base:
            real_workspace = Path(base) / "real"
            real_workspace.mkdir()
            link = Path(base) / "link"
            link.symlink_to(real_workspace)
            executor = DockerExecutor(workspace=link)

            command = executor.build_command(command="ls", shell_type="bash", container_name="sentinel-test")

            mount = command[command.index("--mount") + 1]
            self.assertIn(f"source={real_workspace.resolve()},", mount)

    def test_mount_paths_with_unrepresentable_delimiters_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as base:
            workspace = Path(base) / "workspace,unsafe"
            workspace.mkdir()

            with self.assertRaisesRegex(ValueError, "Docker --mount"):
                DockerExecutor(workspace=workspace).build_command(
                    command="ls",
                    shell_type="bash",
                    container_name="sentinel-test",
                )
            with self.assertRaisesRegex(ValueError, "Docker --mount"):
                DockerExecutor(
                    workspace=Path(base),
                    container_workspace="/workspace,unsafe",
                ).build_command(
                    command="ls",
                    shell_type="bash",
                    container_name="sentinel-test",
                )

    def test_refuses_to_mount_filesystem_root_as_workspace(self) -> None:
        runner = RecordingRunner()
        executor = DockerExecutor(workspace=Path("/"), runner=runner)

        result = executor.run(command="echo hello", shell_type="bash")

        self.assertIn("filesystem root", result.error or "")
        self.assertEqual(runner.calls, [])

    def test_workspace_pointing_at_file_is_rejected(self) -> None:
        runner = RecordingRunner()
        with tempfile.TemporaryDirectory() as workspace:
            file_path = Path(workspace) / "not_a_dir.txt"
            file_path.write_text("hello")
            executor = DockerExecutor(workspace=file_path, runner=runner)

            result = executor.run(command="echo hello", shell_type="bash")

        self.assertIn("not a directory", result.error or "")
        self.assertEqual(runner.calls, [])

    def test_sensitive_host_workspace_is_rejected(self) -> None:
        runner = RecordingRunner()
        executor = DockerExecutor(workspace=Path("/etc"), runner=runner)

        result = executor.run(command="cat passwd", shell_type="bash")

        self.assertIn("sensitive host path", result.error or "")
        self.assertEqual(runner.calls, [])

    def test_home_directory_is_rejected_because_it_contains_sensitive_roots(self) -> None:
        runner = RecordingRunner()
        executor = DockerExecutor(workspace=Path.home(), runner=runner)

        result = executor.run(command="pwd", shell_type="bash")

        self.assertIn("sensitive host path", result.error or "")
        self.assertEqual(runner.calls, [])

    def test_target_validation_rejects_symlink_aliases_and_outside_paths(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            root = Path(workspace)
            (root / "ordinary.txt").write_text("ok", encoding="utf-8")
            (root / "alias.txt").symlink_to(root / "ordinary.txt")
            executor = DockerExecutor(workspace=root)

            executor.validate_targets(["/workspace/ordinary.txt"])
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                executor.validate_targets(["/workspace/alias.txt"])
            with self.assertRaisesRegex(ValueError, "outside the mounted workspace"):
                executor.validate_targets(["/etc/passwd"])

    def test_root_container_user_is_rejected(self) -> None:
        runner = RecordingRunner()
        with tempfile.TemporaryDirectory() as workspace:
            executor = DockerExecutor(workspace=Path(workspace), container_user="0:0", runner=runner)

            result = executor.run(command="id", shell_type="bash")

        self.assertIn("must both be non-root", result.error or "")
        self.assertEqual(runner.calls, [])


if __name__ == "__main__":
    unittest.main()
