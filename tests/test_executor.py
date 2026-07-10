from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.execution import DockerExecutor  # noqa: E402


class RecordingRunner:
    def __init__(
        self,
        *,
        stdout: str = "",
        stderr: str = "",
        returncode: int = 0,
        error: Exception | None = None,
    ) -> None:
        self.calls: list[list[str]] = []
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.error = error

    def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)
        if self.error is not None and args[1] == "run":
            raise self.error
        return subprocess.CompletedProcess(args=args, returncode=self.returncode, stdout=self.stdout, stderr=self.stderr)


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
        self.assertIn("target=/workspace", command[command.index("--mount") + 1])
        self.assertNotIn("/var/run/docker.sock", " ".join(command))
        self.assertEqual(command[-3:], ["sh", "-lc", "git status --short"])

    def test_build_command_can_make_workspace_mount_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            executor = DockerExecutor(workspace=Path(workspace), read_only_workspace=True)

            command = executor.build_command(command="ls", shell_type="bash", container_name="sentinel-test")

        self.assertTrue(command[command.index("--mount") + 1].endswith(",readonly"))

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


if __name__ == "__main__":
    unittest.main()
