from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import patch

from scripts import docker_smoke_check


def test_run_command_applies_the_phase_timeout() -> None:
    with patch.object(subprocess, "run") as run:
        docker_smoke_check.run_command(
            ["docker", "compose", "config"],
            env=dict(os.environ),
            timeout_seconds=17,
            cwd=Path("/tmp"),
        )

    run.assert_called_once_with(
        ["docker", "compose", "config"],
        cwd=Path("/tmp"),
        env=dict(os.environ),
        check=True,
        timeout=17,
    )


def test_smoke_subprocess_phases_have_finite_timeouts() -> None:
    assert 0 < docker_smoke_check.CONFIG_TIMEOUT_SECONDS
    assert (
        docker_smoke_check.CONFIG_TIMEOUT_SECONDS
        < docker_smoke_check.COMPOSE_LIFECYCLE_TIMEOUT_SECONDS
        < docker_smoke_check.BUILD_TIMEOUT_SECONDS
    )
    assert 0 < docker_smoke_check.COMPOSE_EXEC_TIMEOUT_SECONDS
