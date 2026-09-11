"""Run the isolated real backend used by the Week 11 Playwright proof."""

from __future__ import annotations

import hmac
import json
import os
import secrets
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import uvicorn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

if os.environ.get("SENTINEL_ENABLE_ML", "false") != "false":
    raise RuntimeError("Week 11 Playwright server requires SENTINEL_ENABLE_ML=false")

from sentinel.api.main import create_app  # noqa: E402
from sentinel.control import ControlConfig  # noqa: E402
from sentinel.control.pairing import (  # noqa: E402
    AuthenticatedControlSession,
    IssuedControlSession,
    PairingError,
    PairingService,
)
from sentinel.decision.policy import parse_policy_profile  # noqa: E402
from sentinel.execution import DockerExecutor  # noqa: E402

API_HOST = "127.0.0.1"
API_PORT = 8000
# Must match the port Playwright serves the UI on; the control API rejects
# every other browser origin by design. Override with SENTINEL_WEB_PORT.
UI_ORIGIN = f"http://127.0.0.1:{os.environ.get('SENTINEL_WEB_PORT', '3000')}"
PAIRING_CAPABILITY = "playwright-real-control-" + ("a" * 40)
# Manual walkthroughs: keep the fixed link reusable so several browsers (a
# person and an automated one) can pair with the same running backend without
# restarting it. The real PairingService is untouched; this only applies to
# this dev script and only when asked for.
REUSABLE_PAIRING = os.environ.get("SENTINEL_DEV_REUSABLE_PAIRING") == "1"
FIXTURE_ROOT = ROOT / "web" / "test-results" / "real-control"
REPOSITORY = FIXTURE_ROOT / "sample-repository"
BUILD_DIRECTORY = REPOSITORY / "build"
MARKER = BUILD_DIRECTORY / "result.txt"
EXECUTOR_IMAGE = "sentinel-executor:local"


class _ReusablePairingService(PairingService):
    """Dev-only: the fixed capability pairs any number of times and every
    session it issues stays valid until the process exits. Never use outside
    this script; the capability here is public by construction anyway."""

    def __init__(self, capability: str) -> None:
        super().__init__(capability, pairing_ttl=timedelta(days=1))
        self._capability = capability
        self._sessions: dict[str, datetime] = {}

    def exchange(self, capability: str) -> IssuedControlSession:
        if not hmac.compare_digest(capability, self._capability):
            raise PairingError("control:pairing_invalid_or_expired")
        token = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        self._sessions[token] = now
        return IssuedControlSession(token=token, absolute_expires_at=now + timedelta(days=1))

    def authenticate(self, session_token: str | None) -> AuthenticatedControlSession:
        created = self._sessions.get(session_token or "")
        if created is None:
            raise PairingError("control:session_invalid_or_expired")
        now = datetime.now(timezone.utc)
        return AuthenticatedControlSession(
            created_at=created,
            last_seen_at=now,
            absolute_expires_at=created + timedelta(days=1),
        )

    def logout(self, session_token: str | None) -> bool:
        return self._sessions.pop(session_token or "", None) is not None


def _policy_profile():
    environments = {
        environment: {
            "minimum_model_tier_for_confirmation": "confirm_required",
            "warn_requires_confirmation": False,
            "production_change_requires_confirmation": True,
            "unmatched_requires_confirmation": False,
            "allow_confirmation_for_verdicts": ["confirm_required"],
        }
        for environment in ("sandbox", "dev", "staging", "production")
    }
    return parse_policy_profile(
        {
            "name": "week11-playwright-real-api",
            "version": 1,
            "default_environment": "production",
            "environments": environments,
        }
    )


def _prepare_fixture() -> Path:
    if FIXTURE_ROOT.exists():
        shutil.rmtree(FIXTURE_ROOT)
    FIXTURE_ROOT.mkdir(parents=True, mode=0o700)
    FIXTURE_ROOT.chmod(0o700)
    REPOSITORY.mkdir(mode=0o700)
    subprocess.run(
        ["git", "init", "--quiet", str(REPOSITORY)],
        check=True,
        timeout=10,
    )
    BUILD_DIRECTORY.mkdir(mode=0o700)
    BUILD_DIRECTORY.chmod(0o700)
    metadata = {
        "repository": str(REPOSITORY),
        "marker": str(MARKER),
    }
    (FIXTURE_ROOT / "metadata.json").write_text(
        json.dumps(metadata, sort_keys=True),
        encoding="utf-8",
    )
    return FIXTURE_ROOT / "sentinel.sqlite3"


def _require_real_executor() -> None:
    checks = (
        (["docker", "info", "--format", "{{.ServerVersion}}"], "Docker daemon"),
        (
            ["docker", "image", "inspect", EXECUTOR_IMAGE, "--format", "{{.Id}}"],
            f"Docker image {EXECUTOR_IMAGE}",
        ),
    )
    for command, name in checks:
        try:
            subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (
            OSError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
        ) as exc:
            raise RuntimeError(
                f"{name} is required for the real Playwright flow"
            ) from exc


def run() -> None:
    _require_real_executor()
    database = _prepare_fixture()
    os.environ["SENTINEL_STATE_DB"] = str(database)
    app = create_app(
        load_model=False,
        policy_profile=_policy_profile(),
        load_policy=False,
        executor=DockerExecutor(
            image=EXECUTOR_IMAGE,
            workspace=REPOSITORY,
            writable_subdirectory="build",
            container_user=f"{os.getuid()}:{os.getgid()}",
        ),
        execution_environment="production",
        control_config=ControlConfig(
            workspace=REPOSITORY,
            pairing_capability=PAIRING_CAPABILITY,
            api_host=f"{API_HOST}:{API_PORT}",
            ui_origin=UI_ORIGIN,
            demo_mode=True,
        ),
        pairing_service=(
            _ReusablePairingService(PAIRING_CAPABILITY) if REUSABLE_PAIRING else None
        ),
    )
    if REUSABLE_PAIRING:
        print(
            "DEV: reusable pairing enabled; the fixed link pairs any browser until "
            "this process exits.",
            flush=True,
        )
    uvicorn.run(app, host=API_HOST, port=API_PORT)


if __name__ == "__main__":
    run()
