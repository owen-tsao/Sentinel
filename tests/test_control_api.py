from __future__ import annotations

import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.api.main import create_app  # noqa: E402
from sentinel.control import ControlConfig  # noqa: E402
from sentinel.execution import DockerExecutor  # noqa: E402

API_HOST = "127.0.0.1:8000"
UI_ORIGIN = "http://127.0.0.1:3000"
CAPABILITY = "phase-zero-pairing-" + ("a" * 32)


@contextmanager
def configured_control_client(
    *,
    demo_mode: bool = False,
) -> Iterator[tuple[TestClient, Path]]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        repository = root / "repository"
        repository.mkdir()
        (repository / ".git").mkdir()
        database = root / "sentinel.sqlite3"
        config = ControlConfig(
            workspace=repository,
            pairing_capability=CAPABILITY,
            api_host=API_HOST,
            ui_origin=UI_ORIGIN,
            demo_mode=demo_mode,
        )
        with patch.dict(
            os.environ,
            {"SENTINEL_STATE_DB": str(database)},
            clear=False,
        ):
            app = create_app(
                load_policy=False,
                executor=DockerExecutor(workspace=repository, runner=Mock()),
                control_config=config,
            )
            with TestClient(
                app,
                base_url=f"http://{API_HOST}",
            ) as client:
                yield client, repository


class ControlApiTests(unittest.TestCase):
    def test_control_routes_are_disabled_without_startup_configuration(self) -> None:
        client = TestClient(create_app(load_policy=False))

        response = client.get("/control/status")

        self.assertEqual(response.status_code, 404)

    def test_control_mode_rejects_ml_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            (repository / ".git").mkdir()
            config = ControlConfig(
                workspace=repository,
                pairing_capability=CAPABILITY,
                api_host=API_HOST,
                ui_origin=UI_ORIGIN,
            )

            with self.assertRaisesRegex(
                ValueError,
                "control mode requires ML loading to remain disabled",
            ):
                create_app(
                    model=Mock(),
                    load_policy=False,
                    executor=DockerExecutor(workspace=repository),
                    control_config=config,
                )

    def test_unpaired_browser_cannot_read_control_status(self) -> None:
        with configured_control_client() as (client, _):
            response = client.get(
                "/control/status",
                headers={"Origin": UI_ORIGIN},
            )

        self.assertEqual(response.status_code, 401)

    def test_pairing_requires_exact_host_and_origin(self) -> None:
        with configured_control_client() as (client, _):
            wrong_host = client.post(
                "/control/pair/exchange",
                headers={"Host": "localhost:8000", "Origin": UI_ORIGIN},
                json={"capability": CAPABILITY},
            )
            null_origin = client.post(
                "/control/pair/exchange",
                headers={"Origin": "null"},
                json={"capability": CAPABILITY},
            )
            missing_origin = client.post(
                "/control/pair/exchange",
                json={"capability": CAPABILITY},
            )

        self.assertEqual(wrong_host.status_code, 400)
        self.assertEqual(null_origin.status_code, 403)
        self.assertEqual(missing_origin.status_code, 403)

    def test_pairing_sets_a_host_only_strict_httponly_cookie(self) -> None:
        with configured_control_client() as (client, _):
            response = client.post(
                "/control/pair/exchange",
                headers={"Origin": UI_ORIGIN},
                json={"capability": CAPABILITY},
            )
            body_text = response.text
            set_cookie = response.headers["set-cookie"]

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(CAPABILITY, body_text)
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("SameSite=strict", set_cookie)
        self.assertNotIn("Domain=", set_cookie)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(
            response.headers["access-control-allow-origin"],
            UI_ORIGIN,
        )
        self.assertEqual(
            response.headers["access-control-allow-credentials"],
            "true",
        )

    def test_pairing_capability_replay_is_rejected(self) -> None:
        with configured_control_client() as (client, _):
            first = client.post(
                "/control/pair/exchange",
                headers={"Origin": UI_ORIGIN},
                json={"capability": CAPABILITY},
            )
            client.cookies.clear()
            replay = client.post(
                "/control/pair/exchange",
                headers={"Origin": UI_ORIGIN},
                json={"capability": CAPABILITY},
            )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(replay.status_code, 401)
        self.assertNotIn(CAPABILITY, replay.text)

    def test_paired_status_uses_the_server_owned_workspace_and_session(self) -> None:
        with configured_control_client() as (client, repository):
            paired = client.post(
                "/control/pair/exchange",
                headers={"Origin": UI_ORIGIN},
                json={"capability": CAPABILITY},
            )
            status = client.get(
                "/control/status",
                headers={"Origin": UI_ORIGIN},
            )

        self.assertEqual(paired.status_code, 200)
        self.assertEqual(status.status_code, 200)
        body = status.json()
        self.assertEqual(body["workspace"]["canonical_path"], str(repository.resolve()))
        self.assertTrue(body["supervision_session_id"])
        self.assertEqual(body["ml_status"], "disabled")
        self.assertEqual(body["runtime"]["backend"]["status"], "ready")
        self.assertEqual(body["runtime"]["workspace"]["status"], "ready")
        self.assertEqual(body["runtime"]["docker"]["status"], "ready")
        self.assertEqual(body["runtime"]["rules"]["status"], "unavailable")
        self.assertFalse(body["runtime"]["demo_mode"])
        self.assertIsNone(body["runtime"]["sample_repository"])
        self.assertFalse(body["mandatory_agent_connected"])
        self.assertEqual(
            body["connection_message"],
            "No mandatory agent connected.",
        )
        self.assertNotIn("session_id=", str(status.request.url))

    def test_demo_status_identifies_only_the_startup_repository(self) -> None:
        with configured_control_client(demo_mode=True) as (client, repository):
            client.post(
                "/control/pair/exchange",
                headers={"Origin": UI_ORIGIN},
                json={"capability": CAPABILITY},
            )
            status = client.get(
                "/control/status",
                headers={"Origin": UI_ORIGIN},
            )

        self.assertTrue(status.json()["runtime"]["demo_mode"])
        self.assertEqual(
            status.json()["runtime"]["sample_repository"],
            str(repository.resolve()),
        )

    def test_logout_invalidates_the_control_session(self) -> None:
        with configured_control_client() as (client, _):
            client.post(
                "/control/pair/exchange",
                headers={"Origin": UI_ORIGIN},
                json={"capability": CAPABILITY},
            )
            logout = client.post(
                "/control/logout",
                headers={"Origin": UI_ORIGIN},
            )
            after_logout = client.get(
                "/control/status",
                headers={"Origin": UI_ORIGIN},
            )

        self.assertEqual(logout.status_code, 200)
        self.assertEqual(after_logout.status_code, 401)

    def test_pairing_schema_rejects_unknown_fields(self) -> None:
        with configured_control_client() as (client, _):
            response = client.post(
                "/control/pair/exchange",
                headers={"Origin": UI_ORIGIN},
                json={
                    "capability": CAPABILITY,
                    "session_id": "caller-selected",
                },
            )

        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
