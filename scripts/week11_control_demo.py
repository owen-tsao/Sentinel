"""Launch a disposable, explicitly identified Week 11 control-center demo."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from pathlib import Path
from urllib.parse import quote

import uvicorn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

if os.environ.get("SENTINEL_ENABLE_ML", "false") != "false":
    raise RuntimeError("Week 11 control demo requires SENTINEL_ENABLE_ML=false")

from sentinel.api.main import create_app  # noqa: E402
from sentinel.control import (  # noqa: E402
    ControlConfig,
    generate_pairing_capability,
)
from sentinel.execution import DockerExecutor  # noqa: E402

API_HOST = "127.0.0.1"
API_PORT = 8000
UI_ORIGIN = "http://127.0.0.1:3000"


def _open_pairing_link_when_ready(capability: str) -> None:
    for _ in range(100):
        try:
            with socket.create_connection((API_HOST, API_PORT), timeout=0.1):
                webbrowser.open(f"{UI_ORIGIN}/#pair={quote(capability)}")
                return
        except OSError:
            time.sleep(0.1)


def run() -> None:
    with tempfile.TemporaryDirectory(prefix="sentinel-week11-demo-") as directory:
        root = Path(directory)
        repository = root / "sample-repository"
        repository.mkdir(mode=0o700)
        subprocess.run(
            ["git", "init", "--quiet", str(repository)],
            check=True,
            timeout=10,
        )
        build = repository / "build"
        build.mkdir(mode=0o700)
        build.chmod(0o700)
        state_database = root / "sentinel.sqlite3"
        os.environ["SENTINEL_STATE_DB"] = str(state_database)
        capability = generate_pairing_capability()
        app = create_app(
            executor=DockerExecutor(
                workspace=repository,
                writable_subdirectory="build",
                container_user=f"{os.getuid()}:{os.getgid()}",
            ),
            control_config=ControlConfig(
                workspace=repository,
                pairing_capability=capability,
                demo_mode=True,
            ),
        )

        print(f"Disposable demo repository: {repository}")
        print(f"Control API: http://{API_HOST}:{API_PORT}")
        if os.environ.get("SENTINEL_DEMO_NO_BROWSER") != "1":
            print("Opening a one-use pairing link in the default browser.")
            threading.Thread(
                target=_open_pairing_link_when_ready,
                args=(capability,),
                daemon=True,
            ).start()
        uvicorn.run(app, host=API_HOST, port=API_PORT)


if __name__ == "__main__":
    run()
