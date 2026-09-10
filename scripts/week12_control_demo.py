"""Launch the Week 12 live proof: control API + startup ceiling + MCP fixture.

Run this from YOUR terminal, not from an agent shell, so the private state
directory (state DB, fixture DB, adapter capability) is created by the trusted
launcher rather than by the agent being supervised.

    python3 scripts/week12_control_demo.py            # start everything
    python3 scripts/week12_control_demo.py state PATH # inspect a run's fixture

Environment:
    SENTINEL_UI_ORIGIN   default http://127.0.0.1:3100 (the Next.js dev port)
    SENTINEL_DEMO_NO_BROWSER=1 to skip opening the pairing link
"""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

if os.environ.get("SENTINEL_ENABLE_ML", "false") != "false":
    raise RuntimeError("Week 12 control demo requires SENTINEL_ENABLE_ML=false")

import uvicorn  # noqa: E402

from sentinel.api.main import create_app  # noqa: E402
from sentinel.control import ControlConfig, generate_pairing_capability  # noqa: E402
from sentinel.execution import DockerExecutor  # noqa: E402
from sentinel.supervision import week12_fixture_policy  # noqa: E402

API_HOST = "127.0.0.1"
API_PORT = 8000
UI_ORIGIN = os.environ.get("SENTINEL_UI_ORIGIN", "http://127.0.0.1:3100")
FIXTURE_ISSUES = {
    "SPIKE-1": "Login page returns 500 after password reset",
    "SPIKE-2": "CSV export drops rows with unicode names",
    "SPIKE-3": "Nightly job retries forever on 429",
}


def _open_pairing_link_when_ready(capability: str) -> None:
    for _ in range(200):
        try:
            with socket.create_connection((API_HOST, API_PORT), timeout=0.1):
                webbrowser.open(f"{UI_ORIGIN}/#pair={quote(capability)}")
                return
        except OSError:
            time.sleep(0.1)


def _private_root() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    root = Path.home() / ".sentinel" / "week12-demo" / stamp
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    return root


def run() -> None:
    root = _private_root()
    repository = root / "sample-repository"
    repository.mkdir(mode=0o700)
    subprocess.run(["git", "init", "--quiet", str(repository)], check=True, timeout=10)
    (repository / "build").mkdir(mode=0o700)
    state_database = root / "sentinel.sqlite3"
    os.environ["SENTINEL_STATE_DB"] = str(state_database)

    pairing = generate_pairing_capability()
    app = create_app(
        executor=DockerExecutor(
            workspace=repository,
            writable_subdirectory="build",
            container_user=f"{os.getuid()}:{os.getgid()}",
        ),
        control_config=ControlConfig(
            workspace=repository,
            pairing_capability=pairing,
            ui_origin=UI_ORIGIN,
            demo_mode=True,
        ),
        supervision_policy=week12_fixture_policy(),
    )
    app.state.mcp_fixture.seed(FIXTURE_ISSUES)
    issued = app.state.adapter_registry.issue(
        adapter_kind="cursor_mcp",
        tool_family="sentinel_issue_fixture",
    )
    capability_file = root / "adapter_capability"
    capability_file.touch(mode=0o600)
    capability_file.write_text(issued.capability + "\n", encoding="utf-8")
    capability_file.chmod(0o600)

    mcp_entry = {
        "mcpServers": {
            "sentinel": {
                "command": sys.executable,
                "args": [str(ROOT / "src" / "sentinel" / "mcp" / "server.py")],
                "env": {
                    "SENTINEL_API_URL": f"http://{API_HOST}:{API_PORT}",
                    "SENTINEL_ADAPTER_CAPABILITY_FILE": str(capability_file),
                },
            }
        }
    }
    print(f"Private run directory : {root}")
    print(f"Disposable repository : {repository}")
    print(f"Fixture database      : {root / 'mcp_fixture.sqlite3'}")
    print(f"Control API           : http://{API_HOST}:{API_PORT}")
    print(f"Control UI origin     : {UI_ORIGIN}  (start: cd web && npm run dev -- --hostname 127.0.0.1 --port {UI_ORIGIN.rsplit(':', 1)[-1]})")
    print(f"Adapter capability    : {capability_file} (0600; never paste its contents anywhere)")
    print(f"Ceiling sha256        : {app.state.supervision_policy_binding.content_sha256}")
    print("\nPaste into .cursor/mcp.json (workspace) to connect Cursor:\n")
    print(json.dumps(mcp_entry, indent=2))
    print(f"\nInspect fixture later : python3 scripts/week12_control_demo.py state {root}\n")
    if os.environ.get("SENTINEL_DEMO_NO_BROWSER") != "1":
        print("Opening a one-use pairing link in the default browser.")
        threading.Thread(target=_open_pairing_link_when_ready, args=(pairing,), daemon=True).start()
    uvicorn.run(app, host=API_HOST, port=API_PORT)


def state(root: Path) -> None:
    """Print fixture notes and operation states without starting anything."""

    database = root / "mcp_fixture.sqlite3"
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    notes = connection.execute(
        "SELECT issue_id, body, attempt_id, created_at FROM fixture_notes ORDER BY note_id"
    ).fetchall()
    operations = connection.execute(
        "SELECT attempt_id, operation, issue_id, state, updated_at FROM fixture_operations ORDER BY created_at"
    ).fetchall()
    print(f"notes: {len(notes)}")
    for row in notes:
        print(f"  {row['issue_id']}  {row['body']!r}  attempt={row['attempt_id']}  at={row['created_at']}")
    print(f"operations: {len(operations)}")
    for row in operations:
        print(f"  {row['state']:<10} {row['operation']:<15} {row['issue_id']:<8} attempt={row['attempt_id']}")


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "state":
        state(Path(sys.argv[2]).expanduser())
    else:
        run()
