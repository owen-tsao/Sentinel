#!/usr/bin/env python3
"""Launch the disposable Phase 0 gateway for a live Cursor run.

Mints fresh adapter and approver capabilities in a private 0700 directory,
starts the fixture gateway, and prints the exact `.cursor/mcp.json` entry plus
the approver commands. Capabilities are never printed to the terminal; the
approver capability is read from its file by the `approve`/`deny`/`state`
subcommands so the human path stays separate from the agent path.

Usage:
  python3.12 scripts/week12_spike/launch.py serve            # foreground gateway
  python3.12 scripts/week12_spike/launch.py state
  python3.12 scripts/week12_spike/launch.py approve APPROVAL_ID
  python3.12 scripts/week12_spike/launch.py deny APPROVAL_ID
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRIVATE = Path(os.environ.get("SENTINEL_SPIKE_PRIVATE_DIR", Path.home() / ".sentinel-spike-week12"))
PORT = int(os.environ.get("SENTINEL_SPIKE_PORT", "8765"))
BASE = f"http://127.0.0.1:{PORT}"


def _write_private(path: Path, value: str) -> None:
    path.write_text(value)
    os.chmod(path, 0o600)


def serve() -> int:
    PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(PRIVATE, 0o700)
    adapter_cap, approver_cap = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    _write_private(PRIVATE / "adapter.capability", adapter_cap)
    _write_private(PRIVATE / "approver.capability", approver_cap)
    _write_private(PRIVATE / "adapter.sha256", hashlib.sha256(adapter_cap.encode()).hexdigest())
    _write_private(PRIVATE / "approver.sha256", hashlib.sha256(approver_cap.encode()).hexdigest())
    mcp_entry = {
        "mcpServers": {
            "sentinel-spike": {
                "command": sys.executable,
                "args": [str(HERE / "mcp_shim.py")],
                "env": {
                    "SENTINEL_SPIKE_GATEWAY_URL": BASE,
                    "SENTINEL_SPIKE_ADAPTER_CAPABILITY_FILE": str(PRIVATE / "adapter.capability"),
                    "SENTINEL_SPIKE_TIMEOUT_SECONDS": "5",
                },
            }
        }
    }
    print("Add this to .cursor/mcp.json (capabilities stay in files, not in this JSON):")
    print(json.dumps(mcp_entry, indent=2))
    print(f"\nPrivate state: {PRIVATE}\nGateway: {BASE}\n", flush=True)
    return subprocess.call([
        sys.executable, str(HERE / "fixture_gateway.py"), "--port", str(PORT),
        "--state-dir", str(PRIVATE / "state"),
        "--adapter-hash-file", str(PRIVATE / "adapter.sha256"),
        "--approver-hash-file", str(PRIVATE / "approver.sha256"),
    ])


def approver(path: str, body: dict | None) -> int:
    cap = (PRIVATE / "approver.capability").read_text().strip()
    request = urllib.request.Request(
        BASE + path, data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {cap}", "Content-Type": "application/json"},
        method="POST" if body is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            print(json.dumps(json.loads(response.read()), indent=2))
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code}: {exc.read().decode(errors='replace')}")
        return 1
    return 0


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if command == "serve":
        return serve()
    if command == "state":
        return approver("/spike/state", None)
    if command in {"approve", "deny"} and len(sys.argv) == 3:
        return approver(f"/spike/approvals/{sys.argv[2]}/{command}", {})
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
