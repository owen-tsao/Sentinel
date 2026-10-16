"""`sentinel claude-code install` and `doctor`: the managed settings fragment
and the checks that say whether the hook is actually locked.

Sentinel never writes the managed path itself. It prints the fragment and
the `sudo` command; the person places it. That keeps the file root-owned by
construction, which is the first thing `doctor` checks.
"""

from __future__ import annotations

import json
import os
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

from sentinel.hosts.claude_code.settings_check import (
    collect_facts,
    evaluate_enforcement,
    managed_settings_path,
    parse_version,
)
from sentinel.supervision.floor_policy import FloorPolicy

LAUNCHD_LABEL = "com.sentinel.serve"
SESSION_HOOK_MODULE = "sentinel.hosts.claude_code.session_start_hook"


ADVISORY_HOOK_EVENTS = ("UserPromptSubmit", "PostToolUseFailure")


def _matcher(tools: frozenset[str]) -> str:
    return "|".join(sorted(tools))


def managed_fragment(policy: FloorPolicy, *, python: str = sys.executable) -> dict[str, Any]:
    """The managed settings Claude Code needs. Every field here is checked by
    `evaluate_enforcement`; change one and `doctor` says `advisory`."""
    base = policy.hook.server_url.rsplit("/", 1)[0]
    timeout = policy.hook.max_timeout_seconds
    http = lambda path: {"type": "http", "url": f"{base}/{path}", "timeout": timeout}  # noqa: E731
    return {
        "allowManagedHooksOnly": True,
        "allowedHttpHookUrls": [f"{base}/*"],
        "hooks": {
            "SessionStart": [{"hooks": [{"type": "command", "command": f"{python} -m {SESSION_HOOK_MODULE}", "timeout": 10}]}],
            "PreToolUse": [{"matcher": _matcher(policy.hook.tools),
                            "hooks": [{**http("pre-tool-use"), "onFailure": "block"}]}],
            "PostToolUse": [{"matcher": _matcher(policy.hook.tools), "hooks": [http("post-tool-use")]}],
            "PostToolUseFailure": [{"matcher": _matcher(policy.hook.tools), "hooks": [http("post-tool-use-failure")]}],
            "UserPromptSubmit": [{"hooks": [http("user-prompt-submit")]}],
            "PermissionRequest": [{"hooks": [http("permission-request")]}],
            "PermissionDenied": [{"hooks": [http("permission-denied")]}],
            "ConfigChange": [{"hooks": [http("config-change")]}],
        },
    }


def install_text(policy: FloorPolicy, *, python: str = sys.executable) -> str:
    target = managed_settings_path()
    fragment = json.dumps(managed_fragment(policy, python=python), indent=2)
    if target is None:
        return f"# Managed settings are not supported on {platform.system()} by this installer.\n{fragment}\n"
    return (
        f"# 1. Review the managed settings below. They point Claude Code at {policy.hook.server_url}\n"
        f"#    and make a stopped or failing Sentinel block every tool call (onFailure=block).\n"
        f"# 2. Write them as root so the agent cannot edit them:\n"
        f"#      sudo mkdir -p \"{target.parent}\"\n"
        f"#      sudo tee \"{target}\" > /dev/null <<'EOF'\n{fragment}\nEOF\n"
        f"#      sudo chmod 644 \"{target}\"\n"
        f"# 3. Keep Sentinel running: `sentinel serve` (or install the launchd agent: `sentinel claude-code launchd`).\n"
        f"# 4. Check: `sentinel claude-code doctor`.\n"
    )


def launchd_plist(*, python: str, state_db: Path, port: int, log_dir: Path) -> str:
    args = [python, "-m", "sentinel.cli", "serve", "--state-db", str(state_db), "--port", str(port)]
    items = "".join(f"\n      <string>{a}</string>" for a in args)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key><string>{LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>{items}
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>{log_dir / 'sentinel.out.log'}</string>
    <key>StandardErrorPath</key><string>{log_dir / 'sentinel.err.log'}</string>
  </dict>
</plist>
"""


@dataclass
class DoctorResult:
    state: str
    failed: list[str]
    lines: list[str]

    @property
    def ok(self) -> bool:
        return self.state == "mandatory"


def doctor(policy: FloorPolicy, *, claude_version: Optional[str] = None, probe: bool = True,
           settings_path: Optional[Path] = None) -> DoctorResult:
    path = settings_path if settings_path is not None else managed_settings_path()
    facts = collect_facts(path, server_url=policy.hook.server_url, probe_port=probe)
    version = claude_version or _claude_version()
    # `doctor` runs outside a session, so liveness is proven by a synthetic
    # event instead: one PreToolUse POST through the exact configured URL. This
    # catches the Host-header mismatch (`localhost` vs `127.0.0.1`) that would
    # otherwise turn every real call into a block.
    synthetic = _synthetic_event(policy.hook.server_url) if probe and facts.listener == "sentinel" else None
    # Liveness in `evaluate_enforcement` means "the host's hooks are reaching
    # us", which only a session can show. Our own synthetic POST proves the
    # URL and Host header, not the host's configuration, so it is reported
    # separately and the absent-file case stays `advisory` here.
    report = evaluate_enforcement(facts, policy.hook, claude_version=version, liveness=False)
    lines = [f"managed settings: {path}" if path else "managed settings: unsupported on this OS",
             f"  exists={facts.exists} owner_uid={facts.owner_uid} mode={oct(facts.mode) if facts.mode is not None else None}",
             f"  parse_error={facts.parse_error}" if facts.parse_error else "  parsed ok" if facts.exists else "  (absent)",
             f"sentinel listener at {urlsplit(policy.hook.server_url).netloc}: {facts.listener}",
             f"synthetic PreToolUse through {policy.hook.server_url}: {synthetic or 'skipped'}",
             f"claude version: {version or 'unknown'} (need >= {'.'.join(map(str, policy.hook.min_claude_version))})"]
    failed = [f for f in report.failed if f != "no_hook_call_observed"]
    if synthetic not in (None, "ok"):
        failed.append(f"synthetic_event_failed:{synthetic}")
    state = "mandatory" if not failed else "advisory"
    lines.append(f"enforcement: {state}")
    # Week 17 advisory hooks. Their absence never changes the enforcement claim
    # (they cannot deny anything); it only means the boundary line and the
    # error-loop signal are off, so the person is told.
    hooks = (facts.content or {}).get("hooks") or {} if isinstance(facts.content, dict) else {}
    missing = [name for name in ADVISORY_HOOK_EVENTS if not hooks.get(name)]
    if facts.exists and missing:
        lines.append(f"advisory hooks missing: {', '.join(missing)} (boundary line / stuck error signal off; re-run install)")
    if failed:
        lines.append("failed checks:")
        lines.extend(f"  - {f}: {EXPLANATIONS.get(f.split(':')[0], '')}".rstrip(": ") for f in failed)
    return DoctorResult(state=state, failed=failed, lines=lines)


def _synthetic_event(server_url: str) -> str:
    import urllib.error
    import urllib.request
    import uuid

    body = json.dumps({"session_id": f"sentinel-doctor-{uuid.uuid4()}", "hook_event_name": "PreToolUse",
                       "tool_name": "SentinelDoctor", "tool_input": {}, "tool_use_id": "doctor",
                       "cwd": str(Path.home())}).encode("utf-8")
    request = urllib.request.Request(server_url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=3) as response:  # noqa: S310 - loopback only
            payload = json.loads(response.read(65_536).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return f"http_{exc.code}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return f"unreachable:{type(exc).__name__}"
    return "ok" if payload == {} else "unexpected_body"


EXPLANATIONS = {
    "managed_settings_missing": "no managed settings file; run `sentinel claude-code install` and place the fragment as root",
    "managed_settings_unparseable": "the managed settings file is not a JSON object",
    "managed_settings_not_root_owned": "the file must be owned by root so the agent cannot edit it",
    "managed_settings_group_or_world_writable": "chmod 644 the file",
    "allow_managed_hooks_only_not_set": "set allowManagedHooksOnly: true so project/user hooks cannot run",
    "allowed_http_hook_urls_not_pinned": "pin allowedHttpHookUrls to Sentinel's URL or a local file can switch the hook off",
    "pre_tool_use_entry_missing": "no PreToolUse http hook points at Sentinel's URL",
    "matcher_missing": "the PreToolUse matcher does not cover this tool",
    "on_failure_not_block": "set onFailure: block on the PreToolUse hook or a stopped Sentinel lets everything through",
    "timeout_too_long": "set timeout to at most the policy's max (seconds)",
    "hook_is_async": "the PreToolUse hook must not be async",
    "claude_version_unknown": "could not run `claude --version`",
    "claude_version_too_old": "onFailure: block needs Claude Code 2.1.295 or later",
    "no_hook_call_observed": "no PreToolUse reached Sentinel yet (start Sentinel and run doctor with the probe on)",
    "synthetic_event_failed": "a PreToolUse posted to the configured URL did not get an empty 200; check the Host/port in the URL",
    "foreign_listener_on_sentinel_port": "something that is not Sentinel answers on Sentinel's port",
    "sentinel_not_listening": "start Sentinel: `sentinel serve`",
}


def _claude_version() -> Optional[str]:
    import subprocess

    try:
        out = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (out.stdout or out.stderr or "").strip()
    return text if parse_version(text) else None


def default_state_db() -> Path:
    return Path(os.environ.get("SENTINEL_STATE_DB") or (Path.home() / ".sentinel" / "state.sqlite3"))
