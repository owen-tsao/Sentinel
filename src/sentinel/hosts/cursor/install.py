"""`sentinel cursor install` and `sentinel cursor doctor`.

Install writes two files under the person's Cursor directory: the forwarder
script and the user-level hooks file, merged with whatever is already there.
Doctor checks the same two files, the interpreter, the port, and pushes one
synthetic `preToolUse` through the exact installed command line.

What install promises (docs/Week 18 Plan.md §2, reviews S23/S24/C15):
- foreign hook entries are kept, never reordered or deleted;
- re-running changes nothing (idempotent): Sentinel's entries are matched
  by the forwarder's file name and replaced in place;
- a hooks file that is not valid JSON, not an object, or a symlink is
  refused rather than overwritten;
- writes go through a temp file and `os.replace`.

What doctor says honestly: Cursor's user-level hooks file is the person's
own and the agent can edit it, so enforcement is `advisory` at best. It
exits 1 for `advisory` by design, so a script that wants `mandatory` fails.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from sentinel.hosts.cursor import forwarder as forwarder_module
from sentinel.hosts.cursor.schemas import EVENTS, GATING_EVENTS
from sentinel.hosts.cursor.service import FORWARDER_NAME, MIN_CURSOR_VERSION

HOOK_TIMEOUT_SECONDS = 5
ROUND_TRIP_WARN_MS = 100   # plan §3: the forwarder budget; above it, shell + curl is the fallback
EVENT_ORDER = ("beforeSubmitPrompt", "preToolUse", "beforeShellExecution", "beforeMCPExecution", "postToolUse",
               "postToolUseFailure")
assert set(EVENT_ORDER) == EVENTS


class InstallError(Exception):
    pass


@dataclass
class InstallResult:
    hooks_file: Path
    script: Path
    changed: bool
    foreign_entries: int
    lines: list[str]
    warnings: list[str] = field(default_factory=list)


def default_cursor_dir() -> Path:
    return Path.home() / ".cursor"


def hook_command(*, python: str, script: Path, port: int, event: str) -> str:
    # `-I` (isolated): ignore PYTHONPATH, PYTHON* env, and the script's own
    # directory on sys.path, so nothing planted beside the script or in the
    # environment can shadow `json`/`urllib` (review G2).
    return f"{_quote(python)} -I {_quote(str(script))} --port {int(port)} {event}"


def sentinel_entry(*, python: str, script: Path, port: int, event: str) -> dict[str, Any]:
    return {"command": hook_command(python=python, script=script, port=port, event=event),
            "timeout": HOOK_TIMEOUT_SECONDS, "failClosed": True}


def is_sentinel_entry(entry: Any) -> bool:
    return isinstance(entry, dict) and isinstance(entry.get("command"), str) and FORWARDER_NAME in entry["command"]


def merge_hooks(existing: dict[str, Any], *, python: str, script: Path, port: int) -> tuple[dict[str, Any], int]:
    """The hooks document with Sentinel's entries in place. Returns it and
    the number of foreign entries kept."""
    document: dict[str, Any] = dict(existing)
    document.setdefault("version", 1)
    hooks = document.get("hooks")
    if hooks is None:
        hooks = {}
    if not isinstance(hooks, dict):
        raise InstallError("the hooks file's `hooks` field is not an object; refusing to rewrite it")
    merged: dict[str, Any] = {}
    foreign = 0
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            raise InstallError(f"the hooks file's `hooks.{event}` is not a list; refusing to rewrite it")
        kept = [e for e in entries if not is_sentinel_entry(e)]
        foreign += len(kept)
        merged[event] = kept
    for event in EVENT_ORDER:
        entry = sentinel_entry(python=python, script=script, port=port, event=event)
        if event not in merged:
            merged[event] = []
        if event in GATING_EVENTS:
            merged[event] = [entry] + merged[event]   # a deny from Sentinel is read first; any deny wins anyway
        else:
            merged[event] = merged[event] + [entry]
    document["hooks"] = merged
    return document, foreign


def _read_hooks_document(path: Path) -> dict[str, Any]:
    if os.path.islink(path):
        raise InstallError(f"{path} is a symlink; refusing to write through it")
    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InstallError(f"cannot read {path}: {exc}") from exc
    if not text.strip():
        return {}
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise InstallError(f"{path} is not valid JSON ({exc}); fix or move it, then re-run") from exc
    if not isinstance(document, dict):
        raise InstallError(f"{path} is not a JSON object; refusing to rewrite it")
    return document


def _write_atomically(path: Path, text: str, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def install(*, port: int, python: str = sys.executable, cursor_dir: Optional[Path] = None) -> InstallResult:
    cursor_dir = cursor_dir if cursor_dir is not None else default_cursor_dir()
    hooks_file = cursor_dir / "hooks.json"
    script = cursor_dir / "hooks" / FORWARDER_NAME
    # Recorded as given (absolute), not realpath'd: a Homebrew Cellar path
    # changes on every minor upgrade and would silently break every hook.
    python = os.path.abspath(python)
    source = Path(forwarder_module.__file__).read_text(encoding="utf-8")
    for candidate in (cursor_dir, script.parent, script):
        if os.path.islink(candidate):
            raise InstallError(f"{candidate} is a symlink; refusing to write through it")
    warnings: list[str] = []
    if _looks_ephemeral(python):
        warnings.append(f"interpreter {python} lives in a virtual environment; if it is removed, every gating hook fails "
                        "closed with no reason shown. Prefer a system `python3` (`sentinel cursor install` picks one when it can).")
    existing_script = script.read_text(encoding="utf-8") if script.exists() else None
    existing = _read_hooks_document(hooks_file)
    merged, foreign = merge_hooks(existing, python=python, script=script, port=port)
    changed = False
    if existing_script != source:
        _write_atomically(script, source, mode=0o755)
        changed = True
    new_text = json.dumps(merged, indent=2) + "\n"
    old_text = hooks_file.read_text(encoding="utf-8") if hooks_file.exists() else None
    if old_text is None or json.loads(old_text or "{}") != merged:
        _write_atomically(hooks_file, new_text, mode=0o644)
        changed = True
    lines = [
        f"forwarder: {script} ({'written' if existing_script != source else 'unchanged'})",
        f"hooks file: {hooks_file} ({'updated' if changed else 'unchanged'}; {foreign} other hook entr{'y' if foreign == 1 else 'ies'} kept)",
        f"interpreter: {python}",
        f"events: {', '.join(EVENT_ORDER)}",
        "enforcement: advisory (the hooks file is yours to edit, so the agent can edit it too)",
        "next: start `sentinel serve`, then run `sentinel cursor doctor`; Cursor reloads hooks on its own.",
    ]
    lines.extend(f"warning: {w}" for w in warnings)
    return InstallResult(hooks_file=hooks_file, script=script, changed=changed, foreign_entries=foreign, lines=lines,
                         warnings=warnings)


# ---------------------------------------------------------------------- doctor

@dataclass
class DoctorResult:
    state: str                 # advisory | unsupported
    failed: list[str]
    warnings: list[str]
    lines: list[str]

    @property
    def ok(self) -> bool:
        return self.state == "mandatory"   # never true on Cursor: by design doctor exits 1


def _parse_version(text: Optional[str]) -> Optional[tuple[int, ...]]:
    if not text:
        return None
    parts = text.strip().split(".")
    try:
        return tuple(int(p) for p in parts[:3])
    except ValueError:
        return None


def cursor_version() -> Optional[str]:
    """Cursor's version, if `cursor --version` answers in time."""
    try:
        out = subprocess.run(["cursor", "--version"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    first = (out.stdout or "").strip().splitlines()
    return first[0].strip() if first else None


def doctor(*, port: int, cursor_dir: Optional[Path] = None, probe: bool = True, version: Optional[str] = None,
           workspace_roots: Optional[list[str]] = None, latency_samples: int = 5) -> DoctorResult:
    cursor_dir = cursor_dir if cursor_dir is not None else default_cursor_dir()
    hooks_file = cursor_dir / "hooks.json"
    script = cursor_dir / "hooks" / FORWARDER_NAME
    failed: list[str] = []
    warnings: list[str] = []
    lines = [f"hooks file: {hooks_file}", f"forwarder: {script}"]

    document: dict[str, Any] = {}
    if not hooks_file.exists():
        failed.append("hooks_file_missing")
    else:
        try:
            document = _read_hooks_document(hooks_file)
        except InstallError as exc:
            failed.append(f"hooks_file_unreadable:{exc}")
    commands: dict[str, str] = {}
    for event in EVENT_ORDER:
        entries = (document.get("hooks") or {}).get(event) if isinstance(document.get("hooks"), dict) else None
        ours = [e for e in (entries or []) if is_sentinel_entry(e)]
        if not ours:
            if hooks_file.exists():
                # An empty or `{}` file is as unregistered as a missing event (review M2).
                failed.append(f"event_not_registered:{event}")
            continue
        entry = ours[0]
        commands[event] = entry["command"]
        if event in GATING_EVENTS and entry.get("failClosed") is not True:
            failed.append(f"fail_closed_off:{event}")
        if f"--port {port} " not in entry["command"] + " ":
            failed.append(f"port_mismatch:{event}")
    if not script.exists():
        failed.append("forwarder_missing")
    else:
        try:
            if script.read_text(encoding="utf-8") != Path(forwarder_module.__file__).read_text(encoding="utf-8"):
                warnings.append("forwarder differs from this Sentinel's copy; re-run `sentinel cursor install`")
        except OSError:
            failed.append("forwarder_unreadable")
    for command in commands.values():
        try:
            interpreter = shlex.split(command)[0]
        except (ValueError, IndexError):
            failed.append("command_unparseable")
            break
        if not os.path.exists(interpreter):
            failed.append(f"interpreter_missing:{interpreter}")
        elif _looks_ephemeral(interpreter):
            warnings.append(f"interpreter {interpreter} lives in a virtual environment; if it is removed every gating hook fails closed with no reason shown")
        break
    version = version if version is not None else cursor_version()
    parsed = _parse_version(version)
    if parsed is None:
        warnings.append("Cursor version unknown (`cursor --version` did not answer); the hook contract is verified on 3.24.12 only")
    elif parsed < MIN_CURSOR_VERSION:
        warnings.append(f"Cursor {version} is older than {'.'.join(map(str, MIN_CURSOR_VERSION))}, the only version the hook contract is verified on")
    if workspace_roots is not None and len(workspace_roots) > 1:
        warnings.append("multi-root workspace: Sentinel uses the first root only this week")

    if probe:
        reachable = _server_reachable(port)
        lines.append(f"server: {'reachable' if reachable else 'not reachable'} on 127.0.0.1:{port}")
        if not reachable:
            failed.append("server_unreachable")
        if "preToolUse" in commands and "forwarder_missing" not in failed:
            outcome = _synthetic_pre_tool_use(commands["preToolUse"], cwd=str(cursor_dir), expect_server=reachable)
            lines.append(f"synthetic preToolUse through the installed command: {outcome}")
            if not outcome.startswith("ok"):
                failed.append("synthetic_event_failed")
            elif reachable and latency_samples > 0:
                # The only honest end-to-end number: wall clock around the whole
                # hook process (interpreter start, imports, POST, print). The
                # `forwarder_ms` field in rows starts its clock after start-up
                # and so under-counts by the part that dominates.
                samples = _round_trip_ms(commands["preToolUse"], cwd=str(cursor_dir), count=latency_samples)
                if samples:
                    samples.sort()
                    median = samples[len(samples) // 2]
                    lines.append(f"hook round trip ({len(samples)} samples): median {median:.0f} ms, max {samples[-1]:.0f} ms")
                    if median > ROUND_TRIP_WARN_MS:
                        warnings.append(f"hook round trip median {median:.0f} ms exceeds {ROUND_TRIP_WARN_MS} ms; "
                                        "every tool call waits this long")

    state = "unsupported" if any(f.startswith(("hooks_file_missing", "hooks_file_unreadable", "forwarder_missing",
                                                "event_not_registered:preToolUse")) for f in failed) else "advisory"
    lines.append(f"enforcement: {state}" + (" (the hooks file is user-writable; the agent could edit it)" if state == "advisory" else ""))
    if failed:
        lines.append("failed checks:")
        lines.extend(f"  - {f}" for f in failed)
    if warnings:
        lines.append("warnings:")
        lines.extend(f"  - {w}" for w in warnings)
    return DoctorResult(state=state, failed=failed, warnings=warnings, lines=lines)


def _server_reachable(port: int) -> bool:
    """A GET on `/health`: no hook route is touched, so doctor writes no rows."""
    request = urllib.request.Request(f"http://127.0.0.1:{port}/health", headers={"Host": f"127.0.0.1:{port}"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=2) as response:  # noqa: S310 - loopback only
            return response.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _synthetic_event() -> dict[str, Any]:
    """A harmless Shell `preToolUse`. The session id says what it is, so its rows are recognisable."""
    return {"conversation_id": "sentinel-doctor", "session_id": "sentinel-doctor", "hook_event_name": "preToolUse",
            "tool_name": "Shell", "tool_input": {"command": "true", "cwd": "", "timeout": 1000}, "tool_use_id": "doctor-1",
            "workspace_roots": [], "cwd": ""}


def _round_trip_ms(command: str, *, cwd: str, count: int) -> list[float]:
    """Wall-clock milliseconds for `count` runs of the installed hook command on the synthetic event."""
    event = json.dumps({**_synthetic_event(), "workspace_roots": [cwd]})
    out: list[float] = []
    for _ in range(count):
        started = time.perf_counter()
        try:
            subprocess.run(command, shell=True, input=event, capture_output=True, text=True,
                           timeout=HOOK_TIMEOUT_SECONDS + 2, cwd=cwd, check=False)
        except (subprocess.TimeoutExpired, OSError):
            return out
        out.append((time.perf_counter() - started) * 1000.0)
    return out


def _synthetic_pre_tool_use(command: str, *, cwd: str, expect_server: bool) -> str:
    """Run the installed command line on a harmless Shell event. With the
    server up the answer must be `{}`; with it down, a deny that names it."""
    event = {**_synthetic_event(), "workspace_roots": [cwd]}
    try:
        run = subprocess.run(command, shell=True, input=json.dumps(event), capture_output=True, text=True,
                             timeout=HOOK_TIMEOUT_SECONDS + 2, cwd=cwd, check=False)
    except subprocess.TimeoutExpired:
        return "failed: the hook did not answer within the hook timeout"
    except OSError as exc:
        return f"failed: {exc}"
    if run.returncode != 0:
        return f"failed: exit {run.returncode}: {(run.stderr or '').strip()[:200]}"
    try:
        body = json.loads(run.stdout)
    except ValueError:
        return f"failed: non-JSON output {run.stdout[:80]!r}"
    if expect_server:
        return "ok (allowed, {})" if body == {} else f"failed: expected {{}} from a harmless command, got {body}"
    if body.get("permission") == "deny" and "not running" in str(body.get("user_message", "")):
        return "ok (denied with the 'not running' reason, as designed while the server is down)"
    return f"failed: expected a 'not running' deny while the server is down, got {body}"


def _quote(text: str) -> str:
    return text if all(c.isalnum() or c in "/._-:+" for c in text) else "'" + text.replace("'", "'\\''") + "'"


def which_python() -> str:
    """The interpreter the hook command records. The forwarder needs only the
    standard library, so the most durable `python3` wins: a system or
    package-manager one found on the *default* PATH, never the virtual
    environment this command happens to run in (review M3: under `uv run`,
    `shutil.which("python3")` is the project venv, which dies with
    `rm -rf .venv` and would then deny every call with no reason shown)."""
    for candidate in ("/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"):
        if os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate
    found = shutil.which("python3", path=os.defpath)
    if found and not _looks_ephemeral(found):
        return found
    found = shutil.which("python3")
    if found and not _looks_ephemeral(found):
        return found
    return sys.executable


def _looks_ephemeral(interpreter: str) -> bool:
    parts = Path(interpreter).parts
    return any(p in {".venv", "venv", "site-packages", "virtualenvs"} for p in parts) or os.path.exists(
        Path(interpreter).resolve().parent.parent / "pyvenv.cfg") or os.path.exists(Path(interpreter).parent.parent / "pyvenv.cfg")


__all__ = ["DoctorResult", "InstallError", "InstallResult", "doctor", "hook_command", "install", "is_sentinel_entry",
           "merge_hooks", "sentinel_entry"]
