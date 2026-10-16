"""Is the hook actually locked against the agent? Computed from facts the
server owns, never from what the hook says about itself.

`collect_facts` does the I/O (stat, read, parse, probe the port).
`evaluate_enforcement` is pure and is what the tests exercise. The result is
one of `mandatory`, `advisory`, or `unknown` with every failed check named,
so `sentinel claude-code doctor` can print exactly what to fix.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import platform
import re
import stat
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Optional
from urllib.parse import urlsplit

from sentinel.supervision.floor_policy import HookExpectations

EnforcementState = Literal["mandatory", "advisory", "unknown"]

MANAGED_SETTINGS_PATHS = {
    "Darwin": Path("/Library/Application Support/ClaudeCode/managed-settings.json"),
    "Linux": Path("/etc/claude-code/managed-settings.json"),
}
MCP_TOOL_SAMPLE = "mcp__example__tool"


def managed_settings_path() -> Optional[Path]:
    return MANAGED_SETTINGS_PATHS.get(platform.system())


@dataclass(frozen=True)
class SettingsFacts:
    path: Optional[str]
    exists: bool
    owner_uid: Optional[int] = None
    mode: Optional[int] = None
    content: Optional[dict[str, Any]] = None
    parse_error: Optional[str] = None
    sha256: Optional[str] = None
    managed_d_sha256: dict[str, str] = field(default_factory=dict)
    listener: Literal["sentinel", "foreign", "none", "unchecked"] = "unchecked"


@dataclass(frozen=True)
class EnforcementReport:
    state: EnforcementState
    failed: tuple[str, ...]
    liveness: bool

    @property
    def record_value(self) -> str:
        return self.state


def collect_facts(path: Optional[Path], *, server_url: str, probe_port: bool = True) -> SettingsFacts:
    if path is None:
        return SettingsFacts(path=None, exists=False)
    if not path.exists():
        return SettingsFacts(path=str(path), exists=False, listener=_probe_listener(server_url) if probe_port else "unchecked")
    st = path.stat()
    raw = path.read_bytes()
    content: Optional[dict[str, Any]] = None
    parse_error: Optional[str] = None
    try:
        loaded = json.loads(raw.decode("utf-8"))
        if isinstance(loaded, dict):
            content = loaded
        else:
            parse_error = "managed settings is not a JSON object"
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        parse_error = f"{type(exc).__name__}: {exc}"
    managed_d: dict[str, str] = {}
    d_dir = path.with_name("managed-settings.d")
    if d_dir.is_dir():
        for child in sorted(d_dir.iterdir()):
            if child.is_file():
                managed_d[child.name] = hashlib.sha256(child.read_bytes()).hexdigest()
    return SettingsFacts(
        path=str(path), exists=True, owner_uid=st.st_uid, mode=stat.S_IMODE(st.st_mode), content=content,
        parse_error=parse_error, sha256=hashlib.sha256(raw).hexdigest(), managed_d_sha256=managed_d,
        listener=_probe_listener(server_url) if probe_port else "unchecked",
    )


def _probe_listener(server_url: str) -> Literal["sentinel", "foreign", "none"]:
    parts = urlsplit(server_url)
    health = f"{parts.scheme}://{parts.netloc}/health"
    try:
        with urllib.request.urlopen(health, timeout=2) as response:  # noqa: S310 - loopback only
            body = response.read(65_536).decode("utf-8", "replace")
    except urllib.error.HTTPError:
        return "foreign"
    except (urllib.error.URLError, OSError, ValueError):
        return "none"
    return "sentinel" if "sentinel" in body.lower() else "foreign"


def parse_version(text: Optional[str]) -> Optional[tuple[int, int, int]]:
    if not text:
        return None
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
    return (int(match.group(1)), int(match.group(2)), int(match.group(3))) if match else None


def _url_matches(pattern: str, url: str) -> bool:
    return fnmatch.fnmatchcase(url.lower(), pattern.lower()) or url.lower().startswith(pattern.lower().rstrip("*"))


def _matcher_covers(matcher: Any, tool: str) -> bool:
    if matcher in (None, "", "*"):
        return True
    if not isinstance(matcher, str):
        return False
    probe = MCP_TOOL_SAMPLE if tool == "mcp__.*" else tool
    try:
        return re.fullmatch(matcher, probe) is not None
    except re.error:
        return False


def pre_tool_use_entry_ok(content: dict[str, Any], expectations: HookExpectations) -> list[str]:
    """Which expectations the PreToolUse hook entries fail to meet."""
    failed: list[str] = []
    groups = (content.get("hooks") or {}).get("PreToolUse") or []
    if not isinstance(groups, list):
        return ["pre_tool_use_entry_missing"]
    covering: list[dict[str, Any]] = []
    for group in groups:
        if not isinstance(group, dict):
            continue
        for handler in group.get("hooks") or []:
            if not isinstance(handler, dict) or handler.get("type") != "http":
                continue
            if handler.get("url") != expectations.server_url:
                continue
            covering.append({"matcher": group.get("matcher"), **handler})
    if not covering:
        return ["pre_tool_use_entry_missing"]
    for tool in sorted(expectations.tools):
        if not any(_matcher_covers(entry["matcher"], tool) for entry in covering):
            failed.append(f"matcher_missing:{tool}")
    for entry in covering:
        if entry.get("onFailure") != "block":
            failed.append("on_failure_not_block")
        timeout = entry.get("timeout")
        if timeout is None or not isinstance(timeout, (int, float)) or timeout > expectations.max_timeout_seconds or timeout <= 0:
            failed.append("timeout_too_long")
        if entry.get("async") or entry.get("asyncRewake"):
            failed.append("hook_is_async")
    return sorted(set(failed))


def evaluate_enforcement(
    facts: SettingsFacts,
    expectations: HookExpectations,
    *,
    claude_version: Optional[str],
    liveness: bool,
) -> EnforcementReport:
    failed: list[str] = []
    if not facts.exists or facts.content is None:
        # No file, or an unreadable one. If hooks are demonstrably firing the
        # policy may be console- or MDM-delivered, which we cannot inspect.
        if liveness and not facts.exists:
            return EnforcementReport("unknown", ("managed_settings_missing",), liveness)
        failed.append("managed_settings_missing" if not facts.exists else "managed_settings_unparseable")
        return EnforcementReport("advisory", tuple(failed), liveness)
    if facts.owner_uid != 0:
        failed.append("managed_settings_not_root_owned")
    if facts.mode is not None and facts.mode & (stat.S_IWGRP | stat.S_IWOTH):
        failed.append("managed_settings_group_or_world_writable")
    content = facts.content
    if content.get("allowManagedHooksOnly") is not True:
        failed.append("allow_managed_hooks_only_not_set")
    allowlist = content.get("allowedHttpHookUrls")
    if not isinstance(allowlist, list) or not any(isinstance(p, str) and _url_matches(p, expectations.server_url) for p in allowlist):
        failed.append("allowed_http_hook_urls_not_pinned")
    failed.extend(pre_tool_use_entry_ok(content, expectations))
    version = parse_version(claude_version)
    if version is None:
        failed.append("claude_version_unknown")
    elif version < expectations.min_claude_version:
        failed.append("claude_version_too_old")
    if not liveness:
        failed.append("no_hook_call_observed")
    if facts.listener == "foreign":
        failed.append("foreign_listener_on_sentinel_port")
    if facts.listener == "none":
        failed.append("sentinel_not_listening")
    state: EnforcementState = "mandatory" if not failed else "advisory"
    if failed and set(failed) <= {"claude_version_unknown", "no_hook_call_observed"}:
        # The file is right; only the session-level facts are missing. Not
        # mandatory yet, but nothing is known to be wrong either.
        state = "unknown"
    return EnforcementReport(state, tuple(failed), liveness)


def snapshot_relevant_keys(path: Path) -> Optional[dict[str, Any]]:
    """The hook-adjacent keys of a settings file, for ConfigChange comparison."""
    try:
        loaded = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(loaded, dict):
        return None
    return {key: loaded.get(key) for key in CONFIG_CHANGE_KEYS if key in loaded}


CONFIG_CHANGE_KEYS = (
    "hooks", "permissions", "allowedHttpHookUrls", "httpHookAllowedEnvVars", "disableAllHooks",
    "enabledPlugins", "mcpServers", "allowManagedHooksOnly",
)


def settings_files_for(launch_cwd: str, home: str) -> dict[str, Path]:
    return {
        "user_settings": Path(home) / ".claude" / "settings.json",
        "project_settings": Path(launch_cwd) / ".claude" / "settings.json",
        "local_settings": Path(launch_cwd) / ".claude" / "settings.local.json",
    }

