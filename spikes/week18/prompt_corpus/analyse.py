#!/usr/bin/env python3
"""How the person actually prompts, and where the agent actually works.

Reads the local Cursor transcripts (read-only), answers the questions that
bear on the boundary model, writes one aggregate JSON (counts only; no prompt
text, no paths) and prints the summary. Run from the repo root:

    uv run python spikes/week18/prompt_corpus/analyse.py

Subagent transcripts are skipped: their "user" is the parent agent.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import statistics
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
from sentinel.boundary.infer import candidates, is_command_prompt, negated, strip_untrusted  # noqa: E402

PROJECTS = Path.home() / ".cursor" / "projects"
OUT = Path(__file__).with_name("summary.json")
HOME = str(Path.home())
WIDEN_PATTERNS = re.compile(
    r"\b(whole|entire|all of (the|it)|across the|every ?(where|thing)|repo-?wide|project-?wide|codebase-?wide|"
    r"the rest of|everything else|full (repo|codebase|project)|deep review|review (all|everything))\b", re.I)
TS = re.compile(r"<timestamp>(.*?)</timestamp>")
UQ = re.compile(r"<user_query>\n?(.*?)\n?</user_query>", re.S)
PATH_TOOLS = {"Read", "Write", "StrReplace", "Delete", "Glob", "Grep", "ApplyPatch", "EditNotebook"}
WRITE_TOOLS = {"Write", "StrReplace", "Delete", "ApplyPatch", "EditNotebook"}


def workspace_of(project_dir: str, root: Path) -> str | None:
    """The workspace root, derived from where the agent's file tools actually
    pointed: the most common two-level prefix under home across the project's
    transcripts. Directory names are ambiguous (`Learning-Misc` is
    `Learning/Misc`), so they are only used to reject non-home projects."""
    if not project_dir.startswith("Users-owentsao"):
        return None
    prefixes: Counter = Counter()
    for path in root.rglob("*.jsonl"):
        for line in path.open(errors="replace"):
            if '"tool_use"' not in line:
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            for b in ((o.get("message") or {}).get("content") or []):
                if not isinstance(b, dict) or b.get("type") != "tool_use" or not isinstance(b.get("input"), dict):
                    continue
                p = b["input"].get("path") or b["input"].get("file_path")
                if isinstance(p, str) and p.startswith(HOME + "/"):
                    parts = p[len(HOME) + 1:].split("/")
                    if len(parts) >= 2 and not parts[0].startswith("."):
                        prefixes[posixpath.join(HOME, parts[0])] += 1
                        if len(parts) >= 3:
                            prefixes[posixpath.join(HOME, parts[0], parts[1])] += 1
    if not prefixes:
        return None
    # Prefer the deepest prefix that still holds at least 80% of the calls of its parent.
    top, top_n = prefixes.most_common(1)[0]
    for candidate, n in prefixes.most_common():
        if candidate.startswith(top + "/") and n >= 0.8 * top_n and os.path.isdir(candidate):
            return candidate
    return top if os.path.isdir(top) else None


def parse_time(text: str) -> datetime | None:
    m = TS.search(text)
    if not m:
        return None
    raw = re.sub(r"\s*\(UTC[^)]*\)", "", m.group(1))
    for fmt in ("%A, %b %d, %Y, %I:%M %p",):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            pass
    return None


def prompt_paths(text: str, workspace: str) -> list[str]:
    """Inside-the-workspace folders a prompt names, by the real inferrer's token rules."""
    clean, _ = strip_untrusted(text)
    tokens = clean.replace("`", " ").split()
    out = []
    for index, token in candidates(clean):
        if negated(tokens, index):
            continue
        p = token
        if p.startswith("~"):
            p = HOME + p[1:]
        if not p.startswith("/"):
            p = posixpath.join(workspace, p)
        p = posixpath.normpath(p)
        if p == workspace or p.startswith(workspace + "/"):
            out.append(p)
    return out


def folder_of(path: str) -> str:
    # a path with an extension is a file; take its folder
    return posixpath.dirname(path) if "." in posixpath.basename(path) else path


def common(paths: list[str]) -> str:
    parts = [p.rstrip("/").split("/") for p in paths]
    prefix = parts[0]
    for other in parts[1:]:
        n = 0
        while n < len(prefix) and n < len(other) and prefix[n] == other[n]:
            n += 1
        prefix = prefix[:n]
    return "/".join(prefix) or "/"


def inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def analyse_chat(path: Path, workspace: str, agg: dict, phrases: Counter) -> None:
    prompts: list[tuple[datetime | None, str]] = []
    tool_uses: list[tuple[int, str, dict]] = []   # (prompt index at the time, tool, input)
    for line in path.open(errors="replace"):
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        content = (o.get("message") or {}).get("content")
        if o.get("role") == "user" and isinstance(content, list):
            for b in content:
                if b.get("type") == "text":
                    m = UQ.search(b.get("text", ""))
                    if m:
                        prompts.append((parse_time(b["text"]), m.group(1)))
        elif o.get("role") == "assistant" and isinstance(content, list):
            for b in content:
                if b.get("type") == "tool_use":
                    tool_uses.append((len(prompts), b.get("name") or "", b.get("input") or {}))
    if not prompts:
        return
    agg["chats"] += 1
    agg["prompts"] += len(prompts)
    agg["prompts_per_chat"].append(len(prompts))
    times = [t for t, _ in prompts if t]
    if len(times) >= 2:
        agg["chat_minutes"].append((max(times) - min(times)).total_seconds() / 60)

    boundary: str | None = None          # what narrow-only inference would hold
    first_named: str | None = None
    wider_seen = False
    for i, (_, text) in enumerate(prompts):
        words = len(text.split())
        agg["prompt_words"].append(words)
        if is_command_prompt(text):
            agg["command_prompts"] += 1
        paths = prompt_paths(text, workspace)
        if WIDEN_PATTERNS.search(text):
            agg["widen_phrase_prompts"] += 1
            for m in WIDEN_PATTERNS.finditer(text):
                phrases[m.group(0).lower()] += 1
            if not paths:
                agg["widen_phrase_without_path"] += 1
        if not paths:
            agg["prompts_without_path"] += 1
            continue
        agg["prompts_with_path"] += 1
        folder = common([folder_of(p) for p in paths])
        if boundary is None:
            if folder != workspace:
                boundary = folder
                first_named = folder
                agg["chats_that_narrow"] += 1
                agg["narrow_depth"].append(len(folder[len(workspace):].strip("/").split("/")))
            continue
        # A later prompt with paths: deeper, same, or elsewhere relative to the held boundary?
        if inside(folder, boundary) and folder != boundary:
            agg["later_prompt_deeper"] += 1
        elif folder == boundary:
            agg["later_prompt_same"] += 1
        else:
            agg["later_prompt_elsewhere"] += 1
            wider_seen = True
            agg["later_prompt_elsewhere_union_is_root"] += int(common([folder, boundary]) == workspace)
    if first_named and wider_seen:
        agg["chats_narrowed_then_wider_prompt"] += 1

    # Where the agent worked, relative to the first-named folder.
    for _, tool, inp in tool_uses:
        agg["tool_calls"] += 1
        agg["tools"][tool] += 1
        if not isinstance(inp, dict):
            continue
        p = inp.get("path") or inp.get("file_path") or inp.get("target_file")
        if tool in PATH_TOOLS and isinstance(p, str) and p.startswith("/"):
            p = posixpath.normpath(p)
            zone = ("workspace" if inside(p, workspace) else "home" if inside(p, HOME) else "other")
            kind = "write" if tool in WRITE_TOOLS else "read"
            agg["path_calls"][f"{kind}:{zone}"] += 1
            if first_named and zone == "workspace":
                agg["vs_first_named"][f"{kind}:{'inside' if inside(p, first_named) else 'outside'}"] += 1
        if tool == "Shell":
            cmd = str(inp.get("command", ""))
            if re.search(r"\b(pytest|npm test|npm run|uv run|cargo test|go test|make|ruff|eslint|tsc|vitest|jest)\b", cmd):
                agg["shell_test_or_build"] += 1
            if re.search(r"\bgit\b", cmd):
                agg["shell_git"] += 1


def main() -> int:
    agg: dict = {"chats": 0, "prompts": 0, "prompts_per_chat": [], "chat_minutes": [], "prompt_words": [],
                 "command_prompts": 0, "prompts_with_path": 0, "prompts_without_path": 0, "chats_that_narrow": 0,
                 "narrow_depth": [], "later_prompt_deeper": 0, "later_prompt_same": 0, "later_prompt_elsewhere": 0,
                 "later_prompt_elsewhere_union_is_root": 0, "chats_narrowed_then_wider_prompt": 0,
                 "widen_phrase_prompts": 0, "widen_phrase_without_path": 0, "tool_calls": 0, "tools": Counter(),
                 "path_calls": Counter(), "vs_first_named": Counter(), "shell_test_or_build": 0, "shell_git": 0}
    phrases: Counter = Counter()
    skipped = 0
    workspaces: dict[str, str] = {}
    for project in sorted(os.listdir(PROJECTS)):
        root = PROJECTS / project / "agent-transcripts"
        if not root.is_dir():
            skipped += 1
            continue
        workspace = workspace_of(project, root)
        if workspace is None:
            skipped += 1
            continue
        workspaces[project] = workspace
        for path in root.rglob("*.jsonl"):
            if "subagents" in path.parts:
                continue
            analyse_chat(path, workspace, agg, phrases)

    def q(xs: list[float]) -> dict:
        if not xs:
            return {}
        xs = sorted(xs)
        return {"n": len(xs), "p50": round(statistics.median(xs), 1), "p90": round(xs[int(0.9 * (len(xs) - 1))], 1),
                "max": round(xs[-1], 1)}

    summary = {
        "chats": agg["chats"], "prompts": agg["prompts"], "projects_skipped": skipped,
        "workspaces": {k: v.replace(HOME, "~") for k, v in workspaces.items()},
        "prompts_per_chat": q(agg["prompts_per_chat"]), "chat_minutes": q(agg["chat_minutes"]),
        "prompt_words": q(agg["prompt_words"]),
        "command_prompts": agg["command_prompts"],
        "prompts_with_path": agg["prompts_with_path"], "prompts_without_path": agg["prompts_without_path"],
        "chats_that_narrow": agg["chats_that_narrow"], "narrow_depth": q(agg["narrow_depth"]),
        "chats_narrowed_then_wider_prompt": agg["chats_narrowed_then_wider_prompt"],
        "later_prompts_after_narrowing": {"deeper": agg["later_prompt_deeper"], "same": agg["later_prompt_same"],
                                          "elsewhere": agg["later_prompt_elsewhere"],
                                          "elsewhere_union_is_workspace_root": agg["later_prompt_elsewhere_union_is_root"]},
        "widen_phrase_prompts": agg["widen_phrase_prompts"], "widen_phrase_without_path": agg["widen_phrase_without_path"],
        "widen_phrases_top": phrases.most_common(12),
        "tool_calls": agg["tool_calls"], "tools_top": agg["tools"].most_common(14),
        "path_calls_by_zone": dict(agg["path_calls"]), "path_calls_vs_first_named_folder": dict(agg["vs_first_named"]),
        "shell_test_or_build": agg["shell_test_or_build"], "shell_git": agg["shell_git"],
    }
    OUT.write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
