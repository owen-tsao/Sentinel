"""The floor for Cursor's `ApplyPatch` tool: judge every file the patch names.

`ApplyPatch` takes one raw string in the `*** Begin Patch` format. Each file
it touches is announced by a header line at the start of a line:

    *** Update File: /abs/path     (edit an existing file)
    *** Add File: /abs/path        (create a file)
    *** Delete File: /abs/path     (remove a file)
    *** Move to: /abs/path         (rename the preceding Update File here)

Body lines carry a `+`, `-`, or space prefix, so a header never appears
inside a body. Each path is judged exactly as `Write` (update, add, move)
or `Delete` (delete) would be through `decide_path`, and the most severe
verdict wins; among blocks the most severe zone wins, as in `decide_shell`.

A patch with no readable header stays `confirm_required F5.opaque_write`
(Direction §3.1, October 14 amendment): a write tool whose targets cannot
be seen is otherwise a way around every path rule.

Verified against this person's corpus (2,639 patches, October 15): every
input is a string, every path absolute, headers are `Update File` (2,378)
and `Add File` (261); none use `Delete File` or `Move to`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sentinel.floor.extract import Report, Target, guess_home, zone_of
from sentinel.floor.paths import decide_path, resolve_tool_path
from sentinel.floor.rules import ZONE_SEVERITY, Finding

HEADER = re.compile(r"^\*\*\* (Update File|Add File|Delete File|Move to): ?(.*?)\s*$", re.M)
OPS = {"Update File": "update", "Add File": "add", "Delete File": "delete", "Move to": "move"}
OPERATION = {"update": "write", "add": "write", "move": "write", "delete": "delete"}
VERDICT_RANK = {"block": 3, "confirm_required": 2, "warn": 1, "allow": 0}
PATCH_TEXT_KEYS = ("patch", "input", "_raw")
PATCH_TOOL = "ApplyPatch"


@dataclass(frozen=True)
class PatchFile:
    """One file a patch names: `op` is the header (`update|add|delete|move`), `path` as written."""

    op: str
    path: str

    @property
    def operation(self) -> str:
        """The file-tool operation `decide_path` judges this header as."""
        return OPERATION.get(self.op, "write")


def parse_patch(text: Any) -> list[PatchFile]:
    """Every file header in the patch text, in patch order; `[]` when there is none.

    Paths are returned as written (the adapter resolves relative ones against
    the launch directory before the floor judges them). An empty path after
    the colon is kept as `""` so `decide_path` denies it as unresolved rather
    than the header being silently skipped.
    """
    if not isinstance(text, str):
        return []
    return [PatchFile(OPS[m.group(1)], m.group(2)) for m in HEADER.finditer(text)]


def files_from_tool_input(tool_input: Any) -> list[PatchFile]:
    """The files to judge from an envelope's `tool_input`.

    The Cursor adapter sends `files: [{op, path}]` already parsed; an
    envelope built elsewhere may carry the patch text under `patch`,
    `input`, or `_raw`, or be the bare string. Malformed `files` entries are
    kept as unresolved writes so they are denied, never dropped.
    """
    if isinstance(tool_input, str):
        return parse_patch(tool_input)
    if not isinstance(tool_input, dict):
        return []
    files = tool_input.get("files")
    if isinstance(files, list):
        out: list[PatchFile] = []
        for entry in files:
            if not isinstance(entry, dict):
                out.append(PatchFile("update", ""))
                continue
            op, path = entry.get("op"), entry.get("path")
            out.append(PatchFile(op if op in OPERATION else "update", path if isinstance(path, str) else ""))
        return out
    for key in PATCH_TEXT_KEYS:
        if isinstance(tool_input.get(key), str):
            return parse_patch(tool_input[key])
    return []


def opaque_finding(tool: str = PATCH_TOOL) -> Finding:
    """The verdict for a patch whose targets cannot be read (review S15b)."""
    return Finding(
        "confirm_required", "F5.opaque_write",
        f"{tool} carried no `*** Update File:` / `*** Add File:` / `*** Delete File:` header Sentinel can read, "
        "so the files it writes cannot be checked. Ask the user, or use Write/StrReplace with full paths so each file can be checked.",
    )


def _severity(item: tuple[int, Finding]) -> tuple[int, int, int]:
    """Sort key: most severe verdict first, then most severe zone, then patch order."""
    index, finding = item
    zone = finding.rule.split("_", 1)[1] if "_" in finding.rule else ""
    zone_rank = ZONE_SEVERITY.index(zone) if zone in ZONE_SEVERITY else len(ZONE_SEVERITY)
    return (-VERDICT_RANK.get(finding.verdict, 0), zone_rank, index)


def decide_patch(
    files: list[PatchFile],
    *,
    launch_cwd: str,
    home: str | None = None,
    tool: str = PATCH_TOOL,
) -> Finding:
    """Judge one patch: each file through `decide_path`, the most severe verdict wins.

    The returned finding carries the winning file's rule, reason, and target,
    plus a `Report` listing every file with its zone so the audit record
    shows the whole patch, not only the file that decided it.
    """
    home = home or guess_home(launch_cwd)
    if not files:
        return opaque_finding(tool)
    report = Report(status="destructive")
    findings: list[Finding] = []
    previous: PatchFile | None = None
    for f in files:
        findings.append(decide_path(f.path, f.operation, launch_cwd=launch_cwd, home=home, tool=tool))
        resolved = resolve_tool_path(f.path, home)
        zone = zone_of(resolved, launch_cwd, home) if resolved is not None else "dynamic"
        report.targets.append(Target(f"{tool} {f.op}", f.path, resolved, zone, kind=f.operation))
        if f.op == "move" and previous is not None and previous.op == "update":
            # A move removes its source, so the source is also judged as a
            # delete: for zones where delete is stricter than write
            # (`host_artifact`, `home`, `system`) a rename must not be the
            # lenient way to remove a file (review finding, October 15).
            findings.append(decide_path(previous.path, "delete", launch_cwd=launch_cwd, home=home, tool=tool))
            src = resolve_tool_path(previous.path, home)
            src_zone = zone_of(src, launch_cwd, home) if src is not None else "dynamic"
            report.targets.append(Target(f"{tool} move-source", previous.path, src, src_zone, kind="delete"))
        previous = f
    _, winner = min(enumerate(findings), key=_severity)
    reason = winner.reason
    if len(files) > 1 and winner.interrupts:
        reason = f"{reason} The patch names {len(files)} files; this one decides the verdict."
    return Finding(winner.verdict, winner.rule, reason, list(winner.targets), report)


__all__ = ["PatchFile", "decide_patch", "files_from_tool_input", "opaque_finding", "parse_patch"]
