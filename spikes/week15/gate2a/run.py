"""Run the Gate 2a extractor over the Cursor shell corpus and tally results."""

from __future__ import annotations

import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from extract import Target, analyze  # noqa: E402

CORPUS = sys.argv[1] if len(sys.argv) > 1 else "/tmp/cursor_shell_corpus.json"
HOME = os.path.expanduser("~")
CD_PREFIX = re.compile(r"^\s*cd\s+(\"[^\"]+\"|'[^']+'|\S+)\s*(&&|;)")


def _inflate(rest: str) -> str | None:
    """Cursor flattens `/`, ` `, and `.` prefixes to `-` in project folder
    names. Try every split of the hyphenated tail into real directories."""
    parts = rest.split("-")

    def walk(base: str, i: int) -> str | None:
        if i == len(parts):
            return base
        for j in range(len(parts), i, -1):
            seg = "-".join(parts[i:j])
            for cand in (seg, seg.replace("-", " "), "." + seg):
                p = os.path.join(base, cand)
                if os.path.isdir(p):
                    r = walk(p, j)
                    if r:
                        return r
        return None

    return walk(HOME, 0)


def launch_cwd(entry: dict) -> str:
    if entry.get("cwd"):
        return entry["cwd"]
    proj = entry["project"]
    # Cursor names project dirs by flattening the path: /Users/me/x -> Users-me-x
    home_prefix = HOME.strip("/").replace("/", "-") + "-"
    if proj.startswith(home_prefix):
        rest = proj[len(home_prefix):]
        return _inflate(rest) or os.path.join(HOME, rest)
    m = CD_PREFIX.match(entry["command"])
    if m:
        return os.path.expanduser(m.group(1).strip("\"'"))
    return HOME  # unknown: worst case, everything is "inside home"


def repo_family(cwd: str, cache: dict[str, list[str]] = {}) -> list[str]:
    """cwd plus every git worktree of the same repository. Read from git at
    launch; this is a fact about the repo, not an inference from the prompt."""
    if cwd in cache:
        return cache[cwd]
    import subprocess
    roots = [cwd]
    try:
        out = subprocess.run(["git", "-C", cwd, "worktree", "list", "--porcelain"], capture_output=True, text=True, timeout=5).stdout
        roots += [ln.split(" ", 1)[1] for ln in out.splitlines() if ln.startswith("worktree ")]
    except Exception:
        pass
    cache[cwd] = roots
    return roots


def inside_family(resolved: str, cwd: str) -> bool:
    return any(resolved == r or resolved.startswith(r + "/") for r in repo_family(cwd))


def main() -> None:
    corpus = json.load(open(CORPUS))
    status = collections.Counter()
    zones = collections.Counter()
    verbs = collections.Counter()
    opaque_kinds = collections.Counter()
    parse_errors = collections.Counter()
    would_block = []
    would_confirm = []
    dynamic_destructive = []
    unparseable = []
    opaque_samples = collections.defaultdict(list)
    # Second tally: what the person would actually see once the boundary
    # includes git worktrees and a confirm is remembered per (cwd, target).
    confirm_v2_keys: set[tuple[str, str]] = set()
    confirm_v2_worktree_absorbed = 0

    for e in corpus:
        cwd = launch_cwd(e)
        rep = analyze(e["command"], cwd)
        status[rep.status] += 1
        if rep.status == "unparseable":
            parse_errors[rep.parse_error.split(":")[0]] += 1
            unparseable.append((rep.parse_error, e["command"]))
        for k in rep.opaque:
            opaque_kinds[k] += 1
            if len(opaque_samples[k]) < 3:
                opaque_samples[k].append(e["command"][:160].replace("\n", "⏎"))
        for t in rep.targets:
            verbs[t.verb] += 1
            zones[f"{t.kind}:{t.zone}"] += 1
            if t.zone in {"home", "root", "system", "protected_config", "credential"}:
                would_block.append((t, cwd, e["command"]))
            elif t.zone == "outside" and t.kind == "delete":
                would_confirm.append((t, cwd, e["command"]))
                if inside_family(t.resolved, cwd):
                    confirm_v2_worktree_absorbed += 1
                else:
                    confirm_v2_keys.add((cwd, t.resolved))
            elif t.zone == "dynamic" and t.kind == "delete":
                dynamic_destructive.append((t, cwd, e["command"]))
        for c in rep.credential_reads:
            would_block.append((("credential read", c), cwd, e["command"]))
        for c in rep.egress:
            would_confirm.append((Target("egress", c, c, "remote", "", "egress"), cwd, e["command"]))

    n = len(corpus)
    print(f"corpus: {n} unique agent shell commands")
    print("\n== status ==")
    for k, v in status.most_common():
        print(f"  {k:12s} {v:6d}  {v/n:6.1%}")
    print("\n== unparseable by error ==")
    for k, v in parse_errors.most_common():
        print(f"  {v:5d} {k}")
    print("\n== destructive verbs seen ==")
    for k, v in verbs.most_common():
        print(f"  {v:5d} {k}")
    print("\n== target zones (destructive targets only) ==")
    for k, v in zones.most_common():
        print(f"  {v:5d} {k}")
    print("\n== opaque kinds ==")
    for k, v in opaque_kinds.most_common():
        print(f"  {v:5d} {k}")
        for s in opaque_samples[k]:
            print(f"          {s}")
    print(f"\n== floor would BLOCK: {len(would_block)} ==")
    for t, cwd, c in would_block[:40]:
        zone, verb, resolved = (t.zone, t.verb, t.resolved) if hasattr(t, "zone") else (t[0], t[0], t[1])
        print(f"  [{zone}] {verb} -> {resolved}\n      cwd={cwd}\n      {c[:200].replace(chr(10),'⏎')}")
    print(f"\n== floor would CONFIRM (delete outside cwd, or remote egress): {len(would_confirm)} ==")
    egress_n = sum(1 for t, _, _ in would_confirm if t.kind == "egress")
    print(f"   of which remote egress: {egress_n}")
    print(f"   v2: {confirm_v2_worktree_absorbed} absorbed by worktree-aware boundary; "
          f"{len(confirm_v2_keys)} distinct (cwd, target) pairs remain -> {len(confirm_v2_keys)} questions to the person")
    for k in sorted(confirm_v2_keys):
        print(f"      {k[0].replace(HOME, '~')}  ->  {k[1].replace(HOME, '~')}")
    for t, cwd, c in would_confirm[:40]:
        print(f"  {t.verb} -> {t.resolved}\n      cwd={cwd}\n      {c[:200].replace(chr(10),'⏎')}")
    print(f"\n== destructive with DYNAMIC target (floor cannot resolve): {len(dynamic_destructive)} ==")
    for t, cwd, c in dynamic_destructive[:25]:
        print(f"  {t.verb} {t.raw}\n      {c[:200].replace(chr(10),'⏎')}")
    print("\n== unparseable samples ==")
    for err, c in unparseable[:15]:
        print(f"  {err}\n      {c[:200].replace(chr(10),'⏎')}")

    json.dump(
        {"n": n, "status": status, "zones": zones, "verbs": verbs, "opaque": opaque_kinds, "parse_errors": parse_errors,
         "would_block": len(would_block), "would_confirm": len(would_confirm), "dynamic_destructive": len(dynamic_destructive)},
        open(os.path.join(os.path.dirname(__file__), "summary.json"), "w"), indent=2,
    )


if __name__ == "__main__":
    main()
