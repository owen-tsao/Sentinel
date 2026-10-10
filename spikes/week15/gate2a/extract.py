"""Gate 2a: floor-oriented target extraction over real agent shell commands.

This is a spike, not product code. The question it answers: given the raw
`command` string a Bash hook delivers, how often can a deterministic pass
find (a) whether anything destructive is happening, (b) which paths it hits,
and (c) whether those paths escape the working directory, without failing
closed on ordinary work.

Design choice, inverted from the shipped canonicalizer: the floor is
allow-by-default. A command with no visible destructive verb is "benign" and
passes. Only "unparseable" counts against the kill condition; "opaque"
(interpreter, eval, xargs, variables in a destructive target) is a policy
decision the gate measures rather than a parser failure.
"""

from __future__ import annotations

import os
import posixpath
import re
from dataclasses import dataclass, field

import bashlex
import bashlex.ast

HOME = os.path.expanduser("~")
TEMP_PREFIXES = ("/tmp/", "/private/tmp/", "/var/folders/", "/private/var/folders/")
SYSTEM_PREFIXES = ("/bin/", "/sbin/", "/usr/", "/etc/", "/System/", "/Library/", "/var/", "/private/etc/", "/opt/")
PROTECTED_CONFIG = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    "managed-settings.json",
    ".cursor/hooks.json",
    ".cursor/hooks/",
    ".sentinel/",
    "sentinel.toml",
)
CREDENTIAL_PATHS = (".ssh/", ".aws/", ".gnupg/", ".netrc", ".npmrc", ".pypirc", ".docker/config.json", ".kube/config", ".config/gh/hosts.yml")
# Key material by filename. Project `.env` files are deliberately excluded:
# agents read and recreate them constantly and the floor is about key stores
# and exfiltration, not everyday config. `.example`/`.sample` are never secrets.
CREDENTIAL_NAMES = re.compile(r"id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$|\.pem$|\.p12$|\.pfx$|credentials(\.json)?$")

# Simple-command names whose *purpose* is to destroy.
DELETE_VERBS = {"rm", "rmdir", "unlink", "shred"}
# Writes: overwriting or relocating. Lower weight than deletion.
MOVE_VERBS = {"mv"}
# Interpreters / indirection: the real action is in a string or stdin, not argv.
OPAQUE_VERBS = {
    "bash", "sh", "zsh", "dash", "eval", "exec", "source", ".",
    "python", "python3", "node", "ruby", "perl", "php", "osascript",
    "xargs", "parallel", "sudo", "env", "nohup", "time", "timeout", "nice", "watch",
    "make", "npm", "pnpm", "yarn", "npx", "bun", "uv", "uvx", "pip", "pip3", "poetry", "cargo", "go", "docker", "docker-compose",
}
# Commands whose destructive power comes from a sub-verb or flag.
GIT_DESTRUCTIVE = {
    ("clean",): "git clean",
    ("reset", "--hard"): "git reset --hard",
    ("checkout", "--"): "git checkout -- (discard)",
    ("restore",): "git restore (discard)",
    ("push", "--force"): "git push --force",
    ("push", "-f"): "git push --force",
    ("branch", "-D"): "git branch -D",
    ("stash", "drop"): "git stash drop",
    ("stash", "clear"): "git stash clear",
}
DYNAMIC = re.compile(r"[$`*?\[\]{}]")


@dataclass
class Target:
    verb: str
    raw: str
    resolved: str | None
    zone: str  # inside | temp | home | root | system | protected_config | credential | outside | dynamic
    note: str = ""
    kind: str = "delete"  # delete | write


@dataclass
class Report:
    status: str = "benign"  # benign | destructive | opaque | unparseable
    targets: list[Target] = field(default_factory=list)
    opaque: list[str] = field(default_factory=list)
    egress: list[str] = field(default_factory=list)
    credential_reads: list[str] = field(default_factory=list)
    config_writes: list[str] = field(default_factory=list)
    parse_error: str = ""
    heredocs: int = 0
    simple_commands: int = 0


HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)(\w+)\1[^\n]*\n(.*?)\n\2\s*$", re.S | re.M)
VAR_REF = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
GLOB_CHARS = re.compile(r"[*?\[\]{}]")


def substitute_vars(raw: str, env: dict[str, str]) -> tuple[str, bool]:
    """Replace `$VAR`/`${VAR}` with known literal assignments. Returns
    (text, still_dynamic)."""
    def repl(m: re.Match[str]) -> str:
        return env.get(m.group(1), m.group(0))
    out = VAR_REF.sub(repl, raw)
    return out, bool(VAR_REF.search(out)) or "`" in out or "$(" in out


def glob_parent(raw: str) -> str | None:
    """`out/review/st-*.png` -> `out/review`; `*.png` -> `.`; `**/x` -> None.
    A glob only in the last path segment leaves the directory knowable."""
    parts = raw.split("/")
    if any(GLOB_CHARS.search(p) for p in parts[:-1]):
        return None
    if not GLOB_CHARS.search(parts[-1]):
        return raw
    return "/".join(parts[:-1]) or "."


def strip_heredocs(command: str) -> tuple[str, int]:
    """Replace heredoc bodies with an empty stdin redirect; count them."""
    count = 0

    def repl(m: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return "</dev/null"

    return HEREDOC_RE.sub(repl, command), count


def _words(node: bashlex.ast.node) -> list[tuple[str, bool]]:
    """Argv words of a command node with a flag for 'contains expansion'."""
    out: list[tuple[str, bool]] = []
    for part in node.parts:
        if part.kind == "word":
            dynamic = bool(getattr(part, "parts", None)) or bool(DYNAMIC.search(part.word))
            out.append((part.word, dynamic))
    return out


def _redirect_targets(node: bashlex.ast.node) -> list[tuple[str, bool]]:
    out = []
    for part in node.parts:
        if part.kind == "redirect" and part.type in {">", ">>", ">|", "&>"} and hasattr(part.output, "word"):
            w = part.output.word
            out.append((w, bool(DYNAMIC.search(w))))
    return out


def _resolve(raw: str, vcwd: str) -> str:
    expanded = os.path.expanduser(raw)
    candidate = expanded if expanded.startswith("/") else posixpath.join(vcwd, expanded)
    return posixpath.normpath(candidate)


def _zone(resolved: str, launch_cwd: str) -> str:
    lc = posixpath.normpath(launch_cwd)
    if any(p in resolved for p in PROTECTED_CONFIG):
        return "protected_config"
    if resolved == "/":
        return "root"
    if resolved == HOME:
        return "home"
    if resolved == lc or resolved.startswith(lc + "/"):
        return "inside"
    if resolved.startswith(TEMP_PREFIXES):
        return "temp"
    if resolved.startswith(SYSTEM_PREFIXES):
        return "system"
    if any(c in resolved for c in CREDENTIAL_PATHS) or CREDENTIAL_NAMES.search(resolved):
        return "credential"
    return "outside"


def _flag_args(words: list[tuple[str, bool]]) -> tuple[list[str], list[tuple[str, bool]]]:
    flags, args = [], []
    end = False
    for w, dyn in words[1:]:
        if not end and w == "--":
            end = True
            continue
        if not end and w.startswith("-") and len(w) > 1:
            flags.append(w)
        else:
            args.append((w, dyn))
    return flags, args


def analyze(command: str, launch_cwd: str) -> Report:
    rep = Report()
    text, rep.heredocs = strip_heredocs(command)
    try:
        trees = bashlex.parse(text)
    except Exception as e:  # bashlex raises several types
        rep.status = "unparseable"
        rep.parse_error = f"{type(e).__name__}: {str(e)[:80]}"
        return rep

    vcwd = launch_cwd
    env: dict[str, str] = {"HOME": HOME, "TMPDIR": "/tmp", "PWD": launch_cwd}

    def place(verb: str, raw: str, kind: str = "delete", note: str = "") -> Target:
        """Resolve one argv word to a Target, salvaging what can be known.
        Order matters: substitute variables first, then treat a trailing glob
        as 'the directory it lives in', then give up only if something
        dynamic is still left."""
        text, dyn = substitute_vars(raw, env)
        if dyn:
            return Target(verb, raw, None, "dynamic", note, kind)
        knowable = glob_parent(text)
        if knowable is None:
            return Target(verb, raw, None, "dynamic", "glob in directory segment", kind)
        r = _resolve(knowable, vcwd)
        n = note if knowable == text else (note + " (glob: judged by directory)").strip()
        return Target(verb, raw, r, _zone(r, launch_cwd), n, kind)

    def add(t: Target) -> None:
        rep.targets.append(t)
        if t.zone == "protected_config":
            rep.config_writes.append(t.resolved or t.raw)

    def visit(node: bashlex.ast.node) -> None:
        if node.kind == "command":
            rep.simple_commands += 1
            handle_command(node)
            return
        if node.kind == "pipeline":
            handle_pipeline(node)
            return
        for child in getattr(node, "parts", []) or []:
            visit(child)
        for attr in ("list", "command", "body"):
            child = getattr(node, attr, None)
            if child is not None and hasattr(child, "kind"):
                visit(child)

    def handle_pipeline(node: bashlex.ast.node) -> None:
        # `cat x | xargs rm`, `curl ... | bash`: the consumer is the risk.
        cmds = [p for p in node.parts if p.kind != "pipe"]
        for i, c in enumerate(cmds):
            if c.kind == "command":
                words = _words(c)
                if words and i > 0 and posixpath.basename(words[0][0]) in {"bash", "sh", "zsh", "xargs", "parallel", "python", "python3", "node", "psql", "sqlite3", "mysql"}:
                    rep.opaque.append(f"pipe into {posixpath.basename(words[0][0])}")
            visit(c)

    def handle_command(node: bashlex.ast.node) -> None:
        nonlocal vcwd
        # Record `VAR=value` assignments so later `$VAR` targets resolve.
        for part in node.parts:
            if part.kind == "assignment":
                name, _, value = part.word.partition("=")
                value = value.strip("\"'")
                sub, dyn = substitute_vars(value, env)
                if not dyn:
                    env[name] = os.path.expanduser(sub)
        words = _words(node)
        for raw, _ in _redirect_targets(node):
            t = place("redirect >", raw, kind="write")
            if t.resolved != "/dev/null":
                add(t)
        if not words:
            return
        verb, verb_dyn = words[0]
        verb = posixpath.basename(verb)
        if verb_dyn:
            rep.opaque.append("dynamic executable")
            return
        flags, args = _flag_args(words)

        if verb == "cd":
            if not args:
                vcwd = HOME
            else:
                sub, dyn = substitute_vars(args[0][0], env)
                if dyn:
                    rep.opaque.append("cd to dynamic path")
                else:
                    vcwd = _resolve(sub, vcwd)
            return

        if verb in DELETE_VERBS:
            if not args:
                rep.opaque.append(f"{verb} with no visible target")
            for raw, _ in args:
                add(place(verb, raw))
            return

        if verb in MOVE_VERBS:
            if len(args) >= 2:
                for raw, _ in args[:-1]:
                    add(place("mv src", raw, kind="write"))
                add(place("mv dest", args[-1][0], kind="write"))
            return

        if verb == "git":
            sub = [w for w, _ in words[1:]]
            for key, label in GIT_DESTRUCTIVE.items():
                if all(k in sub for k in key):
                    # git acts on the repo containing vcwd (or -C <dir>).
                    repo = vcwd
                    if "-C" in sub and sub.index("-C") + 1 < len(sub):
                        repo = _resolve(sub[sub.index("-C") + 1], vcwd)
                    add(Target(label, ".", repo, _zone(repo, launch_cwd), " ".join(sub[:4])))
                    break
            return

        if verb == "find":
            argv = [w for w, _ in words]
            label = None
            if "-delete" in argv:
                label = "find -delete"
            for ex in ("-exec", "-execdir"):
                if ex in argv:
                    i = argv.index(ex)
                    inner = posixpath.basename(argv[i + 1]) if i + 1 < len(argv) else "?"
                    if inner in DELETE_VERBS | MOVE_VERBS | {"chmod", "chown", "sed", "truncate", "shred"}:
                        label = f"find {ex} {inner}"
            if label:
                roots = [(w, d) for w, d in args if not w.startswith("-")][:1] or [(".", False)]
                for raw, _ in roots:
                    add(place(label, raw))
            return

        if verb in {"chmod", "chown", "chgrp"} and any("R" in f for f in flags if not f.startswith("--")):
            for raw, _ in args[1:]:
                add(place(f"{verb} -R", raw, kind="write"))
            return

        if verb in {"truncate", "dd"}:
            for raw, _ in args:
                if verb == "dd" and not raw.startswith("of="):
                    continue
                add(place(verb, raw[3:] if raw.startswith("of=") else raw, kind="write"))
            return

        if verb == "rsync" and any(f.startswith("--delete") for f in flags) and args:
            add(place("rsync --delete", args[-1][0]))
            return

        if verb in {"curl", "wget", "scp", "nc", "ncat"}:
            argv = [w for w, _ in words]
            # Egress means a local file leaves the machine. Inline JSON bodies
            # (`-d '{"q":..}'`) are ordinary API use and stay benign.
            uploads = any(
                a in {"-T", "--upload-file", "--post-file"}
                or (a.startswith("@") and i > 0 and argv[i - 1] in {"-d", "--data", "--data-binary", "--data-raw"})
                or a.startswith(("-d@", "--data=@", "--data-binary=@", "--data-binary", "--post-file="))
                or (argv[i - 1] in {"-F", "--form"} and "=@" in a if i > 0 else False)
                for i, a in enumerate(argv)
            )
            remote = not any(re.search(r"localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]", a) for a in argv)
            if (verb == "scp" or uploads) and remote:
                rep.egress.append(verb)
            return

        if verb in {"cat", "head", "tail", "less", "more", "bat", "strings", "base64", "xxd", "od", "cp", "rg", "grep"}:
            for raw, _ in args:
                sub, dyn = substitute_vars(raw, env)
                if not dyn:
                    r = _resolve(sub, vcwd)
                    if _zone(r, launch_cwd) == "credential":
                        rep.credential_reads.append(r)
            return

        # Key material fetched through a tool rather than a file.
        if verb == "aws" and "configure" in [w for w, _ in words] and any("secret" in w for w, _ in words):
            rep.credential_reads.append("aws configure get <secret>")
            return
        if verb in {"security", "gh"} and any(w in {"find-generic-password", "find-internet-password", "auth", "token"} for w, _ in words):
            if verb == "security" or "token" in [w for w, _ in words]:
                rep.credential_reads.append(f"{verb} {' '.join(w for w, _ in words[1:3])}")
            return

        if verb in OPAQUE_VERBS:
            argv = [w for w, _ in words]
            if verb in {"bash", "sh", "zsh", "dash"} and ("-c" in argv or len(argv) == 1):
                rep.opaque.append(f"{verb} -c")
            elif verb in {"python", "python3", "node", "ruby", "perl", "php"} and ("-c" in argv or "-e" in argv or "-" in argv[1:2] or rep.heredocs):
                rep.opaque.append(f"{verb} inline/stdin program")
            elif verb in {"eval", "exec", "source", ".", "xargs", "parallel", "osascript"}:
                rep.opaque.append(verb)
            elif verb in {"sudo", "env", "nohup", "time", "timeout", "nice", "watch"}:
                # Wrapper: judge the inner command as if run directly.
                inner = [w for w, _ in words[1:] if not w.startswith("-")]
                if verb == "sudo":
                    rep.opaque.append("wrapper sudo")
                if inner:
                    sub = analyze(" ".join(inner), vcwd)
                    for t in sub.targets:
                        add(t)
                    rep.opaque.extend(sub.opaque)
                    rep.egress.extend(sub.egress)
            # Package managers / build tools run arbitrary scripts, but they are
            # the agent's everyday work; the floor observes.
            return

    for tree in trees:
        visit(tree)

    if rep.targets or rep.config_writes or rep.egress or rep.credential_reads:
        rep.status = "destructive"
    elif rep.opaque:
        rep.status = "opaque"
    return rep
