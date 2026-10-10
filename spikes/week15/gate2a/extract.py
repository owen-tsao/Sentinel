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
SYSTEM_PREFIXES = ("/bin/", "/sbin/", "/usr/", "/etc/", "/System/", "/Library/", "/var/", "/private/etc/", "/opt/", "/dev/", "/boot/", "/proc/", "/sys/")
PROTECTED_CONFIG = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    "managed-settings.json",
    ".cursor/hooks.json",
    ".cursor/hooks/",
    ".sentinel/",
    "sentinel.toml",
    # Evidence and shell history: in three 2026 incidents the agent's sweep
    # destroyed its own transcript; history edits are defense evasion.
    # Bare `.claude/` is deliberately not here: repos carry `.claude/commands`
    # and `CLAUDE.md` that agents legitimately edit.
    ".claude/projects/",
    ".claude-mem/",
    ".bash_history",
    ".zsh_history",
)
CREDENTIAL_PATHS = (".ssh/", ".aws/", ".gnupg/", ".netrc", ".npmrc", ".pypirc", ".docker/config.json", ".kube/config", ".config/gh/")
# Inside key-store directories, these are configuration, not key material.
CREDENTIAL_EXEMPT = (".ssh/config", ".ssh/known_hosts", ".aws/config")
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
    "xargs", "parallel", "sudo", "env", "nohup", "time", "timeout", "nice", "watch", "command", "busybox", "doas", "ionice", "chronic", "caffeinate", "stdbuf", "unbuffer",
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
WRAPPERS = {"sudo", "doas", "env", "nohup", "time", "timeout", "nice", "ionice", "watch", "command", "busybox", "chronic", "caffeinate", "stdbuf", "unbuffer"}
# Wrapper flags that take a value.
WRAPPER_VALUE_FLAGS = {
    "sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"}, "doas": {"-u", "-C"},
    "nice": {"-n", "--adjustment"}, "ionice": {"-c", "-n", "-p"}, "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "watch": {"-n", "--interval", "-d"}, "stdbuf": {"-i", "-o", "-e"}, "env": {"-u", "-C", "-S"},
}


def shlex_join(parts: list[str]) -> str:
    import shlex
    return " ".join(shlex.quote(p) for p in parts)


def _strip_wrapper(verb: str, argv: list[str]) -> list[str]:
    """Drop the wrapper's own arguments up to the wrapped command."""
    values = WRAPPER_VALUE_FLAGS.get(verb, set())
    i = 0
    if verb == "timeout" and argv and re.match(r"^\d+[smhd]?$", argv[0]):
        i = 1  # positional duration
    while i < len(argv):
        a = argv[i]
        if a.startswith("-"):
            i += 2 if a in values and "=" not in a else 1
            continue
        if verb == "env" and "=" in a and not a.startswith("="):
            i += 1  # VAR=value assignments
            continue
        break
    return argv[i:]


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


def substitute_vars(raw: str, env: dict[str, str], *, undefined_as_empty: bool = False) -> tuple[str, bool]:
    """Replace `$VAR`/`${VAR}` with known literal assignments. Returns
    (text, still_dynamic).

    `undefined_as_empty` is the incident rule: in the 2026 home-directory
    wipes the deletion looked scoped (`rm -rf "$DIR"/*`) and resolved to `/*`
    because the variable was empty at run time. For delete targets, an
    undefined variable is evaluated the way the shell would, as nothing, and
    the resulting path is judged. `${VAR:-default}` uses the default."""
    def repl(m: re.Match[str]) -> str:
        name = m.group(1)
        if name in env:
            return env[name]
        if undefined_as_empty:
            return ""
        return m.group(0)
    out = DEFAULT_REF.sub(lambda m: env.get(m.group(1), m.group(2)), raw)
    out = VAR_REF.sub(repl, out)
    return out, bool(VAR_REF.search(out)) or "`" in out or "$(" in out


DEFAULT_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):?-([^}]*)\}")


def glob_parent(raw: str) -> str | None:
    """`out/review/st-*.png` -> `out/review`; `*.png` -> `.`; `/*` -> `/`;
    `**/x` -> None. A glob only in the last path segment leaves the
    directory knowable."""
    parts = raw.split("/")
    if any(GLOB_CHARS.search(p) for p in parts[:-1]):
        return None
    if not GLOB_CHARS.search(parts[-1]):
        return raw
    head = "/".join(parts[:-1])
    if head == "" and raw.startswith("/"):
        return "/"
    return head or "."


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


def _expand_home(raw: str, home: str) -> str:
    """`~` and `~/x` against the session's home, which is a hook fact, not
    this process's environment."""
    if raw == "~":
        return home
    if raw.startswith("~/"):
        return home + raw[1:]
    return raw


def _resolve(raw: str, vcwd: str, home: str = HOME) -> str:
    expanded = _expand_home(raw, home)
    candidate = expanded if expanded.startswith("/") else posixpath.join(vcwd, expanded)
    return posixpath.normpath(candidate)


def _zone(resolved: str, launch_cwd: str, home: str = HOME) -> str:
    lc = posixpath.normpath(launch_cwd)
    probe = resolved + "/"  # so `.claude/projects/` matches the directory itself
    if any(p in probe for p in PROTECTED_CONFIG):
        return "protected_config"
    if resolved == "/":
        return "root"
    # Home, or any ancestor of home (`/Users`, `/home`): deleting it deletes home.
    if resolved == home or (home + "/").startswith(resolved + "/"):
        return "home"
    exempt = resolved.endswith(CREDENTIAL_EXEMPT)
    # Key-store directories are credentials wherever they sit.
    if not exempt and any(c in probe for c in CREDENTIAL_PATHS):
        return "credential"
    if resolved == lc:
        # The working directory itself. Deleting or overwriting the thing the
        # agent was launched in is never "inside" work.
        return "cwd_root"
    if resolved.startswith(lc + "/"):
        # Launching from ~ does not make ~ a trusted working directory: that is
        # how the home-directory wipes happened. Children of ~ stay "outside".
        if lc == home:
            return "outside"
        return "inside"
    # Filename patterns (`id_rsa`, `*.pem`) count only outside the repo, where
    # they are key material rather than test fixtures.
    if not exempt and CREDENTIAL_NAMES.search(resolved):
        return "credential"
    if resolved.startswith(TEMP_PREFIXES) or resolved in {p.rstrip("/") for p in TEMP_PREFIXES}:
        return "temp"
    if resolved.startswith(SYSTEM_PREFIXES):
        return "system"
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


def analyze(command: str, launch_cwd: str, home: str | None = None) -> Report:
    home = home or HOME
    rep = Report()
    text, rep.heredocs = strip_heredocs(command)
    try:
        trees = bashlex.parse(text)
    except Exception as e:  # bashlex raises several types
        rep.status = "unparseable"
        rep.parse_error = f"{type(e).__name__}: {str(e)[:80]}"
        return rep

    vcwd = launch_cwd
    env: dict[str, str] = {"HOME": home, "TMPDIR": "/tmp", "PWD": launch_cwd}

    def place(verb: str, raw: str, kind: str = "delete", note: str = "", container: bool = False) -> Target:
        """Resolve one argv word to a Target, salvaging what can be known.
        Order matters: substitute variables first, then treat a trailing glob
        as 'the directory it lives in', then give up only if something
        dynamic is still left. Delete targets evaluate undefined variables as
        empty (the incident rule); `$(...)` stays dynamic.

        `container`: the path is a directory whose *contents* are affected
        (find root, glob parent), not the directory itself, so resolving to
        the cwd is ordinary inside work rather than deleting the cwd."""
        text, dyn = substitute_vars(raw, env, undefined_as_empty=(kind == "delete"))
        if dyn:
            return Target(verb, raw, None, "dynamic", note, kind)
        collapsed = text != raw and VAR_REF.search(raw) is not None and text.strip("/*") == ""
        if kind == "delete" and text == "" :
            # `rm -rf "$DIR"` with DIR unset: rm receives an empty string, which
            # fails harmlessly. Only the `/*` and `/` suffix forms are deadly.
            return Target(verb, raw, None, "dynamic", "empty target (no-op)", kind)
        knowable = glob_parent(text)
        if knowable is None:
            return Target(verb, raw, None, "dynamic", "glob in directory segment", kind)
        r = _resolve(knowable, vcwd, home)
        zone = _zone(r, launch_cwd, home)
        if zone == "cwd_root" and (container or knowable != text):
            zone = "inside"
        n = note if knowable == text else (note + " (glob: judged by directory)").strip()
        if collapsed:
            n = (n + " (variable collapsed to empty; judged as resolved)").strip()
        return Target(verb, raw, r, zone, n, kind)

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
        # Everything else (list, compound, if, for, while, function) is a
        # container. Descend into every attribute that holds nodes; a subshell
        # `( ... )` or `{ ...; }` must not hide a command from the floor.
        for attr in ("parts", "list"):
            children = getattr(node, attr, None)
            if isinstance(children, list):
                for child in children:
                    if hasattr(child, "kind"):
                        visit(child)
        for attr in ("command", "body", "condition"):
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
                    env[name] = _expand_home(sub, home)
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

        if verb in {"cd", "pushd"}:
            if not args:
                vcwd = home
            else:
                sub, dyn = substitute_vars(args[0][0], env)
                if dyn:
                    rep.opaque.append("cd to dynamic path")
                else:
                    vcwd = _resolve(sub, vcwd, home)
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
                add(place("mv dest", args[-1][0], kind="write", container=True))
            return

        if verb == "git":
            sub = [w for w, _ in words[1:]]
            for key, label in GIT_DESTRUCTIVE.items():
                if all(k in sub for k in key):
                    # git acts on the repo containing vcwd (or -C <dir>).
                    repo = vcwd
                    if "-C" in sub and sub.index("-C") + 1 < len(sub):
                        repo = _resolve(sub[sub.index("-C") + 1], vcwd, home)
                    z = _zone(repo, launch_cwd, home)
                    add(Target(label, ".", repo, "inside" if z == "cwd_root" else z, " ".join(sub[:4])))
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
                    elif inner in {"cat", "head", "tail", "sh", "bash", "cp", "scp", "curl", "base64"}:
                        # Reading whatever the -name pattern finds. If the pattern
                        # names key material, that is a credential read.
                        names = [argv[j + 1] for j, a in enumerate(argv) if a in {"-name", "-iname", "-path"} and j + 1 < len(argv)]
                        if any(CREDENTIAL_NAMES.search(n.strip("*")) or n.strip("*") in {"id_rsa", "id_ed25519", ".pem", "credentials"} for n in names):
                            rep.credential_reads.append(f"find {' '.join(names)} {ex} {inner}")
            if label:
                roots = [(w, d) for w, d in args if not w.startswith("-")][:1] or [(".", False)]
                for raw, _ in roots:
                    add(place(label, raw, container=True))
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
                    r = _resolve(sub, vcwd, home)
                    if _zone(r, launch_cwd, home) == "credential":
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
            elif verb in WRAPPERS:
                # Wrapper: judge the inner command as if run directly. Skip the
                # wrapper's own flags and their values (`nice -n 5`, `timeout 30`,
                # `sudo -u root`, `env FOO=bar`) up to the first bare word.
                inner = _strip_wrapper(verb, [w for w, _ in words[1:]])
                if verb in {"sudo", "doas"}:
                    rep.opaque.append("wrapper sudo")
                if inner:
                    sub = analyze(shlex_join(inner), vcwd, home)
                    for t in sub.targets:
                        add(t)
                    rep.opaque.extend(sub.opaque)
                    rep.egress.extend(sub.egress)
                    rep.credential_reads.extend(sub.credential_reads)
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
