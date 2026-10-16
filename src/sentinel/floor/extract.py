"""Floor-oriented target extraction over agent shell commands.

Allow-by-default: a command with no visible destructive verb passes. The
floor only needs to know (a) whether anything destructive is happening,
(b) which paths it hits, and (c) which zone each path lands in relative to
the directory the agent was launched in.

Two directories matter and they are not the same thing. `cwd` is where the
shell is right now (Claude Code's hook payload moves it when the agent runs
`cd`); relative paths resolve against it. `launch_cwd` is where the person
started the agent; zones are judged against it, so a `cd /` in one call
cannot widen what counts as "inside" in the next.

Every construct the parser skips is a silent allow (Week 15 finding 4), so
the walker descends into every node kind bashlex produces, including
command and process substitutions.
"""

from __future__ import annotations

import os
import posixpath
import re
import shlex
from dataclasses import dataclass, field

import bashlex
import bashlex.ast

from sentinel.decisions.models import HEREDOC_BODY_PLACEHOLDER, strip_heredoc_bodies

TEMP_PREFIXES = ("/tmp/", "/private/tmp/", "/var/folders/", "/private/var/folders/")
SYSTEM_PREFIXES = (
    "/bin/", "/sbin/", "/usr/", "/etc/", "/System/", "/Library/", "/var/",
    "/private/etc/", "/opt/", "/dev/", "/boot/", "/proc/", "/sys/",
)
# Hook, settings, and Sentinel configuration, plus the places an agent could
# plant a hook-adjacent file or stop the supervisor. Bare `.claude/` is not
# here: repos carry `.claude/commands` and `CLAUDE.md` that agents edit.
PROTECTED_CONFIG = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    "managed-settings.json",
    "managed-settings.d/",
    ".claude/skills/",
    ".claude/agents/",
    ".claude.json",
    ".mcp.json",
    ".cursor/hooks.json",
    ".cursor/hooks/",
    ".cursor/mcp.json",
    ".sentinel/",
    "sentinel.toml",
    "Library/LaunchAgents/",
    # Evidence and shell history: in three 2026 incidents the agent's sweep
    # destroyed its own transcript; history edits are defense evasion.
    ".claude/projects/",
    ".claude-mem/",
    ".bash_history",
    ".zsh_history",
)
CREDENTIAL_PATHS = (
    ".ssh/", ".aws/", ".gnupg/", ".netrc", ".npmrc", ".pypirc",
    ".docker/config.json", ".kube/config", ".config/gh/",
)
# Inside key-store directories, these are configuration, not key material.
CREDENTIAL_EXEMPT = (".ssh/config", ".ssh/known_hosts", ".aws/config")
# Key material by filename, judged only outside the repository. Project `.env`
# files are deliberately excluded: agents read and recreate them constantly.
CREDENTIAL_NAMES = re.compile(r"id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$|\.pem$|\.p12$|\.pfx$|credentials(\.json)?$", re.IGNORECASE)
HOME_BLOCK_WRITE = (
    ".ssh/", ".aws/", ".gnupg/", ".config/", "Library/LaunchAgents/", "Library/LaunchDaemons/",
    ".claude/", ".claude.json", ".cursor/",
    ".bashrc", ".bash_profile", ".zshrc", ".zprofile", ".zshenv", ".profile", ".bash_logout",
    ".gitconfig", ".npmrc", ".pypirc", ".netrc",
)
# Where the host stores the agent's own output (Week 18 amendment, Direction
# §3.1): plan files and per-workspace artefacts (canvases, assets). Writes
# there are ordinary work (156 plan writes in the person's corpus), so they
# are zone `host_artifact` rather than the `.cursor/` carve-out. The
# directories themselves, and `agent-transcripts/` (evidence: in three 2026
# incidents the agent deleted its own transcript), stay under the carve-out.
HOST_ARTIFACT_DIRS = (".cursor/plans/", ".cursor/projects/")
HOST_EVIDENCE_DIRS = ("agent-transcripts",)
# Lower-cased once for the case-folded matches in `zone_of`.
_PROTECTED_CONFIG_CI = tuple(p.lower() for p in PROTECTED_CONFIG)
_CREDENTIAL_PATHS_CI = tuple(c.lower() for c in CREDENTIAL_PATHS)


def host_artifact(resolved: str, home: str) -> bool:
    """Return True for a file inside a host artefact directory.

    The directory itself is not an artefact, and neither is anything under an
    evidence folder (`agent-transcripts/`) within it.
    """
    if not resolved.startswith(home + "/"):
        return False
    rel = resolved[len(home) + 1:]
    for prefix in HOST_ARTIFACT_DIRS:
        if not rel.startswith(prefix):
            continue
        remainder = rel[len(prefix):]
        parts = [p for p in remainder.split("/") if p]
        if prefix == ".cursor/projects/":
            # <workspace>/<kind>/...: the workspace folder itself holds the transcripts.
            if len(parts) < 2 or parts[1] in HOST_EVIDENCE_DIRS:
                return False
            return True
        return bool(parts)
    return False

DELETE_VERBS = {"rm", "rmdir", "unlink", "shred"}
MOVE_VERBS = {"mv"}
OPAQUE_VERBS = {
    "bash", "sh", "zsh", "dash", "eval", "exec", "source", ".",
    "python", "python3", "node", "ruby", "perl", "php", "osascript",
    "xargs", "parallel", "sudo", "env", "nohup", "time", "timeout", "nice", "watch", "command",
    "busybox", "doas", "ionice", "chronic", "caffeinate", "stdbuf", "unbuffer",
    "make", "npm", "pnpm", "yarn", "npx", "bun", "uv", "uvx", "pip", "pip3", "poetry",
    "cargo", "go", "docker", "docker-compose",
}
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
WRAPPERS = {
    "sudo", "doas", "env", "nohup", "time", "timeout", "nice", "ionice", "watch", "command",
    "busybox", "chronic", "caffeinate", "stdbuf", "unbuffer",
}
WRAPPER_VALUE_FLAGS = {
    "sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"}, "doas": {"-u", "-C"},
    "nice": {"-n", "--adjustment"}, "ionice": {"-c", "-n", "-p"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "watch": {"-n", "--interval", "-d"}, "stdbuf": {"-i", "-o", "-e"}, "env": {"-u", "--unset"},
}
PIPE_CONSUMERS = {"bash", "sh", "zsh", "xargs", "parallel", "python", "python3", "node", "psql", "sqlite3", "mysql"}
READERS = {"cat", "head", "tail", "less", "more", "bat", "strings", "base64", "xxd", "od", "cp", "rg", "grep"}
# Programs that emit or pack a file's bytes when handed its path. `ls`, `stat`,
# `file`, and `wc` are not here: they describe a file without disclosing it.
CONTENT_READERS = READERS | {
    "sort", "uniq", "awk", "sed", "cut", "tr", "tac", "rev", "nl", "fold", "paste", "join", "ag", "ack",
    "egrep", "fgrep", "tar", "zip", "gzip", "bzip2", "xz", "zstd", "7z", "openssl", "ssh-keygen", "gpg", "jq", "yq",
    "python", "python3", "node", "ruby", "perl", "scp", "rsync", "curl", "wget", "nc", "ncat", "install",
}
VAR_REF = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
# `$1`, `$@`, `$*`, `$#`, `$?`, `$$`, `$!`, `$0`: never known here. In a
# script or hook with no arguments `rm -rf "$1"/*` is `rm -rf /*`.
SPECIAL_REF = re.compile(r"\$(?:[0-9@*#?$!]|\{[0-9@*#?$!]\})")
# `${VAR:-d}` / `${VAR-d}` / `${VAR:=d}` / `${VAR=d}` use `d` when unset;
# `${VAR:+a}` / `${VAR+a}` use `a` only when set; `${VAR:?m}` aborts when unset.
DEFAULT_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!])(:?[-=+?])([^}]*)\}")
GLOB_CHARS = re.compile(r"[*?\[\]{}]")
HEREDOC_OPENER_RE = re.compile(r"(?<!<)<<-?\s*(?:'[^']+'|\"[^\"]+\"|[^\s<>|&;'\"]+)")
# A local host must be the whole host part: `127.0.0.1.evil.com` and
# `localhost.evil.com` are remote (review finding, October 15).
LOCAL_HOST = re.compile(r"(?:^|://|@)(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?=[:/]|$)")
DEVICE_SINKS = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/fd/1", "/dev/fd/2"}


@dataclass
class Target:
    """One path a command deletes or writes, with the zone it lands in."""

    verb: str
    raw: str
    resolved: str | None
    zone: str  # inside | cwd_root | outside | temp | home | root | system | protected_config | credential | host_artifact | dynamic
    note: str = ""
    kind: str = "delete"  # delete | write
    container: bool = False  # the path is a directory the file lands *in* (cp/mv dest, find root)


@dataclass
class Report:
    """Everything the extractor learned about one command.

    `status` is `benign` when nothing destructive was seen, `destructive` when
    any target, config write, egress, or credential read was found, `opaque`
    when a construct hid a command from the parser, and `unparseable` when
    bashlex rejected the text (`parse_error` says why).
    """

    status: str = "benign"  # benign | destructive | opaque | unparseable
    targets: list[Target] = field(default_factory=list)
    opaque: list[str] = field(default_factory=list)
    egress: list[str] = field(default_factory=list)
    credential_reads: list[str] = field(default_factory=list)
    config_writes: list[str] = field(default_factory=list)
    symlinks: list[tuple[str, str]] = field(default_factory=list)  # (link, target), both resolved
    parse_error: str = ""
    heredocs: int = 0
    simple_commands: int = 0


def default_home() -> str:
    """The current user's home directory on this machine."""
    return os.path.expanduser("~")


def guess_home(cwd: str) -> str:
    """Infer a home directory from `cwd` when the host did not supply one.

    A hook fact is always better; this exists so fixtures recorded on another
    machine still resolve.
    """
    match = re.match(r"^(/Users/[^/]+|/home/[^/]+|/root)(?:/|$)", cwd)
    return match.group(1) if match else default_home()


def substitute_vars(raw: str, env: dict[str, str], *, undefined_as_empty: bool = False) -> tuple[str, bool]:
    """Replace `$VAR` / `${VAR}` with known literal assignments.

    Returns `(text, still_dynamic)`. `still_dynamic` is True when something the
    shell would expand remains (indirect `${!X}`, arithmetic, `$(...)`).

    `undefined_as_empty` is the incident rule: `rm -rf "$DIR"/*` with `DIR`
    unset is `rm -rf /*`. Delete targets evaluate an undefined variable the
    way the shell would, as nothing. `${VAR:-default}` uses the default.
    """

    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        if name in env:
            return env[name]
        if undefined_as_empty:
            return ""
        return match.group(0)

    def default_repl(match: re.Match[str]) -> str:
        name, op, word = match.group(1), match.group(2), match.group(3)
        is_set = name in env
        if op.endswith(("-", "=")):
            return env[name] if is_set else word
        if op.endswith("+"):
            return word if is_set else ""
        # `:?` : the shell aborts when unset, so nothing runs; when set, the value.
        return env[name] if is_set else ""

    out = DEFAULT_REF.sub(default_repl, raw)
    out = VAR_REF.sub(repl, out)
    if undefined_as_empty:
        out = SPECIAL_REF.sub("", out)
    # Anything still carrying `$` (indirect `${!X}`, arithmetic, `$(...)`) is unknowable.
    return out, "$" in out or "`" in out


def glob_parent(raw: str) -> str | None:
    """The directory a trailing glob expands inside, or None if a glob sits in a directory segment.

    `out/st-*.png` -> `out`; `*.png` -> `.`; `/*` -> `/`; `**/x` -> None.
    A path with no glob is returned unchanged.
    """
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
    """Replace each heredoc body with an empty stdin redirect.

    Returns `(text, heredoc_count)`. The rest of the operator line is kept, so
    `cat <<EOF > .env` still shows the write to `.env`.

    An unterminated heredoc is left alone. `echo "<<x"` or `$((1 << 3))` look
    like openers whose terminator never comes; stripping "the body" would
    delete every later line before the parser sees them. Left intact, a real
    unterminated heredoc fails to parse (W5 + literal fallback) and a fake
    one parses normally.
    """
    if "<<" not in command:
        return command, 0
    # Never truncated here: the audit cap would drop the tail of the command
    # before the parser saw it, and the tail is where a bypass would hide.
    stripped = strip_heredoc_bodies(command, truncate=False)
    lines = stripped.split("\n")
    if lines and lines[-1] == HEREDOC_BODY_PLACEHOLDER:
        return command, 0
    out: list[str] = []
    opener_lines: set[int] = set()
    count = 0
    i = 0
    while i < len(lines):
        if lines[i] == HEREDOC_BODY_PLACEHOLDER:
            count += 1
            if out:
                opener_lines.add(len(out) - 1)
            i += 2  # the placeholder and its terminator line
            continue
        out.append(lines[i])
        i += 1
    for index in opener_lines:
        out[index] = HEREDOC_OPENER_RE.sub("</dev/null", out[index])
    return "\n".join(out), count


def expand_home(raw: str, home: str) -> str:
    """Expand `~`, `~/x`, `~user`, and `~user/x`; anything else is returned unchanged.

    Another user's home is approximated as a sibling of this one; what matters
    is that it does not resolve as a file inside the project. `~+` (PWD) is
    handled by `resolve` and `~-` (OLDPWD) is treated as dynamic by the caller.
    """
    if raw == "~":
        return home
    if raw.startswith("~/"):
        return home + raw[1:]
    m = re.match(r"^~([A-Za-z_][\w.-]*)(/.*)?$", raw)
    if m:
        user, rest = m.group(1), m.group(2) or ""
        base = "/root" if user == "root" else posixpath.join(posixpath.dirname(home), user)
        return base + rest
    return raw


def normpath(path: str) -> str:
    """`posixpath.normpath`, with a leading `//` collapsed to `/`.

    POSIX leaves `//` implementation-defined and `normpath` preserves exactly
    two; Linux and macOS treat it as `/`, so `rm -rf //` is a root wipe that
    the prefix checks missed (review finding, October 15).
    """
    out = posixpath.normpath(path)
    return "/" + out.lstrip("/") if out.startswith("//") else out


def resolve(raw: str, vcwd: str, home: str) -> str:
    """Resolve one path word to a normalised absolute path against the virtual cwd."""
    if raw == "~+" or raw.startswith("~+/"):
        raw = vcwd + raw[2:]
    expanded = expand_home(raw, home)
    candidate = expanded if expanded.startswith("/") else posixpath.join(vcwd, expanded)
    return normpath(candidate)


def home_carve_out(resolved: str, home: str) -> str | None:
    """The `HOME_BLOCK_WRITE` entry `resolved` falls under, or None.

    Under home, a write to these is a block rather than a confirm: they run
    code at login, start services, or hold tool credentials and configuration.
    Matched case-insensitively: on the default macOS volume `~/.CURSOR/` is
    `~/.cursor/` (review finding, October 15). Folding case can only make a
    verdict stricter, so a case-sensitive host loses nothing but a confirm.
    """
    if not resolved.startswith(home + "/"):
        return None
    rel = resolved[len(home) + 1:].lower()
    for part in HOME_BLOCK_WRITE:
        if part.endswith("/"):
            if rel == part[:-1].lower() or rel.startswith(part.lower()):
                return part
        elif rel == part.lower():
            return part
    return None


def zone_of(resolved: str, launch_cwd: str, home: str) -> str:
    """Which zone an already-resolved absolute path lands in, judged against the launch directory.

    Shared by the shell extractor and the file tools so a path gets the same
    answer whichever tool names it. Checks run most-specific first:
    protected config and credentials before home, home before the launch
    directory, so `~/.ssh` under a home-launched agent is still `credential`.

    The restricting matches (protected config, credential stores, key names)
    fold case, since the default macOS volume does; the permitting ones
    (`host_artifact`, `inside`, the credential exemptions) stay exact, so
    folding can only tighten a verdict, never loosen it.
    """
    lc = posixpath.normpath(launch_cwd)
    probe = resolved + "/"  # so `.claude/projects/` matches the directory itself
    probe_ci = probe.lower()
    if any(p in probe_ci for p in _PROTECTED_CONFIG_CI):
        return "protected_config"
    if resolved == "/":
        return "root"
    # Home, or any ancestor of home (`/Users`, `/home`): deleting it deletes home.
    if resolved == home or (home + "/").startswith(resolved + "/"):
        return "home"
    exempt = resolved.endswith(CREDENTIAL_EXEMPT)
    if not exempt and any(c in probe_ci for c in _CREDENTIAL_PATHS_CI):
        return "credential"
    if host_artifact(resolved, home):
        return "host_artifact"
    if resolved == lc:
        return "cwd_root"
    if resolved.startswith(lc + "/"):
        # Launching from ~ does not make ~ a trusted working directory.
        if lc == home:
            return "outside"
        return "inside"
    if not exempt and CREDENTIAL_NAMES.search(resolved):
        return "credential"
    if resolved.startswith(TEMP_PREFIXES) or resolved in {p.rstrip("/") for p in TEMP_PREFIXES}:
        return "temp"
    if resolved.startswith(SYSTEM_PREFIXES) or resolved in {p.rstrip("/") for p in SYSTEM_PREFIXES}:
        return "system"
    return "outside"


_TIMEOUT_DURATION = re.compile(r"^\d+(?:\.\d+)?[smhd]?$")


def _strip_wrapper(verb: str, argv: list[str], vcwd: str, home: str) -> tuple[list[str], str]:
    """Return `(inner_argv, cwd)` for one wrapper's arguments.

    `env -S 'rm -rf ~'` splits its string into the command; `env -C DIR` /
    `--chdir=DIR` runs the command in DIR; `timeout` takes its duration after
    any flags (`timeout -k 1 5 rm ...`). Each of these used to drop or
    misplace the command and resolve to allow (review finding, October 15).
    """
    values = WRAPPER_VALUE_FLAGS.get(verb, set())
    i = 0
    while i < len(argv):
        a = argv[i]
        if verb == "env" and a in {"-S", "--split-string"} and i + 1 < len(argv):
            try:
                split = shlex.split(argv[i + 1])
            except ValueError:
                split = [argv[i + 1]]
            return _strip_wrapper(verb, split + argv[i + 2:], vcwd, home)
        if verb == "env" and a.startswith("--split-string="):
            try:
                split = shlex.split(a.split("=", 1)[1])
            except ValueError:
                split = [a.split("=", 1)[1]]
            return _strip_wrapper(verb, split + argv[i + 1:], vcwd, home)
        if verb == "env" and (a in {"-C", "--chdir"} or a.startswith("--chdir=")):
            target = a.split("=", 1)[1] if "=" in a else (argv[i + 1] if i + 1 < len(argv) else "")
            vcwd = resolve(target, vcwd, home) if target else vcwd
            i += 1 if "=" in a else 2
            continue
        if a.startswith("-") and len(a) > 1:
            i += 2 if a in values and "=" not in a else 1
            continue
        if verb == "env" and "=" in a and not a.startswith("="):
            i += 1
            continue
        if verb == "timeout" and _TIMEOUT_DURATION.match(a):
            i += 1
            verb = ""  # only one duration
            continue
        break
    return argv[i:], vcwd


def _strip_wrappers(argv: list[str], vcwd: str, home: str) -> tuple[list[str], str, bool]:
    """Peel every leading wrapper in one pass: `(inner_argv, cwd, saw_sudo)`.

    Iterative rather than one recursive `analyze` per wrapper: 2,000 `sudo`
    prefixes re-parsed the remainder 2,000 times (10 s; review finding,
    October 15).
    """
    saw_sudo = False
    while argv and posixpath.basename(argv[0]) in WRAPPERS and not DYNAMIC.search(argv[0]):
        verb = posixpath.basename(argv[0])
        saw_sudo = saw_sudo or verb in {"sudo", "doas"}
        argv, vcwd = _strip_wrapper(verb, argv[1:], vcwd, home)
    return argv, vcwd, saw_sudo


def _words(node: bashlex.ast.node) -> list[tuple[str, bool]]:
    out: list[tuple[str, bool]] = []
    for part in node.parts:
        if part.kind == "word":
            has_parts = bool(getattr(part, "parts", None))
            for w in _expand_word(part.word):
                out.append((w, has_parts or bool(DYNAMIC.search(w))))
    return out


def _expand_word(word: str) -> list[str]:
    """Brace-expand an unquoted word; quoted or escaped braces are literal and left alone."""
    if "{" not in word or any(c in word for c in "'\"\\"):
        return [word]
    expanded = brace_expand(word)
    return expanded if expanded is not None else [word]


def _redirect_targets(node: bashlex.ast.node) -> list[tuple[str, bool]]:
    out = []
    for part in node.parts:
        # `>&` and `&>>` write the file like `>`; `<>` opens it read-write and
        # creates it (review finding, October 15: `echo x >& ~/.zshrc` was allow).
        if part.kind == "redirect" and part.type in {">", ">>", ">|", "&>", ">&", "&>>", "<>"} and hasattr(part.output, "word"):
            for w in _expand_word(part.output.word):
                out.append((w, bool(DYNAMIC.search(w))))
    return out


def _stdin_sources(node: bashlex.ast.node) -> list[str]:
    """Files fed to a command with `<` (not heredocs, which are stripped earlier)."""
    return [
        part.output.word for part in node.parts
        if part.kind == "redirect" and part.type == "<" and hasattr(part.output, "word")
    ]


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


def _shlex_join(parts: list[str]) -> str:
    return " ".join(shlex.quote(p) for p in parts)


_ESCAPE = re.compile(r"\\(.)")


def _unescape(word: str) -> str:
    """Drop the backslashes bashlex leaves in words so `\\rm` and `\\/` read as the shell sees them.

    Outside quotes a backslash only protects the next character, so dropping
    it yields what the shell executes. Variable and glob characters stay
    escaped (`\\$HOME` is the literal text, not the variable).
    """
    if "\\" not in word:
        return word
    return _ESCAPE.sub(lambda m: m.group(0) if m.group(1) in "$`*?[]{}" else m.group(1), word)


_TIME_PREFIX = re.compile(r"(^|[;&|(\n]\s*)time\s+(?:-p\s+)?")
_DOUBLE_BRACKET_OPEN = re.compile(r"(^|[\s;&|(])\[\[(?=\s)")
_DOUBLE_BRACKET_CLOSE = re.compile(r"(?<=\s)\]\](?=[\s;&|)]|$)")


def _parser_prepass(text: str) -> str:
    """Rewrite two bash forms bashlex rejects into forms it parses the same way.

    `time CMD` is a reserved word bashlex does not know; `[[ expr ]]` is a
    keyword. Both are common, and an unparseable command only reaches the
    narrow literal fallback, so `time rm -rf ~/.ssh` and `[[ -f x ]] && rm
    -rf ~/.ssh` were a warn (review finding, October 15). `time` adds nothing
    the floor judges; `[ expr ]` is a command bashlex parses with the same
    words.
    """
    text = _TIME_PREFIX.sub(r"\1", text)
    if "[[" in text:
        text = _DOUBLE_BRACKET_OPEN.sub(r"\1[", text)
        text = _DOUBLE_BRACKET_CLOSE.sub("]", text)
    return text


_BRACE_LIST = re.compile(r"\{([^{}]*,[^{}]*)\}")
MAX_BRACE_ALTERNATIVES = 64


def brace_expand(word: str) -> list[str] | None:
    """Expand simple `{a,b}` lists the way bash does, or None when the word has
    a brace form this does not model (nesting, `{1..5}`, more than 64 results).

    `rm -rf {~,}` is `rm -rf ~ ''` and `> .cursor/hooks.json{,}` names the hook
    file; judging the braces as a glob in the current directory let both
    through (review finding, October 15). Escaped and quoted braces are left to
    the caller (bashlex keeps the quotes in the word).
    """
    if "{" not in word:
        return [word]
    out = [word]
    for _ in range(8):  # nested lists are expanded outermost-last, 8 levels deep
        m = next((_BRACE_LIST.search(w) for w in out if _BRACE_LIST.search(w)), None)
        if m is None:
            break
        expanded: list[str] = []
        for w in out:
            m = _BRACE_LIST.search(w)
            if m is None:
                expanded.append(w)
                continue
            for alt in m.group(1).split(","):
                expanded.append(w[:m.start()] + alt + w[m.end():])
        out = expanded
        if len(out) > MAX_BRACE_ALTERNATIVES:
            return None
    if any("{" in w and _BRACE_LIST.search(w) for w in out):
        return None
    return out


def analyze(command: str, cwd: str, launch_cwd: str | None = None, home: str | None = None) -> Report:
    """Extract every path the command touches and zone it.

    `cwd` is where the shell is for this call; `launch_cwd` (default: `cwd`)
    is the boundary zones are judged against. `home` is a hook fact; it
    defaults to a guess from the cwd so fixtures from other machines resolve.
    """
    launch_cwd = posixpath.normpath(launch_cwd or cwd)
    home = home or guess_home(launch_cwd)
    rep = Report()
    # A NUL cannot reach argv; judging the text with it removed is the strict reading.
    text, rep.heredocs = strip_heredocs(_parser_prepass(command.replace("\x00", "")))
    try:
        trees = bashlex.parse(text)
    except Exception as exc:  # noqa: BLE001 - bashlex raises several types
        rep.status = "unparseable"
        rep.parse_error = f"{type(exc).__name__}: {str(exc)[:80]}"
        return rep

    vcwd = posixpath.normpath(cwd)
    env: dict[str, str] = {"HOME": home, "TMPDIR": "/tmp", "PWD": vcwd}

    def through_symlink(resolved: str) -> tuple[str, str] | None:
        """Rewrite `resolved` through a symlink created earlier in this command.

        Returns `(rewritten_path, link)` when `resolved` is, or sits under, such
        a link, so the link target's zone is the one judged; None otherwise.
        `ln -s ~ h && rm -rf h/` is a home wipe.
        """
        for link, target in rep.symlinks:
            if resolved == link:
                return target, link
            if resolved.startswith(link + "/"):
                return target + resolved[len(link):], link
        return None

    def place(verb: str, raw: str, kind: str = "delete", note: str = "", container: bool = False) -> Target:
        """Resolve one argv word to a Target, salvaging what can be known.

        Order: substitute variables, then treat a trailing glob as "the
        directory it lives in", then give up only if something dynamic is
        still left. Delete targets evaluate undefined variables as empty (the
        incident rule); `$(...)` stays dynamic.

        `container`: the path is a directory whose *contents* are affected
        (find root, glob parent), so resolving to the cwd is ordinary inside
        work rather than deleting the cwd.
        """
        text, dyn = substitute_vars(raw, env, undefined_as_empty=(kind == "delete"))
        if dyn or text == "~-" or text.startswith("~-/"):
            return Target(verb, raw, None, "dynamic", note or ("previous directory" if text.startswith("~-") else ""), kind)
        had_ref = VAR_REF.search(raw) is not None or SPECIAL_REF.search(raw) is not None
        collapsed = text != raw and had_ref and text.strip("/*") == ""
        if kind == "delete" and text == "":
            return Target(verb, raw, None, "dynamic", "empty target (no-op)", kind)
        knowable = glob_parent(text)
        if knowable is None:
            return Target(verb, raw, None, "dynamic", "glob in directory segment", kind)
        r = resolve(knowable, vcwd, home)
        rewritten = through_symlink(r)
        if rewritten is not None:
            r, link = rewritten
            note = (note + f" (through symlink {link} created in this command)").strip()
        zone = zone_of(r, launch_cwd, home)
        if zone == "cwd_root" and (container or knowable != text):
            zone = "inside"
        if container and kind == "write" and zone == "home":
            # `cp report.pdf ~/`: the file lands *in* home; home itself is not
            # overwritten. Deletes keep the stricter zone (`find ~ -delete`).
            zone = "outside"
        n = note if knowable == text else (note + " (glob: judged by directory)").strip()
        if collapsed:
            n = (n + " (variable collapsed to empty; judged as resolved)").strip()
        return Target(verb, raw, r, zone, n, kind, container=container)

    def add(t: Target) -> None:
        rep.targets.append(t)
        if t.zone == "protected_config":
            rep.config_writes.append(t.resolved or t.raw)

    def visit(node: bashlex.ast.node) -> None:
        if node.kind == "command":
            rep.simple_commands += 1
            handle_command(node)
            visit_substitutions(node)
            return
        if node.kind == "pipeline":
            handle_pipeline(node)
            return
        # list, compound, if, for, while, until, function: containers. Descend
        # into every attribute that holds nodes so `( ... )` and `{ ...; }`
        # cannot hide a command from the floor.
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

    def visit_substitutions(node: bashlex.ast.node) -> None:
        """`echo $(rm -rf ~)` and `cat <(rm -rf /)` run the inner command."""
        for part in getattr(node, "parts", []) or []:
            for inner in getattr(part, "parts", []) or []:
                if getattr(inner, "kind", None) in {"commandsubstitution", "processsubstitution"}:
                    cmd = getattr(inner, "command", None)
                    if cmd is not None and hasattr(cmd, "kind"):
                        visit(cmd)

    def handle_pipeline(node: bashlex.ast.node) -> None:
        cmds = [p for p in node.parts if p.kind != "pipe"]
        for i, c in enumerate(cmds):
            if c.kind == "command":
                words = _words(c)
                if words and i > 0 and posixpath.basename(words[0][0]) in PIPE_CONSUMERS:
                    rep.opaque.append(f"pipe into {posixpath.basename(words[0][0])}")
            visit(c)

    def handle_command(node: bashlex.ast.node) -> None:
        nonlocal vcwd
        words = _words(node)
        for part in node.parts:
            if part.kind == "assignment":
                # `VAR=x cmd` sets VAR only in the child's environment; the
                # shell expands `cmd`'s words first, so `HOME=/tmp rm -rf $HOME`
                # deletes the real home (review finding, October 15). Only a
                # bare assignment (`VAR=x; cmd`) changes what later words mean.
                if words:
                    continue
                name, _, value = part.word.partition("=")
                value = value.strip("\"'")
                sub, dyn = substitute_vars(value, env)
                if not dyn:
                    env[name] = expand_home(sub, home)
        for raw, _ in _redirect_targets(node):
            t = place("redirect >", raw, kind="write")
            if t.resolved not in DEVICE_SINKS:
                add(t)
        if not words:
            return
        # `\rm` bypasses an alias, not the floor: an escaped verb is the verb.
        # `builtin rm` / `command rm` likewise.
        words = [(_unescape(w), d) for w, d in words]
        while len(words) > 1 and posixpath.basename(words[0][0]) in {"builtin", "command"}:
            words = words[1:]
        verb, verb_dyn = words[0]
        # Lower-cased: on the default macOS volume `/bin/RM` is `rm`. Folding
        # can only make a verdict stricter (review finding, October 15).
        verb = posixpath.basename(verb).lower()
        if verb_dyn:
            rep.opaque.append("dynamic executable")
            return
        flags, args = _flag_args(words)

        # Naming a key file as stdin (`tr a a < ~/.ssh/id_rsa`) reads it whatever
        # the program; naming it as an argument reads it when the program emits
        # or packs file contents (`sort`, `tar`, `openssl`), but `ls ~/.ssh` only
        # lists names.
        candidates = _stdin_sources(node) + ([w for w, _ in args] if verb in CONTENT_READERS else [])
        for raw in candidates:
            sub, dyn = substitute_vars(raw, env)
            if not dyn and (sub.startswith(("/", "~", ".")) or "/" in sub):
                r = resolve(sub, vcwd, home)
                if zone_of(r, launch_cwd, home) == "credential" and r not in rep.credential_reads:
                    rep.credential_reads.append(r)

        if verb in {"cd", "pushd"}:
            if not args:
                vcwd = home
            else:
                sub, dyn = substitute_vars(args[0][0], env)
                if dyn:
                    rep.opaque.append("cd to dynamic path")
                else:
                    vcwd = resolve(sub, vcwd, home)
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

        if verb == "tee":
            # `... | sudo tee /etc/hosts` is the write; the pipe feeds it.
            for raw, _ in args:
                t = place("tee", raw, kind="write")
                if t.resolved not in DEVICE_SINKS:
                    add(t)
            return

        if verb == "ln" and ("--symbolic" in flags or any("s" in f for f in flags if not f.startswith("--"))):
            # `ln -s TARGET [LINK]`. The link itself is a harmless write; what
            # matters is where it points, so a later delete through it is
            # judged at the target. The link can live anywhere the agent can
            # write (`/tmp/x -> /` is as good as `./x -> /`).
            if args:
                target_text, dyn = substitute_vars(args[0][0], env)
                if not dyn:
                    target = resolve(target_text, vcwd, home)
                    link_raw = args[1][0] if len(args) > 1 else posixpath.basename(target_text.rstrip("/")) or "."
                    link_text, link_dyn = substitute_vars(link_raw, env)
                    if not link_dyn:
                        link = resolve(link_text, vcwd, home)
                        if link != target and not target.startswith(link + "/"):
                            rep.symlinks.append((link, target))
            return

        if verb == "git":
            sub = [w for w, _ in words[1:]]
            for key, label in GIT_DESTRUCTIVE.items():
                if all(k in sub for k in key):
                    repo = vcwd
                    if "-C" in sub and sub.index("-C") + 1 < len(sub):
                        repo = resolve(sub[sub.index("-C") + 1], vcwd, home)
                    z = zone_of(repo, launch_cwd, home)
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
            uploads = any(
                a in {"-T", "--upload-file", "--post-file"}
                or (a.startswith("@") and i > 0 and argv[i - 1] in {"-d", "--data", "--data-binary", "--data-raw"})
                or a.startswith(("-d@", "--data=@", "--data-binary=@", "--data-binary", "--post-file="))
                or (argv[i - 1] in {"-F", "--form"} and "=@" in a if i > 0 else False)
                for i, a in enumerate(argv)
            )
            remote = not any(LOCAL_HOST.search(a) for a in argv)
            if (verb == "scp" or uploads) and remote:
                rep.egress.append(verb)
            return

        if verb in READERS:
            for raw, _ in args:
                sub, dyn = substitute_vars(raw, env)
                if not dyn:
                    r = resolve(sub, vcwd, home)
                    if zone_of(r, launch_cwd, home) == "credential":
                        rep.credential_reads.append(r)
            if verb == "cp" and len(args) >= 2:
                add(place("cp dest", args[-1][0], kind="write", container=True))
            return

        if verb == "install" and args:
            # `install SRC... DEST` is a copy with modes; `install -d DIR` makes directories.
            targets = args if "-d" in flags or "--directory" in flags else args[-1:]
            for raw, _ in targets:
                add(place("install", raw, kind="write", container=len(args) >= 2))
            return

        if verb == "aws" and "configure" in [w for w, _ in words] and any("secret" in w for w, _ in words):
            rep.credential_reads.append("aws configure get <secret>")
            return
        if verb in {"security", "gh"} and any(w in {"find-generic-password", "find-internet-password", "dump-keychain", "export", "auth", "token"} for w, _ in words):
            if verb == "security" or "token" in [w for w, _ in words]:
                rep.credential_reads.append(f"{verb} {' '.join(w for w, _ in words[1:3])}")
            return
        if verb == "gpg" and any(w.startswith("--export-secret") for w, _ in words):
            rep.credential_reads.append("gpg --export-secret-keys")
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
                inner, inner_cwd, saw_sudo = _strip_wrappers([w for w, _ in words], vcwd, home)
                if saw_sudo:
                    rep.opaque.append("wrapper sudo")
                if inner:
                    sub_report = analyze(_shlex_join(inner), inner_cwd, launch_cwd, home)
                    for t in sub_report.targets:
                        add(t)
                    rep.opaque.extend(sub_report.opaque)
                    rep.egress.extend(sub_report.egress)
                    rep.credential_reads.extend(sub_report.credential_reads)
                    rep.symlinks.extend(sub_report.symlinks)
                    if sub_report.status == "unparseable":
                        # The gap must not vanish inside the wrapper: the
                        # rules apply the literal fallback when `parse_error`
                        # is set (review finding, October 15).
                        rep.parse_error = rep.parse_error or sub_report.parse_error
                        rep.opaque.append(f"wrapper {verb}: inner command unparseable")
            return

    for tree in trees:
        visit(tree)

    if rep.targets or rep.config_writes or rep.egress or rep.credential_reads:
        rep.status = "destructive"
    elif rep.opaque:
        rep.status = "opaque"
    return rep
