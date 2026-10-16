"""Boundary inference from the person's prompt: the "hear" verb.

Deterministic and advisory (docs/Week 17 Plan.md §3.2, amended Week 18 in
Direction §3.1). The boundary is the launch directory for the whole session;
nothing in a prompt moves it. What a prompt can add is a *focus*: the folder
inside the boundary that this one prompt points at, attached to the context
line for this prompt only. Anything that points outside produces a *caution*
(a sentence to the agent and a tagged row), not a wider boundary. Nothing
here is an input to the floor, which keeps deciding on `launch_cwd` alone.

Three defences against text the person did not write steering the result:
pasted blocks and fenced code are removed before any token is read; a
negated or example path ("don't touch src/legacy/") disables the focus for
the whole prompt; and the filesystem is consulted only for candidates that
already resolve inside the launch directory.

Disk access (`exists`, `realpath`) is injected so tests never touch the disk.
"""

from __future__ import annotations

import hashlib
import os
import posixpath
import re
from dataclasses import dataclass, field
from typing import Callable, Literal, Optional

from sentinel.floor.extract import CONTENT_READERS, DELETE_VERBS, MOVE_VERBS, expand_home, zone_of

CautionKind = Literal["path", "environment"]
Outcome = Literal["focus", "caution", "none"]

# Untrusted spans are removed with a linear `str.find` scan, not a lazy regex:
# `opener.*?closer` is quadratic when openers have no closer, and a forged
# 200k prompt of unclosed tags would hold the session lock for seconds
# (security review finding 1).
PASTED_OPEN = "<pasted_content"
PASTED_CLOSE = "</pasted_content"
FENCE = "```"
# A segment with no sentence boundary over this length is treated as pasted
# material even when the host did not wrap it (defence in depth).
LONG_SEGMENT_CHARS = 2_000
SENTENCE_BOUNDARY = re.compile(r"[.!?](?:\s|$)")

# Path-shaped tokens only. A bare word is never a path; `and/or` matches and
# is discarded later because no such path exists.
PATH_TOKEN = re.compile(
    r"^(?:[~.]?/)?[\w.@+-]+(?:/[\w.@+-]+)+/?$"   # a/b, ./a/b, ~/a, /a/b
    r"|^[~.]?/[\w.@+-]+/?$"                      # /a, ~/a, ./a
    r"|^[\w.@+-]+/$"                             # a/  (trailing slash marks a directory)
    r"|^~/?$|^\.\.?/$"                            # ~, ~/, ./, ../
)
URL_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
STRIP_PUNCT = ".,;:!?)\"'`"
LEAD_PUNCT = "(\"'`"


MAX_TOKEN_CHARS = 4_096   # longer than any path; longer tokens are not paths and are skipped


def _clean(token: str) -> str:
    # Trim wrapping punctuation but never a path's own leading `./`, `../`, or `~`.
    if len(token) > MAX_TOKEN_CHARS:
        return ""
    token = token.lstrip(LEAD_PUNCT)
    stripped = token.rstrip(STRIP_PUNCT)
    # `rstrip` would also eat the `.` of a trailing `/.`; put it back in that one case.
    if token.endswith("/.") and not stripped.endswith("/."):
        stripped = token[: len(token.rstrip(STRIP_PUNCT.replace(".", "")))]
    return stripped


# A token right after one of these is a git ref, not a path (`checkout feature/x`).
REF_WORDS = {"origin", "branch", "checkout", "switch", "merge", "rebase", "upstream"}
# Any candidate preceded (within six tokens) by one of these disables the
# focus for the whole prompt: a wrong hint is noise, and none costs nothing.
NEGATION_WORDS = {
    "not", "don't", "dont", "never", "except", "avoid", "without", "like", "e.g.", "e.g", "eg", "i.e.", "i.e",
    "unlike", "leave", "skip", "ignore", "exclude", "excluding", "besides",
}
NEGATION_PHRASES = ("do not", "instead of", "such as", "similar to", "rather than", "other than", "apart from",
                    "same as", "based on", "modeled on", "modelled on")
NEGATION_WINDOW = 6
# A prompt that *is* a command carries no focus: the floor judges it when it runs.
COMMAND_VERBS = DELETE_VERBS | MOVE_VERBS | CONTENT_READERS | {
    "git", "npm", "npx", "pnpm", "yarn", "pip", "pip3", "uv", "python", "python3", "make", "cargo", "go", "docker",
    "ls", "cd", "echo", "mkdir", "touch", "chmod", "chown", "sudo", "brew", "apt", "kubectl", "terraform",
}
ENVIRONMENT_WORDS = {"production": "production", "prod": "production", "staging": "staging",
                     "sandbox": "sandbox", "dev": "dev", "development": "dev"}
INSIDE_ZONES = {"inside", "cwd_root"}
CAUTION_ZONES = {"outside", "home", "system"}
MAX_CANDIDATES = 64


@dataclass(frozen=True)
class Inference:
    outcome: Outcome
    focus: Optional[str] = None                # realpath inside the launch directory; this prompt only
    caution: Optional[CautionKind] = None
    caution_target: Optional[str] = None       # realpath; the service stores only its hash and zone
    caution_zone: Optional[str] = None
    pasted_stripped: bool = False
    command_prompt: bool = False
    candidates_inside: int = 0
    candidates_outside: int = 0
    candidates_dropped_by_negation: int = 0
    prompt_sha256: str = ""


@dataclass
class _Scan:
    inside: list[str] = field(default_factory=list)
    cautions: list[tuple[str, str]] = field(default_factory=list)   # (realpath, zone)
    dropped: int = 0


def prompt_hash(prompt: str) -> str:
    """The only form of the prompt that reaches a row: rows never hold prompt text."""
    return hashlib.sha256(prompt.encode("utf-8", "surrogatepass")).hexdigest()


def strip_untrusted(prompt: str) -> tuple[str, bool]:
    """Remove text the person did not type: pasted blocks, fenced code, and
    over-long segments with no sentence boundary."""
    text, n1 = _remove_spans(prompt, PASTED_OPEN, PASTED_CLOSE, close_to_line_end=True, casefold=True)
    text, n2 = _remove_spans(text, FENCE, FENCE)
    kept: list[str] = []
    dropped_long = 0
    for segment in re.split(r"\n\s*\n", text):
        if len(segment) > LONG_SEGMENT_CHARS and not SENTENCE_BOUNDARY.search(segment):
            dropped_long += 1
            continue
        kept.append(segment)
    return "\n\n".join(kept), bool(n1 or n2 or dropped_long)


def _remove_spans(text: str, opener: str, closer: str, *, close_to_line_end: bool = False, casefold: bool = False) -> tuple[str, int]:
    """Drop every `opener … closer` span in one left-to-right pass. An opener
    with no closer drops the rest of the text: an unterminated paste is still
    not the person's words."""
    haystack = text.casefold() if casefold else text
    needle_open = opener.casefold() if casefold else opener
    needle_close = closer.casefold() if casefold else closer
    out: list[str] = []
    pos = 0
    removed = 0
    while True:
        start = haystack.find(needle_open, pos)
        if start < 0:
            out.append(text[pos:])
            break
        out.append(text[pos:start])
        removed += 1
        end = haystack.find(needle_close, start + len(needle_open))
        if end < 0:
            break
        end += len(needle_close)
        if close_to_line_end:
            newline = haystack.find("\n", end)
            end = len(text) if newline < 0 else newline + 1
        out.append(" ")
        pos = end
    return "".join(out), removed


def is_command_prompt(text: str) -> bool:
    """True when the prompt is itself a shell command (`rm -rf build/`, or a
    single backticked span): paths inside it are arguments for the floor to
    judge at run time, not a statement of where the task lives."""
    stripped = text.strip()
    if not stripped:
        return False
    if stripped.startswith("`") and stripped.endswith("`") and stripped.count("`") == 2:
        return True
    first = stripped.split(None, 1)[0].lstrip("$").lower()
    return first in COMMAND_VERBS


def _tokens(text: str) -> list[str]:
    return text.replace("`", " ").split()


def candidates(text: str) -> list[tuple[int, str]]:
    """Path-shaped tokens with their positions, excluding URLs and git refs."""
    out: list[tuple[int, str]] = []
    tokens = _tokens(text)
    for index, raw in enumerate(tokens):
        token = _clean(raw)
        if not token or URL_SCHEME.match(token) or not PATH_TOKEN.match(token):
            continue
        if index > 0 and _clean(tokens[index - 1]).lower() in REF_WORDS:
            continue
        out.append((index, token))
        if len(out) >= MAX_CANDIDATES:
            break
    return out


def negated(tokens: list[str], index: int) -> bool:
    """True when a negation or example marker sits within `NEGATION_WINDOW`
    tokens before `index` ("don't touch src/legacy/", "like src/api/")."""
    raw = [t.lower().replace("\u2019", "'") for t in tokens[max(0, index - NEGATION_WINDOW):index]]
    stripped = [t.strip(STRIP_PUNCT) for t in raw]
    # Both forms: `e.g.` loses its final dot when stripped, `don't,` keeps it when raw.
    if any(w in NEGATION_WORDS for w in raw) or any(w in NEGATION_WORDS for w in stripped):
        return True
    joined = " ".join(stripped)
    return any(phrase in joined for phrase in NEGATION_PHRASES)


def _resolve(token: str, base: str, home: str) -> str:
    expanded = expand_home(token, home)
    joined = expanded if expanded.startswith("/") else posixpath.join(base, expanded)
    return posixpath.normpath(joined)


def _common_ancestor(paths: list[str]) -> str:
    parts = [p.rstrip("/").split("/") for p in paths]
    prefix = parts[0]
    for other in parts[1:]:
        n = 0
        while n < len(prefix) and n < len(other) and prefix[n] == other[n]:
            n += 1
        prefix = prefix[:n]
    return "/".join(prefix) or "/"


def infer(
    prompt: str,
    *,
    launch_cwd: str,
    event_cwd: Optional[str],
    home: str,
    environment: str,
    exists: Callable[[str], bool] = os.path.exists,
    isdir: Callable[[str], bool] = os.path.isdir,
    realpath: Callable[[str], str] = os.path.realpath,
) -> Inference:
    """One prompt in, one of `focus` / `caution` / `none` out. The boundary
    itself is never touched."""
    digest = prompt_hash(prompt)
    text, stripped = strip_untrusted(prompt)
    if is_command_prompt(text):
        return Inference(outcome="none", pasted_stripped=stripped, command_prompt=True, prompt_sha256=digest)

    launch = posixpath.normpath(launch_cwd)
    base = launch
    if event_cwd and event_cwd.startswith("/"):
        normalized = posixpath.normpath(event_cwd)
        if normalized == launch or normalized.startswith(launch + "/"):
            base = normalized

    tokens = _tokens(text)
    scan = _Scan()
    for index, token in candidates(text):
        if negated(tokens, index):
            scan.dropped += 1
            continue
        lexical = _resolve(token, base, home)
        lexical_zone = zone_of(lexical, launch, home)
        if lexical_zone in INSIDE_ZONES:
            # Only paths already inside are allowed to touch the disk.
            if not exists(lexical):
                continue
            real = posixpath.normpath(realpath(lexical))
            real_zone = zone_of(real, launch, home)
            if real_zone in INSIDE_ZONES:
                scan.inside.append(real if isdir(real) else posixpath.dirname(real))
            elif real_zone in CAUTION_ZONES:
                scan.cautions.append((real, real_zone))
            continue
        if lexical_zone in CAUTION_ZONES:
            # `/s`, `/q`: single-component root paths that are not a known
            # system or home root are command flags in pasted text (`rd /s /q`),
            # not places. Live false caution, row 2419, October 14.
            if lexical_zone == "outside" and lexical.count("/") == 1:
                continue
            scan.cautions.append((lexical, lexical_zone))
        # credential / protected_config / root / temp: the floor's business or nobody's.

    env_caution = _environment_caution(tokens, environment)
    common = dict(pasted_stripped=stripped, candidates_inside=len(scan.inside), candidates_outside=len(scan.cautions),
                  candidates_dropped_by_negation=scan.dropped, prompt_sha256=digest)

    if scan.cautions:
        target, zone = scan.cautions[0]
        return Inference(outcome="caution", caution="path", caution_target=target, caution_zone=zone, **common)
    if env_caution:
        return Inference(outcome="caution", caution="environment", caution_target=env_caution, **common)
    if scan.dropped or not scan.inside:
        return Inference(outcome="none", **common)

    ancestor = _common_ancestor(scan.inside)
    if ancestor != launch and ancestor.startswith(launch + "/"):
        return Inference(outcome="focus", focus=ancestor, **common)
    return Inference(outcome="none", **common)


def _environment_caution(tokens: list[str], environment: str) -> Optional[str]:
    for raw in tokens:
        word = raw.strip(STRIP_PUNCT).lower()
        named = ENVIRONMENT_WORDS.get(word)
        if named and named != environment:
            return named
    return None


__all__ = ["Inference", "candidates", "infer", "is_command_prompt", "negated", "prompt_hash", "strip_untrusted"]
