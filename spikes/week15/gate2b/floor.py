"""The deterministic floor, as graded by Gate 2b.

Input: the raw command, the launch cwd, the launch environment, and
server-owned session history (earlier floor findings in this session).
Output: one verdict in {allow, warn, confirm, block} and a reason the agent
can act on. No prompt, no inferred boundary, no model: only facts.

Decision order is fixed: block → confirm → warn → allow. The first rule that
fires wins.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gate2a"))
from extract import analyze  # noqa: E402

BLOCK_ZONES = {"home", "root", "system", "protected_config", "credential"}
PROTECTED_BRANCHES = {"main", "master", "production", "prod", "release"}
PROD_ENVIRONMENTS = {"production", "prod", "staging"}

# Windows: bashlex cannot see these, and every 2026 drive-root wipe was one of
# them. A tiny explicit recognizer, judged on the resolved path.
WIN_DELETE = re.compile(
    r"(?i)\b(?:rd|rmdir)\s+(?:/s\s+/q|/q\s+/s|/s)\b|"
    r"\bdel\s+(?:/[fsq]\s+)*|"
    r"\bRemove-Item\b(?=.*-Recurse)|"
    r"\brobocopy\b(?=.*/MIR)"
)
WIN_DRIVE_ROOT = re.compile(r"(?i)^(?:[a-z]:\\?|\\)$")
WIN_PROFILE = re.compile(r"(?i)^[a-z]:\\users\\?[^\\]*\\?$|^%userprofile%\\?$|^\$env:userprofile\\?$|^\$home\\?$|^~\\?$")
# A PowerShell/cmd variable in a recursive-delete target that this text never
# assigns. Judged as the shell would when the variable is empty: the incident
# rule, Windows edition (`"$tempRoot\*"` -> `\*` -> drive root).
WIN_UNRESOLVED_VAR = re.compile(r"(?i)^(?:\$(?!env:)[a-z_][a-z0-9_]*|%[a-z_][a-z0-9_]*%)(?:[\\/]\*?)?$")

INFRA_DESTROY = [
    (re.compile(r"\bterraform\s+(destroy|apply\s+.*-auto-approve)"), "terraform destroy/auto-approve"),
    (re.compile(r"\baws\s+s3\s+(rm|rb)\b.*(--recursive|--force)"), "aws s3 recursive delete"),
    (re.compile(r"\baws\s+(rds|ec2|dynamodb|cloudformation)\s+(delete|terminate)"), "aws resource delete"),
    (re.compile(r"\bkubectl\s+delete\s+(namespace|ns|deployment|statefulset|pvc|pv)\b"), "kubectl delete"),
    (re.compile(r"\bgcloud\s+.*\bdelete\b"), "gcloud delete"),
    (re.compile(r"\b(dropdb|DROP\s+(DATABASE|SCHEMA|TABLE))\b", re.I), "database drop"),
    (re.compile(r"\b(DELETE\s+FROM|TRUNCATE)\b(?![^;]*\bWHERE\b)", re.I), "unfiltered delete/truncate"),
    (re.compile(r"\b(prisma\s+migrate\s+reset|drizzle-kit\s+(push|drop)|supabase\s+db\s+reset)\b"), "schema reset"),
    (re.compile(r"\b(gh\s+repo\s+delete|heroku\s+apps:destroy|fly\s+apps\s+destroy|vercel\s+(rm|remove)\s+.*--yes)\b"), "platform resource delete"),
    (re.compile(r"\bdocker\s+(system\s+prune.*--volumes|volume\s+(rm|prune))"), "docker volume removal"),
]
# Schema migrations: routine in dev, irreversible against a shared database.
# Fire only when the launch environment is production/staging (the Replit
# incident was exactly a forced schema push against production).
SCHEMA_CHANGE = [
    (re.compile(r"\balembic\s+(upgrade|downgrade)\b"), "alembic migration"),
    (re.compile(r"\b(prisma\s+(migrate\s+deploy|db\s+push)|drizzle-kit\s+(push|migrate)|db:push|db:migrate|rails\s+db:migrate|flyway\s+migrate|knex\s+migrate|sequelize\s+db:migrate|dbmate\s+up|goose\s+up|atlas\s+schema\s+apply|liquibase\s+update)\b"), "schema migration"),
    (re.compile(r"\bmanage\.py\s+migrate\b"), "django migration"),
]
DEFENSE_EVASION = [
    (re.compile(r"\bhistory\s+-c\b"), "clear shell history"),
    (re.compile(r"\bunset\s+HISTFILE\b|\bHISTSIZE=0\b"), "disable shell history"),
    (re.compile(r"\b(csrutil\s+disable|spctl\s+--master-disable|setenforce\s+0|ufw\s+disable|pfctl\s+-d)\b"), "disable OS security control"),
    (re.compile(r"\bgit\s+config\b.*\bcore\.hooksPath\b"), "redirect git hooks"),
    (re.compile(r"\bcrontab\s+-r\b"), "remove all cron jobs"),
    (re.compile(r"\bchmod\s+(-R\s+)?[0-7]*7[0-7]*7\s+/\s*$|\bchmod\s+-R\s+777\s+/"), "world-writable root"),
]
BIND_ALL = re.compile(r"--bind\s+0\.0\.0\.0|--host\s+0\.0\.0\.0|-b\s+0\.0\.0\.0")
PIPE_TO_SHELL = re.compile(r"\|\s*(sudo\s+)?(ba|z|da)?sh\b")
# Used only when bashlex cannot parse: rm with a recursive flag whose target is
# `/`, `/*`, `~`, `~/`, `$HOME`, or `${HOME}` as a whole word.
DEADLY_LITERAL = re.compile(
    r"\brm\s+(?:-[a-zA-Z]*[rR][a-zA-Z]*\s+|--recursive\s+|-[a-zA-Z]+\s+)+(?:--\s+)?"
    r"(?:\"?(?:/|/\*|~|~/|~/\*|\$HOME|\$\{HOME\}|\$HOME/\*?)\"?)(?=\s|$|;|&|\|)"
)


def _guess_home(cwd: str) -> str:
    m = re.match(r"^(/Users/[^/]+|/home/[^/]+|/root)(?:/|$)", cwd)
    return m.group(1) if m else os.path.expanduser("~")


@dataclass
class Finding:
    verdict: str
    rule: str
    reason: str
    targets: list[str] = field(default_factory=list)


@dataclass
class Session:
    """Server-owned history: what the floor itself saw earlier this session."""
    credential_read: bool = False
    confirmed: set[str] = field(default_factory=set)  # (target) already confirmed by the person


def _resolved_windows_target(command: str) -> str | None:
    """Pull the path argument out of a Windows recursive delete, after the
    quote-collapse that caused the incidents: `cmd /c "rd /s /q \"X\""`
    becomes `rd /s /q ""` once cmd re-parses, so an inner `\"` pair with
    nothing meaningful left is treated as empty → drive root."""
    m = WIN_DELETE.search(command)
    if not m:
        return None
    rest = command[m.end():].strip()
    # PowerShell: flags may precede the path; `-Path X` / `-LiteralPath X` name it.
    while True:
        pm = re.match(r"(?i)^-(?:literal)?path\s+", rest)
        if pm:
            rest = rest[pm.end():]
            break
        fm = re.match(r"^-[A-Za-z]+(?::\$?\w+)?\s*", rest)
        if fm and not re.match(r"^-[A-Za-z]+[\\/]", rest):
            rest = rest[fm.end():]
            continue
        break
    # Inner escaped-quote form collapses to empty.
    if re.match(r'^\\"\s*\\"', rest) or rest in {'""', "''", ""} or re.match(r'^\\"\\"', rest):
        return "\\"
    tok = re.match(r'^(?:"([^"]*)"|\'([^\']*)\'|(\S+))', rest)
    if not tok:
        return "\\"
    path = next(g for g in tok.groups() if g is not None)
    path = re.sub(r"[\\/]?\*+$", "", path)  # `C:\*` -> `C:` ; judged as the directory
    if re.match(r"(?i)^[a-z]:$", path):
        path += "\\"
    return path or "\\"


def floor(command: str, cwd: str, environment: str = "dev", session: Session | None = None, home: str | None = None) -> Finding:
    """`home` is a hook fact (the session's $HOME). Defaults to a guess from
    the cwd so test fixtures on another machine's paths still resolve."""
    session = session or Session()
    home = home or _guess_home(cwd)
    cmd = command.strip()

    # ---- Windows pre-pass ------------------------------------------------
    win = _resolved_windows_target(cmd)
    if win is not None:
        if WIN_DRIVE_ROOT.match(win) or win in {"\\", "/"}:
            return Finding("block", "F1.destructive_root", f"Recursive delete resolves to a drive root ({win!r}). The path collapsed to empty; this is the shape of every 2026 drive wipe.", [win])
        if WIN_PROFILE.match(win):
            return Finding("block", "F1.destructive_home", f"Recursive delete of the user profile ({win}).", [win])
        if WIN_UNRESOLVED_VAR.match(win) and not re.search(r"(?i)\$" + re.escape(win.strip("$%\\/*")) + r"\s*=", cmd):
            return Finding("block", "F1.destructive_root", f"Recursive delete target is a variable this command never sets ({win}). Evaluated as empty it resolves to the drive root; this is the shape of the 2026 profile wipe (claude-code#86872).", [win])
        if re.search(r'cmd(?:\.exe)?\s+/c\s+"', cmd, re.I) and '\\"' in cmd:
            # The Cursor D:/C: wipes: `cmd /c "rd /s /q \"X\""`. cmd.exe re-parses
            # the inner `\"` and the path the delete receives is not the one in
            # the text. Unknowable from here, so it is confirmed, not allowed.
            return Finding("confirm", "F5.windows_nested_quote_delete", f"Recursive delete routed through cmd /c with escaped inner quotes; the effective path cannot be verified from the text (written as {win}). Run the delete directly, without nested quoting.", [win])
        if re.match(r"(?i)^[a-z]:\\", win) and not win.lower().replace("/", "\\").startswith(cwd.lower().replace("/", "\\")):
            return Finding("confirm", "F5.destructive_outside", f"Recursive delete outside the working directory ({win}).", [win])
        return Finding("allow", "", "", [win])

    rep = analyze(cmd, cwd, home)

    # ---- BLOCK -----------------------------------------------------------
    # Most severe target wins, not the first one seen: `rm -rf ../x ~/.ssh`
    # is a block, not a confirm about ../x.
    blocked = [t for t in rep.targets if t.zone in BLOCK_ZONES]
    if blocked:
        t = sorted(blocked, key=lambda t: ["protected_config", "credential", "root", "home", "system"].index(t.zone))[0]
        where = {"home": "the home directory", "root": "the filesystem root", "system": "a system path",
                 "protected_config": "a hook or Sentinel configuration file", "credential": "a credential store"}[t.zone]
        verb = "Destructive operation" if t.kind == "delete" else "Write"
        extra = f" {t.note}" if t.note else ""
        return Finding("block", f"F1.{t.kind}_{t.zone}", f"{verb} targets {where} ({t.resolved}).{extra} Stay inside {cwd} or ask the user.", [t.resolved or t.raw])
    if rep.credential_reads:
        session.credential_read = True
        return Finding("block", "F3.credential_read", f"Reads a credential store ({rep.credential_reads[0]}). Sentinel does not allow agents to read key material; ask the user to provide what is needed.", rep.credential_reads)
    if rep.egress and session.credential_read:
        return Finding("block", "F4.exfiltration", "Sends a local file off the machine after a credential store was read earlier in this session.", rep.egress)
    for rx, label in DEFENSE_EVASION:
        if rx.search(cmd):
            return Finding("block", "F2.defense_evasion", f"{label}: disabling or erasing a security control or its evidence is not allowed.", [])
    if re.search(r"\brm\s+(-[a-zA-Z]*\s+)*--no-preserve-root", cmd):
        return Finding("block", "F1.destructive_root", "rm --no-preserve-root.", ["/"])

    # ---- CONFIRM ---------------------------------------------------------
    for t in rep.targets:
        if t.kind == "delete" and t.zone == "cwd_root":
            return Finding("confirm", "F5.destructive_cwd_root", f"Deletes the working directory itself ({t.resolved}). The agent was launched here.", [t.resolved])
    for t in rep.targets:
        if t.kind == "delete" and t.zone == "outside":
            if t.resolved in session.confirmed:
                continue
            return Finding("confirm", "F5.destructive_outside", f"Destructive operation outside the working directory ({t.resolved}). The working directory is {cwd}.", [t.resolved])
    if rep.egress:
        return Finding("confirm", "F6.file_egress", f"Uploads a local file to a remote host ({rep.egress[0]}).", rep.egress)
    m = re.search(r"\bgit\s+push\b(?=.*(?:--force|-f\b|--force-with-lease))(?:.*\b(" + "|".join(PROTECTED_BRANCHES) + r")\b)?", cmd)
    if m and m.group(1):
        return Finding("confirm", "F7.force_push_protected", f"Force-push to a protected branch ({m.group(1)}).", [m.group(1)])
    for rx, label in INFRA_DESTROY:
        if rx.search(cmd):
            local = re.search(r"localhost|127\.0\.0\.1|sqlite|\.db\b|test|dev\b|local", cmd, re.I) and environment not in PROD_ENVIRONMENTS
            if local and "docker" not in label:
                break  # local dev database/infra: authorized destructive, falls to warn
            if environment in PROD_ENVIRONMENTS or not local:
                return Finding("confirm", "F8.infra_destroy", f"{label} in {environment}. Irreversible against shared infrastructure.", [])
    if BIND_ALL.search(cmd):
        return Finding("confirm", "F8.expose_network", "Binds a server to all interfaces (0.0.0.0), exposing it beyond this machine.", [])
    if environment in PROD_ENVIRONMENTS:
        for rx, label in SCHEMA_CHANGE:
            if rx.search(cmd):
                return Finding("confirm", "F8.schema_change_prod", f"{label} in {environment}. Schema changes against a shared database are irreversible without a backup.", [])
    if PIPE_TO_SHELL.search(cmd) and re.search(r"\b(curl|wget)\b", cmd):
        return Finding("confirm", "F6.remote_script", "Pipes a downloaded script into a shell.", [])

    # ---- WARN (tag only, no interruption) --------------------------------
    for t in rep.targets:
        if t.verb.startswith("git ") and t.zone == "inside":
            return Finding("warn", "W1.git_history_inside", f"{t.verb} inside the repository; destructive but authorized.", [t.resolved])
        if t.kind == "delete" and t.zone == "dynamic":
            return Finding("warn", "W2.unresolvable_delete", f"Delete target could not be resolved ({t.raw}); {t.note or 'dynamic'}.", [t.raw])
    for rx, label in INFRA_DESTROY:
        if rx.search(cmd):
            return Finding("warn", "W3.local_infra_destroy", f"{label} against a local/dev target.", [])
    if rep.status == "opaque":
        return Finding("warn", "W4.opaque", f"Opaque: {rep.opaque[0]}. Observed, not judged.", [])
    if rep.status == "unparseable":
        # The floor must not fail open on a parser gap when the text is
        # unambiguous. Literal scan for the deadliest shapes only.
        m = DEADLY_LITERAL.search(cmd)
        if m:
            return Finding("block", "F1.literal_fallback", f"Parser gap ({rep.parse_error.split(':')[0]}), but the text contains an unambiguous destructive target: {m.group(0)!r}.", [m.group(0)])
        return Finding("warn", "W5.unparseable", f"Parser gap: {rep.parse_error}. Observed, not judged.", [])

    return Finding("allow", "", "", [t.resolved or t.raw for t in rep.targets])
