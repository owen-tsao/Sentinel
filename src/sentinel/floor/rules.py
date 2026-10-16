"""The deterministic floor for shell commands.

Input: the raw command, the shell's current directory, the launch directory,
the launch environment, and server-owned session history. Output: one verdict
in {allow, warn, confirm_required, block}, the rule that fired, a reason the
agent can act on, and the targets involved. No prompt, no inferred boundary,
no model: only facts.

Decision order is fixed: block -> confirm -> warn -> allow. The first rule
that fires wins, except that among blocked targets the most severe zone wins
so `rm -rf ../x ~/.ssh` is a block about `~/.ssh`, not a confirm about `../x`.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from sentinel.floor import windows
from sentinel.floor.extract import Report, analyze, guess_home, home_carve_out

BLOCK_ZONES = {"home", "root", "system", "protected_config", "credential"}
ZONE_SEVERITY = ["protected_config", "credential", "root", "home", "system"]
ZONE_LABEL = {
    "home": "the home directory", "root": "the filesystem root", "system": "a system path",
    "protected_config": "a hook or Sentinel configuration file", "credential": "a credential store",
}
PROTECTED_BRANCHES = {"main", "master", "production", "prod", "release"}
PROD_ENVIRONMENTS = {"production", "prod", "staging"}

# Rules that can never be set to log-only by configuration (docs/Week 16 Plan.md §4C).
PROTECTED_RULES = frozenset({"F1", "F2", "F3", "F4"})
ALL_RULES = (
    "F1.destructive_root", "F1.destructive_home", "F1.delete_home", "F1.delete_root", "F1.delete_system",
    "F1.delete_protected_config", "F1.delete_credential", "F1.write_home", "F1.write_root",
    "F1.write_system", "F1.write_protected_config", "F1.write_credential", "F1.literal_fallback",
    "F1.write_unresolved", "F1.delete_unresolved",
    "F2.defense_evasion", "F2.supervisor_disable", "F2.session_escape",
    "F3.credential_read", "F4.exfiltration", "F4.web_egress_after_credential_read",
    "F5.destructive_cwd_root", "F5.destructive_outside", "F5.windows_nested_quote_delete", "F5.symlink_escape",
    "F5.write_outside", "F5.mcp_path_outside", "F5.mcp_source_unaccepted", "F5.opaque_write",
    "F6.file_egress", "F6.remote_script", "F7.force_push_protected",
    "F8.infra_destroy", "F8.expose_network", "F8.schema_change_prod",
    "W1.git_history_inside", "W2.unresolvable_delete", "W2.unresolvable_write", "W3.local_infra_destroy", "W4.opaque", "W5.unparseable",
)

INFRA_DESTROY = [
    (re.compile(r"\bterraform\s+(destroy|apply\s+.*-auto-approve)"), "terraform destroy/auto-approve"),
    (re.compile(r"\baws\s+s3\s+(rm|rb)\b.*(--recursive|--force)"), "aws s3 recursive delete"),
    (re.compile(r"\baws\s+(rds|ec2|dynamodb|cloudformation)\s+(delete|terminate)"), "aws resource delete"),
    (re.compile(r"\bkubectl\s+delete\s+(namespace|ns|deployment|statefulset|pvc|pv)\b"), "kubectl delete"),
    (re.compile(r"\bgcloud\s+.{0,400}\bdelete\b"), "gcloud delete"),
    (re.compile(r"\b(dropdb|DROP\s+(DATABASE|SCHEMA|TABLE))\b", re.I), "database drop"),
    (re.compile(r"\b(DELETE\s+FROM|TRUNCATE)\b(?![^;]*\bWHERE\b)", re.I), "unfiltered delete/truncate"),
    (re.compile(r"\b(prisma\s+migrate\s+reset|drizzle-kit\s+(push|drop)|supabase\s+db\s+reset)\b"), "schema reset"),
    (re.compile(r"\b(gh\s+repo\s+delete|heroku\s+apps:destroy|fly\s+apps\s+destroy|vercel\s+(rm|remove)\s+.*--yes)\b"), "platform resource delete"),
    (re.compile(r"\bdocker\s+(system\s+prune.*--volumes|volume\s+(rm|prune))"), "docker volume removal"),
]
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
    (re.compile(r"\bchmod\s+(-R\s+)?[0-7]*7[0-7]*7\s+/\s*$|\bchmod\s+-R\s+777\s+/(?=\s|$|;|&|\|)"), "world-writable root"),
]
# Stopping or replacing the supervisor. `kill %1`, `pkill node`, and
# `launchctl list` stay allow: only a Sentinel-naming argument fires.
# Spans are bounded (`{0,400}`) so a 32 KB command with thousands of keyword
# hits stays linear; an unbounded `[^;&|\n]*` re-scanned to the segment end
# from every hit and took seconds (review finding, October 15).
SUPERVISOR_DISABLE = [
    (re.compile(r"\b(pkill|killall)\b[^;&|\n]{0,400}\bsentinel\b", re.I), "kill the Sentinel process"),
    (re.compile(r"\bkill\b[^;&|\n]{0,400}\$\(\s*(pgrep|lsof|pidof)\b[^)]{0,400}\bsentinel\b", re.I), "kill the Sentinel process"),
    (re.compile(r"\blaunchctl\s+(unload|bootout|remove|disable|stop|kill)\b[^;&|\n]{0,400}sentinel", re.I), "unload the Sentinel launch agent"),
    (re.compile(r"\bsystemctl\s+(--user\s+)?(stop|disable|mask|kill)\b[^;&|\n]{0,400}sentinel", re.I), "stop the Sentinel service"),
]
SUPERVISOR_PORT_KILL = re.compile(r"\bkill\b[^;&|\n]{0,400}\$\(\s*lsof\s+[^)]{0,400}-i\s*:?(\d{2,5})", re.I)
# A fresh Claude Code session started from inside this one chooses its own
# project dir, settings, and permission mode. `claude` must begin a command
# segment (start, newline, `;`, `&`, `|`, `(`) or follow a wrapper, possibly
# with a path prefix; `echo claude -p` and `git commit -m "claude -p"` do not.
SESSION_ESCAPE = re.compile(
    r"(?:^|[;&|(\n]|\s-c\s+['\"]|\b(?:exec|nohup|sudo|doas|env|time|timeout|xargs|npx|command|watch)\b[^;&|\n]{0,400}?)"
    r"\s*(?:[\w.~/-]*/)?claude\b[^;&|\n]{0,400}"
    r"(?:\s-p\b|\s--print\b|\s--bare\b|\s--settings\b|\s--add-dir\b|\s--dangerously-skip-permissions\b|\s--permission-mode\b)"
)
BIND_ALL = re.compile(r"--bind\s+0\.0\.0\.0|--host\s+0\.0\.0\.0|-b\s+0\.0\.0\.0")
PIPE_TO_SHELL = re.compile(r"\|\s*(sudo\s+)?(ba|z|da)?sh\b")
# Used only when bashlex cannot parse: rm with a recursive flag whose target is
# `/`, `/*`, `~`, `~/`, `$HOME`, `${HOME}`, or a dot-directory directly under
# home (`~/.ssh`), as a whole word. The flag run is a single alternative
# (`-word` or `--recursive`) and the recursive letter is checked afterwards:
# two overlapping alternatives made the old pattern exponential in the number
# of flags (24 flags took 3.5 s; review finding, October 15).
DEADLY_LITERAL = re.compile(
    r"\brm\s+((?:-(?:-recursive|[a-zA-Z]+)\s+)+)(?:--\s+)?"
    r"(?:\"?(?:/|/\*|~|~/|~/\*|\$HOME|\$\{HOME\}|\$HOME/\*?|(?:~|\$HOME|\$\{HOME\})/\.[A-Za-z][\w.-]*/?)\"?)(?=\s|$|;|&|\|)"
)
DEADLY_RECURSIVE_FLAG = re.compile(r"--recursive\b|(?<!-)-[a-zA-Z]*[rR]")
FORCE_PUSH = re.compile(
    r"\bgit\s+push\b(?=.{0,400}(?:--force\b|\s-[a-zA-Z]*f[a-zA-Z]*\b|--force-with-lease))(?:.{0,400}\b(" + "|".join(PROTECTED_BRANCHES) + r")\b)?"
)
LOCAL_INFRA = re.compile(r"localhost|127\.0\.0\.1|sqlite|\.db\b|test|dev\b|local", re.I)
NO_PRESERVE_ROOT = re.compile(r"\brm\s+(-[a-zA-Z]*\s+)*--no-preserve-root")


@dataclass
class Finding:
    """The floor's answer for one action: a verdict, the rule that fired, and why.

    `rule` and `reason` are empty for `allow`. `report` carries the extractor's
    full output when the shell path ran; `windows` and `literal` mark verdicts
    reached without the parser (recognizer before it, literal fallback after).
    """

    verdict: str  # allow | warn | confirm_required | block
    rule: str
    reason: str
    targets: list[str] = field(default_factory=list)
    report: Report | None = None
    windows: bool = False
    literal: bool = False

    @property
    def interrupts(self) -> bool:
        """True when this verdict stops the action and spends the person's attention."""
        return self.verdict in {"confirm_required", "block"}


@dataclass
class History:
    """Server-owned facts from earlier in this session.

    Only the server writes these; a forged fact can only make later verdicts
    stricter, never looser.

    The credential taint is set only when a credential read *executed* (the
    host reported the tool ran), never when the floor denied it: a denied read
    leaks nothing. It expires after `CREDENTIAL_TAINT_SECONDS` (Week 18
    amendment: one denied gate test muted web access for seven hours).
    """

    credential_read_at: float | None = None

    def tainted(self, now: float | None = None) -> bool:
        """True while a credential read is recent enough to arm F4."""
        if self.credential_read_at is None:
            return False
        now = time.time() if now is None else now
        return now - self.credential_read_at < CREDENTIAL_TAINT_SECONDS

    def facts(self, now: float | None = None) -> list[str]:
        """The history facts to stamp on a record, for the audit trail."""
        return ["session:credential_store_read"] if self.tainted(now) else []


CREDENTIAL_TAINT_SECONDS = 30 * 60


def _windows_pass(cmd: str, cwd: str) -> Finding | None:
    """Judge a Windows recursive delete before bashlex sees the text, or None if there is none."""
    win = windows.resolved_windows_target(cmd)
    if win is None:
        return None
    if windows.WIN_DRIVE_ROOT.match(win) or win in {"\\", "/"}:
        return Finding("block", "F1.destructive_root", f"Recursive delete resolves to a drive root ({win!r}). The path collapsed to empty; this is the shape of every 2026 drive wipe.", [win], windows=True)
    if windows.WIN_PROFILE.match(win):
        return Finding("block", "F1.destructive_home", f"Recursive delete of the user profile ({win}).", [win], windows=True)
    if windows.WIN_UNRESOLVED_VAR.match(win) and not windows.variable_assigned(cmd, win):
        return Finding("block", "F1.destructive_root", f"Recursive delete target is a variable this command never sets ({win}). Evaluated as empty it resolves to the drive root; this is the shape of the 2026 profile wipe (claude-code#86872).", [win], windows=True)
    if windows.NESTED_CMD.search(cmd) and '\\"' in cmd:
        return Finding("confirm_required", "F5.windows_nested_quote_delete", f"Recursive delete routed through cmd /c with escaped inner quotes; the effective path cannot be verified from the text (written as {win}). Run the delete directly, without nested quoting.", [win], windows=True)
    if re.match(r"(?i)^[a-z]:\\", win) and not windows.under_cwd(win, cwd):
        return Finding("confirm_required", "F5.destructive_outside", f"Recursive delete outside the working directory ({win}).", [win], windows=True)
    return Finding("allow", "", "", [win], windows=True)


def decide_shell(
    command: str,
    *,
    cwd: str,
    launch_cwd: str | None = None,
    home: str | None = None,
    environment: str = "dev",
    history: History | None = None,
    sentinel_port: int | None = None,
    now: float | None = None,
) -> Finding:
    """Judge one shell command: block -> confirm -> warn -> allow, first rule wins.

    `cwd` is where the shell is for this call; `launch_cwd` (default: `cwd`)
    is the boundary zones are judged against. `history` is read, not written:
    the taint that arms F4 is set by the service when a credential read is
    reported as executed, not when the floor denies one. `now` exists so tests
    can pin the taint clock.
    """
    history = history if history is not None else History()
    launch_cwd = launch_cwd or cwd
    home = home or guess_home(launch_cwd)
    cmd = command.strip()

    win = _windows_pass(cmd, launch_cwd)
    if win is not None and win.verdict != "allow":
        return win
    # A Windows recogniser `allow` is not a verdict on the whole text: `echo
    # del x; rm -rf ~` must still reach the parser (review finding, October 15).

    rep = analyze(cmd, cwd, launch_cwd, home)

    # ---- BLOCK -----------------------------------------------------------
    blocked = [t for t in rep.targets if t.zone in BLOCK_ZONES]
    if blocked:
        t = sorted(blocked, key=lambda t: ZONE_SEVERITY.index(t.zone))[0]
        verb = "Destructive operation" if t.kind == "delete" else "Write"
        extra = f" {t.note}" if t.note else ""
        return Finding("block", f"F1.{t.kind}_{t.zone}", f"{verb} targets {ZONE_LABEL[t.zone]} ({t.resolved}).{extra} Stay inside {launch_cwd} or ask the user.", [t.resolved or t.raw], rep)
    if rep.credential_reads:
        return Finding("block", "F3.credential_read", f"Reads a credential store ({rep.credential_reads[0]}). Sentinel does not allow agents to read key material; ask the user to provide what is needed.", rep.credential_reads, rep)
    for t in rep.targets:
        if t.kind in {"write", "delete"} and t.resolved and t.zone == "outside":
            carve = home_carve_out(t.resolved, home)
            if carve is not None:
                verb = "Destructive operation" if t.kind == "delete" else "Write"
                return Finding("block", f"F1.{t.kind}_home", f"{verb} targets {t.resolved}, under the home directory in a place that runs code at login or holds tool configuration ({carve}). Ask the user.", [t.resolved], rep)
    if rep.egress and history.tainted(now):
        return Finding("block", "F4.exfiltration", "Sends a local file off the machine after a credential store was read earlier in this session.", rep.egress, rep)
    for rx, label in DEFENSE_EVASION:
        if rx.search(cmd):
            return Finding("block", "F2.defense_evasion", f"{label}: disabling or erasing a security control or its evidence is not allowed.", [], rep)
    for rx, label in SUPERVISOR_DISABLE:
        if rx.search(cmd):
            return Finding("block", "F2.supervisor_disable", f"{label}: Sentinel is the supervisor for this session and may not be stopped by the agent. Ask the user.", [], rep)
    port_kill = SUPERVISOR_PORT_KILL.search(cmd)
    if port_kill and sentinel_port is not None and int(port_kill.group(1)) == sentinel_port:
        return Finding("block", "F2.supervisor_disable", f"Kills whatever listens on port {sentinel_port}, which is Sentinel. Ask the user.", [], rep)
    if NO_PRESERVE_ROOT.search(cmd):
        return Finding("block", "F1.destructive_root", "rm --no-preserve-root.", ["/"], rep)

    # ---- CONFIRM ---------------------------------------------------------
    for t in rep.targets:
        if t.kind == "delete" and "through symlink" in t.note and t.zone not in BLOCK_ZONES:
            return Finding("confirm_required", "F5.symlink_escape", f"Deletes through a symlink created in this same command; the real target is {t.resolved}, outside the working directory.", [t.resolved or t.raw], rep)
    for t in rep.targets:
        if t.kind == "delete" and t.zone == "cwd_root":
            return Finding("confirm_required", "F5.destructive_cwd_root", f"Deletes the working directory itself ({t.resolved}). The agent was launched here.", [t.resolved or t.raw], rep)
    for t in rep.targets:
        if t.kind == "delete" and t.zone in {"outside", "host_artifact"}:
            where = "inside the host's artefact store" if t.zone == "host_artifact" else "outside the working directory"
            return Finding("confirm_required", "F5.destructive_outside", f"Destructive operation {where} ({t.resolved}). The working directory is {launch_cwd}.", [t.resolved or t.raw], rep)
    for t in rep.targets:
        # Same answer the Write tool gives for the same path (§3.4): a shell
        # redirect to ~/notes.txt is not a different act. Delivering a file
        # *into* an outside directory (`cp report.pdf ~/`) stays allow: the
        # held-out set labels that as ordinary work.
        if t.kind == "write" and t.zone == "outside" and not t.container:
            return Finding("confirm_required", "F5.write_outside", f"Write to {t.resolved}, outside the working directory ({launch_cwd}).", [t.resolved or t.raw], rep)
    if SESSION_ESCAPE.search(cmd):
        return Finding("confirm_required", "F2.session_escape", "Starts a new Claude Code session with its own project directory, settings, or permission mode. The nested session would choose its own boundary; ask the user before starting it.", [], rep)
    if rep.egress:
        return Finding("confirm_required", "F6.file_egress", f"Uploads a local file to a remote host ({rep.egress[0]}).", rep.egress, rep)
    m = FORCE_PUSH.search(cmd)
    if m and m.group(1):
        return Finding("confirm_required", "F7.force_push_protected", f"Force-push to a protected branch ({m.group(1)}).", [m.group(1)], rep)
    for rx, label in INFRA_DESTROY:
        if rx.search(cmd):
            local = LOCAL_INFRA.search(cmd) and environment not in PROD_ENVIRONMENTS
            if local and "docker" not in label:
                break  # local dev database/infra: authorized destructive, falls to warn
            if environment in PROD_ENVIRONMENTS or not local:
                return Finding("confirm_required", "F8.infra_destroy", f"{label} in {environment}. Irreversible against shared infrastructure.", [], rep)
    if BIND_ALL.search(cmd):
        return Finding("confirm_required", "F8.expose_network", "Binds a server to all interfaces (0.0.0.0), exposing it beyond this machine.", [], rep)
    if environment in PROD_ENVIRONMENTS:
        for rx, label in SCHEMA_CHANGE:
            if rx.search(cmd):
                return Finding("confirm_required", "F8.schema_change_prod", f"{label} in {environment}. Schema changes against a shared database are irreversible without a backup.", [], rep)
    if PIPE_TO_SHELL.search(cmd) and re.search(r"\b(curl|wget)\b", cmd):
        return Finding("confirm_required", "F6.remote_script", "Pipes a downloaded script into a shell.", [], rep)

    # ---- WARN (tag only, no interruption) --------------------------------
    for t in rep.targets:
        if t.verb.startswith("git ") and t.zone == "inside":
            return Finding("warn", "W1.git_history_inside", f"{t.verb} inside the repository; destructive but authorized.", [t.resolved or t.raw], rep)
        if t.kind == "delete" and t.zone == "dynamic":
            return Finding("warn", "W2.unresolvable_delete", f"Delete target could not be resolved ({t.raw}); {t.note or 'dynamic'}.", [t.raw], rep)
        if t.kind == "write" and t.zone == "dynamic":
            return Finding("warn", "W2.unresolvable_write", f"Write target could not be resolved ({t.raw}); {t.note or 'dynamic'}.", [t.raw], rep)
    for rx, label in INFRA_DESTROY:
        if rx.search(cmd):
            return Finding("warn", "W3.local_infra_destroy", f"{label} against a local/dev target.", [], rep)
    if rep.status == "opaque":
        if rep.parse_error:
            # A wrapped command bashlex could not parse (`nice time rm -rf ~`):
            # the gap is inside the wrapper, so the literal fallback applies
            # here too (review finding, October 15).
            m = _deadly_literal(cmd)
            if m:
                return Finding("block", "F1.literal_fallback", f"Parser gap inside a wrapper ({rep.parse_error.split(':')[0]}), but the text contains an unambiguous destructive target: {m!r}.", [m], rep, literal=True)
        return Finding("warn", "W4.opaque", f"Opaque: {rep.opaque[0]}. Observed, not judged.", [], rep)
    if rep.status == "unparseable":
        m = _deadly_literal(cmd)
        if m:
            return Finding("block", "F1.literal_fallback", f"Parser gap ({rep.parse_error.split(':')[0]}), but the text contains an unambiguous destructive target: {m!r}.", [m], rep, literal=True)
        return Finding("warn", "W5.unparseable", f"Parser gap: {rep.parse_error}. Observed, not judged.", [], rep)

    return Finding("allow", "", "", [t.resolved or t.raw for t in rep.targets], rep)


def _deadly_literal(cmd: str) -> str | None:
    """The `rm -r <deadly target>` text in `cmd`, if any, for the parser-gap fallback."""
    for m in DEADLY_LITERAL.finditer(cmd):
        if DEADLY_RECURSIVE_FLAG.search(m.group(1)):
            return m.group(0)
    return None
