"""Report the Week 13 preregistered measures from a real run's audit database.

Point it at one or more private run directories created by
`scripts/week12_control_demo.py` (each fresh Cursor chat should be its own
run so denominators are honest):

    python3 scripts/week13_measure.py ~/.sentinel/week12-demo/<stamp> [...]
    python3 scripts/week13_measure.py RUN_DIR --prose-marker "ZEBRA"

Every number is derived from audit events Sentinel wrote itself; nothing here
is self-reported by the agent. Targets come from docs/Week 13 Plan.md and are
printed next to each result so a miss is visible, not hidden.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import statistics
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

PROPOSE_TOOL = "sentinel_task_propose"
HUMAN_EVENTS = {
    "task_proposal_confirmed",
    "task_proposal_dismissed",
    "exact_action_approved",
    "exact_action_denied",
}


BUDGETED_WRITE = "mcp:budgeted_write"
STANDING_READ = "supervision:standing_read"
BUDGET_EXHAUSTED = "supervision:write_budget_exhausted"


@dataclass
class Event:
    event_type: str
    timestamp: datetime
    contract_id: str | None
    verdict: str | None
    details: dict
    reason_codes: list[str]
    raw: str


@dataclass
class Tally:
    runs: int = 0
    proposals_attempted: int = 0
    proposals_accepted: int = 0
    confirm_seconds: list[float] = field(default_factory=list)
    confirmations: int = 0
    adjusted_in_full_form: int = 0
    human_dismissals: int = 0
    completed_loops: int = 0
    human_interactions_in_completed_loops: list[int] = field(default_factory=list)
    prose_hits: int = 0
    unconfirmed_contract_ids: set[str] = field(default_factory=set)
    # Week 14. Read-only proposals are counted apart from write jobs because
    # standing reads remove them entirely after the change, which would
    # otherwise flatter the per-job interaction count.
    read_only_confirmations: int = 0
    budgeted_notes: int = 0
    # Distinct attempts, not decision rows: a replay of an already-applied
    # attempt logs the exhausted reason again without producing a card.
    budget_exhausted_attempts: set[str] = field(default_factory=set)
    standing_reads: int = 0


def load_events(database: Path) -> list[Event]:
    # The audit table lives in a WAL-mode database shared with other state
    # stores, so unread pages may still sit in sentinel.sqlite3-wal. Read in
    # place (do not copy only the main file) after stopping Sentinel.
    try:
        connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
        connection.execute("SELECT 1 FROM audit_events LIMIT 1")
    except sqlite3.OperationalError:
        connection = sqlite3.connect(str(database))
    try:
        rows = connection.execute(
            "SELECT event_type, timestamp, contract_id, verdict, event_json FROM audit_events ORDER BY sequence_id"
        ).fetchall()
    finally:
        connection.close()
    events = []
    for event_type, timestamp, contract_id, verdict, event_json in rows:
        payload = json.loads(event_json)
        events.append(
            Event(
                event_type=event_type,
                timestamp=datetime.fromisoformat(timestamp.replace("Z", "+00:00")),
                contract_id=contract_id,
                verdict=verdict,
                details=payload.get("details") or {},
                reason_codes=list(payload.get("reason_codes") or []),
                raw=event_json,
            )
        )
    return events


def grep_marker(root: Path, marker: str) -> int:
    """Count occurrences of `marker` in Sentinel's own state files.

    Scans `sentinel.sqlite3` plus its `-wal`/`-shm` side files (after Ctrl-C,
    un-checkpointed rows live only in the WAL). Deliberately skips
    `mcp_fixture.sqlite3*`: that is the mock issue tracker, and an approved note
    body is supposed to land there. The claim under test is that Sentinel never
    stores agent prose, so pick a marker the agent puts in its *proposal or
    chat*, not in a note you then approve.
    """

    hits = 0
    needle = marker.encode("utf-8")
    for path in sorted(root.glob("sentinel.sqlite3*")):
        if path.is_file():
            hits += path.read_bytes().count(needle)
    return hits


def tally_run(root: Path, tally: Tally, *, prose_marker: str | None) -> None:
    database = root / "sentinel.sqlite3"
    if not database.exists():
        print(f"skip {root}: no sentinel.sqlite3", file=sys.stderr)
        return
    events = load_events(database)
    tally.runs += 1

    proposed_at: dict[str, datetime] = {}
    confirmed_contracts: set[str] = set()
    proposal_contract_ids: set[str] = set()
    for event in events:
        details = event.details
        if event.event_type == "decision" and details.get("tool") == PROPOSE_TOOL:
            tally.proposals_attempted += 1
        elif event.event_type == "task_proposed":
            tally.proposals_accepted += 1
            proposed_at[details["draft_id"]] = event.timestamp
        elif event.event_type == "task_proposal_confirmed":
            tally.confirmations += 1
            if details.get("operation") == "read":
                tally.read_only_confirmations += 1
            started = proposed_at.get(details["draft_id"])
            if started is not None:
                tally.confirm_seconds.append((event.timestamp - started).total_seconds())
            if event.contract_id:
                confirmed_contracts.add(event.contract_id)
        elif event.event_type == "task_proposal_dismissed":
            if details.get("resolution") == "adjusted_in_full_form":
                tally.adjusted_in_full_form += 1
            else:
                tally.human_dismissals += 1
        if event.event_type.startswith("task_propos") and event.contract_id:
            proposal_contract_ids.add(event.contract_id)
        if event.event_type == "execution_admitted":
            if BUDGETED_WRITE in event.reason_codes:
                tally.budgeted_notes += 1
            if STANDING_READ in event.reason_codes:
                tally.standing_reads += 1
        if event.event_type == "decision" and BUDGET_EXHAUSTED in event.reason_codes:
            tally.budget_exhausted_attempts.add(str(details.get("attempt_id") or event.raw))

    tally.unconfirmed_contract_ids |= proposal_contract_ids - confirmed_contracts

    # A completed loop = one confirmed *write* proposal followed by at least one
    # applied note. Count every human browser interaction in that window: two
    # under per-note approval, one when the note ran inside the task.
    confirmed_indexes = [
        i for i, e in enumerate(events)
        if e.event_type == "task_proposal_confirmed" and e.details.get("operation") != "read"
    ]
    for start in confirmed_indexes:
        window = events[start:]
        applied = next(
            (i for i, e in enumerate(window)
             if e.event_type == "post_execution" and e.details.get("tool") == "sentinel_issue_add_note"
             and e.verdict == "allow"),
            None,
        )
        if applied is None:
            continue
        interactions = sum(1 for e in window[: applied + 1] if e.event_type in HUMAN_EVENTS)
        tally.completed_loops += 1
        tally.human_interactions_in_completed_loops.append(interactions)

    if prose_marker:
        tally.prose_hits += grep_marker(root, prose_marker)


def ratio(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return f"{numerator}/0 (no data)"
    return f"{numerator}/{denominator} = {numerator / denominator:.0%}"


def report(tally: Tally, *, prose_marker: str | None) -> None:
    print(f"Runs inspected: {tally.runs}\n")
    print(f"{'Measure':<44}{'Result':<52}Target")
    print("-" * 118)
    print(f"{'Proposal success':<44}{ratio(tally.proposals_accepted, tally.proposals_attempted):<52}>= 80% over >= 10 fresh chats")
    if tally.confirm_seconds:
        median = statistics.median(tally.confirm_seconds)
        confirm = f"median {median:.1f}s over {len(tally.confirm_seconds)} (min {min(tally.confirm_seconds):.1f}s, max {max(tally.confirm_seconds):.1f}s)"
    else:
        confirm = "no confirmations recorded"
    print(f"{'Time to confirm':<44}{confirm:<52}median < 15 s, human present")
    manual_denominator = tally.confirmations + tally.adjusted_in_full_form
    print(f"{'Manual edits (adjust / all confirmations)':<44}{ratio(tally.adjusted_in_full_form, manual_denominator):<52}< 20%")
    if tally.human_interactions_in_completed_loops:
        counts = sorted(set(tally.human_interactions_in_completed_loops))
        loops = f"{tally.completed_loops} loops; interactions per loop: {counts}"
    else:
        loops = "no completed loop (confirm + applied note)"
    print(f"{'Interactions per write job (task + note)':<44}{loops:<52}2 before Week 14; 1 after")
    print(f"{'Read-only proposals confirmed':<44}{str(tally.read_only_confirmations):<52}report; 0 once standing reads are on")
    print(f"{'Notes run inside the task (no card)':<44}{str(tally.budgeted_notes):<52}report")
    print(f"{'Writes blocked at the runaway limit':<44}{str(len(tally.budget_exhausted_attempts)):<52}expect 0; any means a looping agent")
    print(f"{'Reads with no task (standing)':<44}{str(tally.standing_reads):<52}report")
    print(f"{'Human dismissals':<44}{str(tally.human_dismissals):<52}report; judge unnecessary ones by hand")
    prose = f"{tally.prose_hits} hits for {prose_marker!r}" if prose_marker else "not checked (pass --prose-marker)"
    print(f"{'Raw agent text retained':<44}{prose:<52}0")
    unconfirmed = len(tally.unconfirmed_contract_ids)
    print(f"{'Contracts tied to unconfirmed proposals':<44}{str(unconfirmed):<52}0 (also enforced by tests)")
    print()
    print("Read the denominators before the percentages. Fewer than 10 runs is a smoke check, not a result.")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("runs", nargs="+", type=Path, help="private run directories from week12_control_demo.py")
    parser.add_argument("--prose-marker", help="a unique string the agent was told to include; must never be stored")
    args = parser.parse_args(argv)
    tally = Tally()
    for root in args.runs:
        tally_run(root.expanduser(), tally, prose_marker=args.prose_marker)
    report(tally, prose_marker=args.prose_marker)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
