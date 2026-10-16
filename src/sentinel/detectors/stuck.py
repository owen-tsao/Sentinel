"""Deterministic stuck detection: the same action, again, to the same end.

Thresholds follow OpenHands' `StuckDetector` and were checked against this
machine's own sessions before any message was allowed (spikes/week17/
S2_RESULTS.md: 3.7% of 164 sessions trip under a pessimistic upper bound).

The detector is advisory. It is consulted only after the floor returned
`allow` or `warn`, it can produce only `warn`, and the service runs it inside
a try that swallows everything, so a bug here can never become a deny
(docs/Week 17 Plan.md §2, §3.5).

Action identity is the tool name plus a hash of the canonical input with
volatile fields removed; a retry with a changed argument is a different
action. Result identity is a hash of the response with durations removed.
Only hashes are kept: no command text, no output.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Literal, Optional

REPEAT_THRESHOLD = 4        # 4th identical attempt after 3 identical results
ERROR_THRESHOLD = 3         # 3rd attempt after 2 failures
ALTERNATION_LENGTH = 6      # A B A B A B
RING_SIZE = 12
IN_FLIGHT_TTL_SECONDS = 600.0
MAX_IN_FLIGHT = 256

# Fields that change between otherwise identical calls and must not split an identity.
VOLATILE_INPUT_FIELDS = {"description", "timeout", "run_in_background", "dangerouslyDisableSandbox"}
VOLATILE_RESPONSE_FIELDS = {"duration_ms", "durationMs", "elapsed_ms", "timestamp", "startTime", "endTime"}
BASH_RESULT_FIELDS = ("stdout", "stderr", "interrupted")

RuleId = Literal["S1.repeat_same_result", "S2.repeat_error", "S3.alternation"]


@dataclass(frozen=True)
class Completed:
    """One action that ran: when it was proposed, when it finished, what came of it."""

    identity: str
    result: str                 # fingerprint, or "error:<first line>"
    failed: bool
    pre_seq: int                # server sequence of the PreToolUse row
    post_seq: int               # server sequence of the PostToolUse(Failure) row


@dataclass(frozen=True)
class InFlight:
    identity: str
    pre_seq: int
    started_at: float


@dataclass(frozen=True)
class Signal:
    rule_id: RuleId
    streak: int                 # attempts of the looping identity including the proposed one
    identity: str

    @property
    def nudge(self) -> str:
        if self.rule_id == "S1.repeat_same_result":
            return (f"Sentinel: this is attempt {self.streak} of the same command with the same result. "
                    "Try a different approach or ask the user.")
        if self.rule_id == "S2.repeat_error":
            return (f"Sentinel: this is attempt {self.streak} of the same command after it failed each time. "
                    "Read the error, change something, or ask the user.")
        return ("Sentinel: the last six actions alternate between two commands with unchanged results. "
                "Step back and try a different approach or ask the user.")


@dataclass
class StuckState:
    """Per-session detector state. Cleared on boundary supersession."""

    ring: deque[Completed] = field(default_factory=lambda: deque(maxlen=RING_SIZE))
    in_flight: dict[str, InFlight] = field(default_factory=dict)
    nudged: set[tuple[str, str]] = field(default_factory=set)        # (rule_id, identity) already nudged once
    messaged_identities: set[str] = field(default_factory=set)

    def start(self, tool_use_id: str, identity: str, pre_seq: int, now: float) -> None:
        self.expire(now)
        if len(self.in_flight) >= MAX_IN_FLIGHT:
            oldest = min(self.in_flight, key=lambda k: self.in_flight[k].started_at)
            del self.in_flight[oldest]
        self.in_flight[tool_use_id] = InFlight(identity=identity, pre_seq=pre_seq, started_at=now)

    def complete(self, tool_use_id: str, *, result: str, failed: bool, post_seq: int) -> bool:
        """Move an in-flight action into the ring. False when nothing was in flight
        for that id (orphan or expired), in which case nothing is recorded."""
        entry = self.in_flight.pop(tool_use_id, None)
        if entry is None:
            return False
        self.ring.append(Completed(identity=entry.identity, result=result, failed=failed,
                                   pre_seq=entry.pre_seq, post_seq=post_seq))
        return True

    def expire(self, now: float) -> None:
        stale = [k for k, v in self.in_flight.items() if now - v.started_at > IN_FLIGHT_TTL_SECONDS]
        for key in stale:
            del self.in_flight[key]

    def reset(self) -> None:
        self.ring.clear()
        self.in_flight.clear()
        self.nudged.clear()
        self.messaged_identities.clear()


# ----------------------------------------------------------------- hashing

def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def identity(tool_name: Optional[str], tool_input: Any) -> str:
    """Tool name plus a hash of the input, whatever its type. A string or null
    input is hashed as itself; S2 showed that coercing it to `{}` makes every
    such call look identical."""
    if isinstance(tool_input, dict):
        clean: dict[str, Any] = {k: v for k, v in tool_input.items() if k not in VOLATILE_INPUT_FIELDS}
        for key in ("command",):
            if isinstance(clean.get(key), str):
                clean[key] = clean[key].strip()
        payload = _canonical(clean)
    else:
        payload = _canonical({"_raw": tool_input})
    return f"{tool_name or '?'}:{_sha(payload)[:32]}"


def fingerprint(tool_name: Optional[str], tool_response: Any) -> str:
    """Hash of what the tool returned, with durations removed. For Bash the
    documented fields are used when present so an extra host field cannot
    split two identical runs."""
    if isinstance(tool_response, dict):
        if tool_name in {"Bash", "PowerShell"} and any(k in tool_response for k in BASH_RESULT_FIELDS):
            payload = _canonical({k: tool_response.get(k) for k in BASH_RESULT_FIELDS})
        else:
            payload = _canonical({k: v for k, v in tool_response.items() if k not in VOLATILE_RESPONSE_FIELDS})
    else:
        payload = _canonical({"_raw": tool_response})
    return _sha(payload)[:32]


def error_fingerprint(error: Optional[str]) -> str:
    first = (error or "").strip().splitlines()[0] if (error or "").strip() else ""
    return "error:" + _sha(first)[:24]


# ----------------------------------------------------------------- evaluation

def _sequential(entries: list[Completed]) -> bool:
    """True when each entry was proposed after the previous one finished: a
    chain of retries rather than a parallel burst."""
    for previous, current in zip(entries, entries[1:]):
        if current.pre_seq <= previous.post_seq:
            return False
    return True


def evaluate(state: StuckState, proposed_identity: str, proposed_pre_seq: int) -> Optional[Signal]:
    """The proposed action against the ring. None means no signal."""
    ring = list(state.ring)

    last_repeat = ring[-(REPEAT_THRESHOLD - 1):]
    if (len(last_repeat) == REPEAT_THRESHOLD - 1
            and all(e.identity == proposed_identity for e in last_repeat)
            and len({e.result for e in last_repeat}) == 1
            and not any(e.failed for e in last_repeat)
            and _sequential(last_repeat)):
        streak = _streak(ring, proposed_identity) + 1
        return Signal("S1.repeat_same_result", streak, proposed_identity)

    last_error = ring[-(ERROR_THRESHOLD - 1):]
    if (len(last_error) == ERROR_THRESHOLD - 1
            and all(e.identity == proposed_identity and e.failed for e in last_error)
            and _sequential(last_error)):
        streak = _streak(ring, proposed_identity) + 1
        return Signal("S2.repeat_error", streak, proposed_identity)

    window = ring[-(ALTERNATION_LENGTH - 1):]
    if len(window) == ALTERNATION_LENGTH - 1 and _sequential(window):
        ids = [e.identity for e in window] + [proposed_identity]
        a, b = ids[0], ids[1]
        if a != b and all(ids[i] == (a if i % 2 == 0 else b) for i in range(ALTERNATION_LENGTH)):
            a_results = {e.result for e in window if e.identity == a}
            b_results = {e.result for e in window if e.identity == b}
            if len(a_results) == 1 and len(b_results) == 1:
                # The loop's identity is the pair, so the second firing (which
                # proposes the other member) is recognised as the same loop.
                return Signal("S3.alternation", ALTERNATION_LENGTH, "|".join(sorted((a, b))))
    return None


def _streak(ring: list[Completed], identity_: str) -> int:
    n = 0
    for entry in reversed(ring):
        if entry.identity != identity_:
            break
        n += 1
    return n


__all__ = [
    "ALTERNATION_LENGTH", "ERROR_THRESHOLD", "REPEAT_THRESHOLD", "Completed", "InFlight", "Signal", "StuckState",
    "error_fingerprint", "evaluate", "fingerprint", "identity",
]
