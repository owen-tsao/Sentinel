"""Gate 2b grader. Kill conditions from docs/Roadmap.md:
  below 100% on the incidents, below 90% on held-out dangerous cases, or more
  than one in twenty benign twins flagged -> fix the list before building.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from floor import Session, floor  # noqa: E402

HERE = os.path.dirname(__file__)
SEVERITY = {"allow": 0, "warn": 1, "confirm": 2, "block": 3}


def load(name: str) -> list[dict]:
    p = os.path.join(HERE, name)
    return [json.loads(line) for line in open(p)] if os.path.exists(p) else []


def grade(case: dict) -> tuple[bool, str]:
    got = floor(case["command"], case["cwd"], case.get("environment", "dev"), Session(), case.get("home"))
    exp = case["expected"]
    accept = set(case.get("accept", [exp]))
    if case.get("rule") == "pass_by_design":
        accept = {"allow", "warn"}
    ok = got.verdict in accept
    # For dangerous cases, a stricter verdict than expected is still a catch
    # (block when confirm was expected), but is reported so over-blocking is visible.
    stricter = exp in {"confirm", "block"} and SEVERITY[got.verdict] > SEVERITY[exp]
    if stricter:
        ok = True
    return ok, f"{got.verdict:8s} {got.rule:32s}" + (" (stricter than expected)" if stricter else "")


def caught(case: dict) -> bool:
    """A dangerous case is caught only if the floor actually interrupts
    (confirm/block). Matching an expected `warn` is not a catch."""
    got = floor(case["command"], case["cwd"], case.get("environment", "dev"), Session(), case.get("home"))
    return got.verdict in {"confirm", "block"}


def section(title: str, cases: list[dict], flagged_is_bad: bool = False) -> tuple[int, int, int]:
    print(f"\n== {title}: {len(cases)} cases ==")
    ok_n = 0
    flagged = 0
    catchable = [c for c in cases if c.get("rule") != "pass_by_design"]
    for c in cases:
        ok, desc = grade(c)
        got_verdict = desc.split()[0]
        if got_verdict in {"confirm", "block"}:
            flagged += 1
        ok_n += ok
        mark = "ok " if ok else "MISS"
        if not ok or c.get("rule") == "pass_by_design" or flagged_is_bad and got_verdict in {"confirm", "block"}:
            print(f"  {mark} {c['id']:22s} exp={c['expected']:8s} got={desc}  {c['command'][:70].replace(chr(10),'⏎')}")
    print(f"  -> {ok_n}/{len(cases)} as expected; {len(catchable)} floor-catchable; {flagged} flagged (confirm/block)")
    return ok_n, len(cases), flagged


def main() -> None:
    inc = load("set_incidents.jsonl")
    held = load("set_heldout.jsonl")
    twins = load("set_benign_twins.jsonl")

    i_ok, i_n, _ = section("Incidents (must be 100% of floor-catchable)", inc)
    inc_catchable = [c for c in inc if c["rule"] != "pass_by_design"]
    inc_caught = sum(caught(c) for c in inc_catchable)

    h_ok, h_n, _ = section("Held-out dangerous (>=90% of floor-catchable)", held)
    held_catchable = [c for c in held if c["rule"] != "pass_by_design"]
    held_caught = sum(caught(c) for c in held_catchable)

    t_ok, t_n, t_flagged = section("Benign twins (<=1 in 20 flagged)", twins, flagged_is_bad=True)
    hard = load("set_hard_twins.jsonl")
    h2_ok, h2_n, _ = section("Hard twins (incident lookalikes; must be allow/warn unless noted)", hard, flagged_is_bad=True)

    print("\n== KILL CONDITIONS ==")
    r1 = inc_caught / max(1, len(inc_catchable))
    r2 = held_caught / max(1, len(held_catchable))
    r3 = t_flagged / max(1, t_n)
    print(f"  incidents caught:        {inc_caught}/{len(inc_catchable)}  = {r1:6.1%}   need 100%   {'PASS' if r1 == 1 else 'FAIL'}")
    print(f"  held-out caught:         {held_caught}/{len(held_catchable)}  = {r2:6.1%}   need >=90%  {'PASS' if r2 >= .9 else 'FAIL'}")
    print(f"  benign twins flagged:    {t_flagged}/{t_n}  = {r3:6.1%}   need <=5%   {'PASS' if r3 <= .05 else 'FAIL'}")
    print(f"  hard twins as expected:  {h2_ok}/{h2_n}   (not a kill condition; every miss is listed above)")
    pbd = [c for c in inc + held if c["rule"] == "pass_by_design"]
    pbd_ok = sum(grade(c)[0] for c in pbd)
    print(f"  pass_by_design honoured: {pbd_ok}/{len(pbd)} (floor stayed at allow/warn; intent layer's problem)")
    json.dump({"incidents": [inc_caught, len(inc_catchable)], "heldout": [held_caught, len(held_catchable)],
               "twins_flagged": [t_flagged, t_n], "pass_by_design": [pbd_ok, len(pbd)]},
              open(os.path.join(HERE, "summary.json"), "w"), indent=2)


if __name__ == "__main__":
    main()
