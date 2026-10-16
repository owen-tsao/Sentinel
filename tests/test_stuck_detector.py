"""Stuck detector: docs/Week 17 Plan.md §3.5 and §6.

The ring is driven directly; the service's wiring is tested in
test_claude_code_adapter.py. Sequence numbers stand in for audit row order.
"""

from __future__ import annotations

import unittest

from sentinel.detectors.stuck import (
    ALTERNATION_LENGTH,
    ERROR_THRESHOLD,
    REPEAT_THRESHOLD,
    StuckState,
    error_fingerprint,
    evaluate,
    fingerprint,
    identity,
)

A = identity("Bash", {"command": "pytest -x", "description": "run tests"})
B = identity("Read", {"file_path": "/p/test.log"})
SAME = fingerprint("Bash", {"stdout": "1 failed", "stderr": "", "interrupted": False})
OTHER = fingerprint("Bash", {"stdout": "2 failed", "stderr": "", "interrupted": False})
ERR = error_fingerprint("Exit code 1\nError: boom")


class Driver:
    """Sequential actions: each starts after the previous one finished."""

    def __init__(self) -> None:
        self.state = StuckState()
        self.seq = 0
        self.n = 0

    def run(self, ident: str, result: str = SAME, *, failed: bool = False, overlap_with_previous: bool = False):
        self.n += 1
        tid = f"t{self.n}"
        pre = self.seq if overlap_with_previous else self.seq + 1
        self.seq = max(self.seq, pre) + 1
        signal = evaluate(self.state, ident, pre)
        self.state.start(tid, ident, pre, now=float(self.n))
        self.seq += 1
        self.state.complete(tid, result=result, failed=failed, post_seq=self.seq)
        return signal

    def propose(self, ident: str):
        return evaluate(self.state, ident, self.seq + 1)


class Identity(unittest.TestCase):
    def test_volatile_fields_do_not_split(self) -> None:
        self.assertEqual(identity("Bash", {"command": "ls", "description": "a"}), identity("Bash", {"command": "ls", "description": "b"}))

    def test_changed_argument_is_a_different_action(self) -> None:
        self.assertNotEqual(identity("Bash", {"command": "pytest -x"}), identity("Bash", {"command": "pytest -x -k foo"}))

    def test_string_input_is_hashed_not_collapsed(self) -> None:
        self.assertNotEqual(identity("ApplyPatch", "*** patch one"), identity("ApplyPatch", "*** patch two"))
        self.assertNotEqual(identity("ApplyPatch", "*** patch one"), identity("ApplyPatch", {}))

    def test_null_input_is_distinct_from_empty_dict(self) -> None:
        self.assertNotEqual(identity("X", None), identity("X", {}))

    def test_internal_whitespace_is_preserved(self) -> None:
        self.assertNotEqual(identity("Bash", {"command": "echo 'a  b'"}), identity("Bash", {"command": "echo 'a b'"}))

    def test_bash_fingerprint_ignores_extra_host_fields(self) -> None:
        a = fingerprint("Bash", {"stdout": "x", "stderr": "", "interrupted": False, "duration_ms": 10})
        b = fingerprint("Bash", {"stdout": "x", "stderr": "", "interrupted": False, "duration_ms": 99, "newField": 1})
        self.assertEqual(a, b)

    def test_error_fingerprint_uses_first_line_only(self) -> None:
        self.assertEqual(error_fingerprint("Exit code 1\nfoo"), error_fingerprint("Exit code 1\nbar"))
        self.assertNotEqual(error_fingerprint("Exit code 1\nfoo"), error_fingerprint("Exit code 2\nfoo"))


class Repeat(unittest.TestCase):
    def test_fires_at_threshold_and_not_before(self) -> None:
        d = Driver()
        for _ in range(REPEAT_THRESHOLD - 1):
            self.assertIsNone(d.run(A))
        signal = d.propose(A)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.rule_id, "S1.repeat_same_result")
        self.assertEqual(signal.streak, REPEAT_THRESHOLD)

    def test_changed_result_breaks_the_streak(self) -> None:
        d = Driver()
        d.run(A, SAME)
        d.run(A, OTHER)
        d.run(A, SAME)
        self.assertIsNone(d.propose(A))

    def test_changed_argument_breaks_the_streak(self) -> None:
        d = Driver()
        d.run(A)
        d.run(A)
        d.run(identity("Bash", {"command": "pytest -x -k foo"}))
        self.assertIsNone(d.propose(A))

    def test_parallel_burst_does_not_count(self) -> None:
        d = Driver()
        d.run(A)
        d.run(A, overlap_with_previous=True)
        d.run(A, overlap_with_previous=True)
        self.assertIsNone(d.propose(A))

    def test_streak_keeps_counting_past_threshold(self) -> None:
        d = Driver()
        for _ in range(5):
            d.run(A)
        self.assertEqual(d.propose(A).streak, 6)

    def test_failed_runs_are_not_a_same_result_repeat(self) -> None:
        d = Driver()
        for _ in range(3):
            d.run(A, ERR, failed=True)
        signal = d.propose(A)
        self.assertEqual(signal.rule_id, "S2.repeat_error")


class ErrorLoop(unittest.TestCase):
    def test_fires_at_threshold_and_not_before(self) -> None:
        d = Driver()
        for _ in range(ERROR_THRESHOLD - 1):
            self.assertIsNone(d.run(A, ERR, failed=True))
        signal = d.propose(A)
        self.assertEqual(signal.rule_id, "S2.repeat_error")
        self.assertEqual(signal.streak, ERROR_THRESHOLD)

    def test_different_error_text_still_counts(self) -> None:
        d = Driver()
        d.run(A, error_fingerprint("Exit code 1\na"), failed=True)
        d.run(A, error_fingerprint("Exit code 2\nb"), failed=True)
        self.assertIsNotNone(d.propose(A))

    def test_a_success_in_between_breaks_it(self) -> None:
        d = Driver()
        d.run(A, ERR, failed=True)
        d.run(A, SAME)
        d.run(A, ERR, failed=True)
        self.assertIsNone(d.propose(A))


class Alternation(unittest.TestCase):
    def test_five_do_not_fire_six_do(self) -> None:
        d = Driver()
        pattern = [A, B, A, B, A]
        for ident in pattern[:-1]:
            self.assertIsNone(d.run(ident))
        self.assertIsNone(d.propose(A))      # would be the 5th
        d.run(A)
        signal = d.propose(B)                # the 6th
        self.assertIsNotNone(signal)
        self.assertEqual(signal.rule_id, "S3.alternation")
        self.assertEqual(signal.streak, ALTERNATION_LENGTH)

    def test_changing_results_do_not_fire(self) -> None:
        d = Driver()
        d.run(A, SAME)
        d.run(B, SAME)
        d.run(A, OTHER)
        d.run(B, SAME)
        d.run(A, SAME)
        self.assertIsNone(d.propose(B))

    def test_parallel_pairs_do_not_fire(self) -> None:
        d = Driver()
        d.run(A)
        d.run(B, overlap_with_previous=True)
        d.run(A)
        d.run(B, overlap_with_previous=True)
        d.run(A)
        self.assertIsNone(d.propose(B))


class State(unittest.TestCase):
    def test_orphan_completion_records_nothing(self) -> None:
        s = StuckState()
        self.assertFalse(s.complete("never-started", result=SAME, failed=False, post_seq=1))
        self.assertEqual(len(s.ring), 0)

    def test_expired_in_flight_never_enters_ring(self) -> None:
        s = StuckState()
        s.start("t1", A, 1, now=0.0)
        s.start("t2", A, 2, now=700.0)          # expires t1 (TTL 600)
        self.assertFalse(s.complete("t1", result=SAME, failed=False, post_seq=3))
        self.assertTrue(s.complete("t2", result=SAME, failed=False, post_seq=4))

    def test_reset_clears_everything(self) -> None:
        d = Driver()
        for _ in range(3):
            d.run(A)
        d.state.messaged_identities.add(A)
        d.state.reset()
        self.assertEqual(len(d.state.ring), 0)
        self.assertEqual(d.state.messaged_identities, set())
        self.assertIsNone(d.propose(A))

    def test_reset_clears_nudged_pairs(self) -> None:
        s = StuckState()
        s.nudged.add(("S1.repeat_same_result", A))
        s.reset()
        self.assertEqual(s.nudged, set())


if __name__ == "__main__":
    unittest.main()
