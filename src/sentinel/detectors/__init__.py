"""Deterministic detectors that run only after the floor did not decide.

They may produce `warn`; never `allow`, `block`, or `confirm`.
"""

from sentinel.detectors.stuck import Signal, StuckState, evaluate, fingerprint, identity

__all__ = ["Signal", "StuckState", "evaluate", "fingerprint", "identity"]
