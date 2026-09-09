from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel.control import PairingError, PairingService  # noqa: E402


class MutableClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 9, 8, 20, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now


class PairingServiceTests(unittest.TestCase):
    def test_capability_is_hashed_and_can_be_exchanged_only_once(self) -> None:
        capability = "pairing-capability-" + ("a" * 32)
        session_token = "session-token-" + ("b" * 32)
        service = PairingService(
            capability,
            session_token_factory=lambda: session_token,
        )

        self.assertNotIn(capability, repr(vars(service)))
        with self.assertRaisesRegex(
            PairingError,
            "control:pairing_invalid_or_expired",
        ):
            service.exchange("wrong-capability-" + ("x" * 32))

        issued = service.exchange(capability)
        self.assertEqual(issued.token, session_token)
        self.assertNotIn(session_token, repr(vars(service)))
        with self.assertRaisesRegex(
            PairingError,
            "control:pairing_invalid_or_expired",
        ):
            service.exchange(capability)

    def test_expired_pairing_capability_fails_closed(self) -> None:
        clock = MutableClock()
        capability = "c" * 43
        service = PairingService(
            capability,
            clock=clock,
            pairing_ttl=timedelta(minutes=1),
        )
        clock.now += timedelta(minutes=1)

        with self.assertRaisesRegex(
            PairingError,
            "control:pairing_invalid_or_expired",
        ):
            service.exchange(capability)

    def test_session_uses_inactivity_and_absolute_expiry(self) -> None:
        clock = MutableClock()
        capability = "d" * 43
        raw_session = "e" * 43
        service = PairingService(
            capability,
            clock=clock,
            session_token_factory=lambda: raw_session,
            inactivity_ttl=timedelta(minutes=5),
            absolute_ttl=timedelta(minutes=12),
        )
        service.exchange(capability)

        clock.now += timedelta(minutes=4)
        service.authenticate(raw_session)
        clock.now += timedelta(minutes=4)
        service.authenticate(raw_session)
        clock.now += timedelta(minutes=4)

        with self.assertRaisesRegex(
            PairingError,
            "control:session_invalid_or_expired",
        ):
            service.authenticate(raw_session)

    def test_session_expires_after_inactivity(self) -> None:
        clock = MutableClock()
        capability = "f" * 43
        raw_session = "g" * 43
        service = PairingService(
            capability,
            clock=clock,
            session_token_factory=lambda: raw_session,
            inactivity_ttl=timedelta(minutes=5),
        )
        service.exchange(capability)
        clock.now += timedelta(minutes=5)

        with self.assertRaisesRegex(
            PairingError,
            "control:session_invalid_or_expired",
        ):
            service.authenticate(raw_session)

    def test_logout_requires_the_exact_session_and_invalidates_it(self) -> None:
        capability = "h" * 43
        raw_session = "i" * 43
        service = PairingService(
            capability,
            session_token_factory=lambda: raw_session,
        )
        service.exchange(capability)

        self.assertFalse(service.logout("j" * 43))
        service.authenticate(raw_session)
        self.assertTrue(service.logout(raw_session))
        with self.assertRaisesRegex(
            PairingError,
            "control:session_invalid_or_expired",
        ):
            service.authenticate(raw_session)


if __name__ == "__main__":
    unittest.main()
