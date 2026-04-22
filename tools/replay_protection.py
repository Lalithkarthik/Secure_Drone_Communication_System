"""
tools/replay_protection.py
==========================
Replay Attack Protection — Nonce Registry

How it works
------------
Every DroneMessage carries a UUID4 nonce generated at creation time.
When the GCS receives a packet it calls register_nonce().  The manager
records the nonce in a set.  Any subsequent packet carrying the same
nonce is immediately rejected.

UUID4 uniqueness
----------------
A UUID4 is 122 bits of cryptographic randomness.  The probability of
a collision across 1 billion messages is approximately 6 × 10⁻¹⁹ —
effectively impossible in practice.

Thread safety
-------------
The internal set is protected by a threading.Lock so the manager can
be shared safely across threads.

Classes
-------
NonceManager — one instance per GCS session.
"""

import uuid
from threading import Lock


class NonceManager:
    """
    Tracks nonces seen in the current session to detect replayed packets.

    A nonce is accepted (returns True) the first time it is registered.
    Any later registration of the same nonce returns False — the caller
    should treat this as a replay attack and reject the message.
    """

    def __init__(self):
        self._seen: set[str] = set()
        self._lock = Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def generate_nonce() -> str:
        """
        Generate a fresh cryptographically-random UUID4 nonce string.

        This is called by the Drone when building a new DroneMessage.
        """
        return str(uuid.uuid4())

    def register_nonce(self, nonce: str) -> bool:
        """
        Attempt to register a nonce from an incoming message.

        Parameters
        ----------
        nonce : nonce string extracted from the packet

        Returns
        -------
        True  — nonce is fresh; message should be processed
        False — nonce already seen; REPLAY ATTACK — reject message
        """
        with self._lock:
            if nonce in self._seen:
                return False
            self._seen.add(nonce)
            return True

    def reset(self):
        """Clear all stored nonces — useful for testing."""
        with self._lock:
            self._seen.clear()

    @property
    def seen_count(self) -> int:
        """Number of nonces registered in this session."""
        return len(self._seen)
