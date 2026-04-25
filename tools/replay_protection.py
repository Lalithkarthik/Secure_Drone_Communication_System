"""
tools/replay_protection.py
==========================
Replay Attack Protection - Nonce Registry

How it works
------------
Every DroneMessage carries a UUID4 nonce generated at creation time.
When the GCS receives a packet it calls register_nonce().  The manager
records the nonce in a set.  Any subsequent packet carrying the same
nonce is immediately rejected.

UUID4 uniqueness
----------------
A UUID4 is 122 bits of cryptographic randomness.  The probability of
a collision across 1 billion messages is approximately 6 × 10⁻¹⁹ -
effectively impossible in practice.

Thread safety
-------------
The internal set is protected by a threading.Lock so the manager can
be shared safely across threads.

Classes
-------
NonceManager - one instance per GCS session.
"""

import uuid
from threading import Lock

class NonceManager:
    """
    Tracks nonces seen in the current session so far and ensures that there are no repetitions. It works to detect replayed packets and
    preventing Replay attacks.
    """
    def __init__(self):
        self.seen: set[str] = set()
        self.lock = Lock()

    @staticmethod
    def generate_nonce() -> str:
        """
        Generates a fresh random nonce string, which is called by the Drone everytime it builds a new message of "DroneMessage" class.
        """
        return str(uuid.uuid4())

    def register_nonce(self, nonce: str) -> bool:
        """
        Attempt to register a nonce from an incoming message. It is successful if the nonce is fresh, else, if it has already been seen 
        within the session, it is considered to be a potential replay attack and the message is rejected, before raising an alarm of the 
        potential security breach in communications.
        """
        with self.lock:
            if nonce in self.seen:
                return False
            self.seen.add(nonce)
            return True
