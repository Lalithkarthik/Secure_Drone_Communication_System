"""
tools/replay_protection.py
This file is specifically built to prevent replay attacks, and the technique chosen for that is Nonce. This file provides classes which enable the generation of a UUID4 nonce for every new message and register it with a Nonce manager, who checks and ensures the uniqueness of said nonce. In case of previously used nonce within a particular session being used again, it is an indication of replay attack, and that packet is rejected.
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
