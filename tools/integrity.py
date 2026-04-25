"""
integrity.py
Message Authentication Code - HMAC-SHA256

Purpose
-------
The MAC protects the ciphertext (and its AES nonce) from tampering
in transit.  The GCS checks the MAC *before* decrypting - this is the
"Encrypt-then-MAC" construction, which prevents chosen-ciphertext attacks.

MAC key
-------
The MAC key is the first 16 bytes of the DH-derived shared key.
Because both the Drone and GCS independently derive the same DH key,
they share this MAC key without ever transmitting it.

Classes
-------
MACHandler - stateless; all methods are static helpers.
"""

import hashlib
import hmac

class MACHandler:
    @staticmethod
    def generate(message: bytes, key: bytes) -> bytes:
        """
        Computes the MAC of the message using a key shared using Diffie-Hellman technique.
        """
        return hmac.new(key, message, hashlib.sha256).digest()

    @staticmethod
    def verify(message: bytes, key: bytes, tag: bytes) -> bool:
        """
        Verifies the message and it's corresponding MAC to ensure message integrity. Any mismatch between the message and its message
        leads to a belief that the message has been tampered with and its integrity has been compromised with malicious intentions.
        """
        expected = MACHandler.generate(message, key)
        return hmac.compare_digest(expected, tag)
