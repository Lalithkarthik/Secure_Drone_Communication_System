"""
integrity.py
As the name suggests, this file handles the "integrity" aspect, using the Message Authentication code (MAC), specifically HMAC-SHA256. How it is implemented:
1. Through Diffie Hellman key exchange, the key required for creating this MAC has been shared between both drone and ground station, after initialisation and authentication.
2. After encryption with the AES session key, the drone uses this key and appends the MAC computed to the message, and continues to transmit.
3. After receiving the transmission, the Ground Station verifies the MAC, before decrypting, which is done by computing the MAC itself using it's own shared key version. Any mismatch is considered to be an integrity violation, suggesting that the message has been tampered with.
All methods are static, so initialise of this class as an object to use these methods is not required, with the same having been followed in the implementation.
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
