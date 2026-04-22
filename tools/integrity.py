"""
tools/integrity.py
==================
Message Authentication Code — HMAC-SHA256

Purpose
-------
The MAC protects the ciphertext (and its AES nonce) from tampering
in transit.  The GCS checks the MAC *before* decrypting — this is the
"Encrypt-then-MAC" construction, which prevents chosen-ciphertext attacks.

MAC key
-------
The MAC key is the first 16 bytes of the DH-derived shared key.
Because both the Drone and GCS independently derive the same DH key,
they share this MAC key without ever transmitting it.

Classes
-------
MACHandler — stateless; all methods are static helpers.
"""

import hashlib
import hmac


class MACHandler:
    """
    Stateless HMAC-SHA256 helper for message integrity verification.

    All methods are static — instantiation is not required.
    """

    @staticmethod
    def generate(message: bytes, key: bytes) -> bytes:
        """
        Compute HMAC-SHA256 of message under key.

        Parameters
        ----------
        message : bytes to authenticate (typically ciphertext + aes_nonce)
        key     : secret MAC key (derived from DH shared secret)

        Returns
        -------
        32-byte HMAC tag
        """
        return hmac.new(key, message, hashlib.sha256).digest()

    @staticmethod
    def verify(message: bytes, key: bytes, tag: bytes) -> bool:
        """
        Verify an HMAC-SHA256 tag in constant time.

        Constant-time comparison prevents timing side-channel attacks —
        the comparison never short-circuits on the first mismatched byte.

        Parameters
        ----------
        message : the bytes that were authenticated
        key     : the same secret MAC key
        tag     : the received HMAC tag to check

        Returns
        -------
        True if valid; False if the message or tag was tampered with
        """
        expected = MACHandler.generate(message, key)
        return hmac.compare_digest(expected, tag)
