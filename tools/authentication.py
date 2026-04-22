"""
tools/authentication.py
=======================
CHAP-style Challenge–Response Authentication

Protocol (mirrors PPP-CHAP, RFC 1994)
--------------------------------------
1. GCS (authenticator) calls generate_challenge() → 16 random bytes → sends to Drone
2. Drone calls compute_response(challenge, password) → HMAC-SHA256(key=password, msg=challenge)
3. GCS calls verify_response(response, password)    → recomputes and compares in constant time

Why CHAP?
---------
The password is NEVER transmitted in the clear.  An eavesdropper
who captures the challenge and response cannot derive the password
without breaking HMAC-SHA256.  The challenge is single-use — the GCS
clears it immediately after a verification attempt, preventing re-use.

Password storage (PasswordStore)
---------------------------------
On-disk passwords are stored as  SHA-256(salt || password) — never
as plaintext.  This class is used to demonstrate secure storage
best-practices in the system design, and is used at enrolment time.

Note on CHAP's known limitation
--------------------------------
CHAP requires the authenticator (GCS) to hold a copy of the plaintext
(or reversibly encrypted) shared secret so it can recompute the expected
HMAC.  This is a recognised trade-off inherent to CHAP.  In a production
system this would be mitigated by storing the secret in a hardware HSM
or a secure enclave.
"""

import hashlib
import hmac
import os


class PasswordStore:
    """
    Secure salted password hashing.

    Passwords are NEVER stored or logged as plaintext.
    Each password is salted with 16 random bytes before hashing.
    """

    @staticmethod
    def hash_password(password: str) -> tuple[bytes, bytes]:
        """
        Hash a password with a fresh random 16-byte salt.

        Returns
        -------
        (salt, sha256_digest)  — store both; salt is not secret
        """
        salt   = os.urandom(16)
        digest = hashlib.sha256(salt + password.encode("utf-8")).digest()
        return salt, digest

    @staticmethod
    def verify_password(password: str, salt: bytes, stored_hash: bytes) -> bool:
        """
        Verify a plaintext password against its stored salt + hash.
        Comparison is constant-time to prevent timing attacks.
        """
        computed = hashlib.sha256(salt + password.encode("utf-8")).digest()
        return hmac.compare_digest(computed, stored_hash)


class CHAPAuthenticator:
    """
    CHAP Challenge–Response Authenticator.

    This object lives on the GCS (server / authenticator side).
    The Drone uses the static compute_response() method independently.

    Each challenge is one-time-use: it is cleared immediately after
    verify_response() is called, whether the attempt succeeds or not.
    """

    def __init__(self):
        self._challenge: bytes | None = None

    # ------------------------------------------------------------------
    # GCS side
    # ------------------------------------------------------------------

    def generate_challenge(self) -> bytes:
        """
        Generate a fresh 16-byte random challenge.

        The challenge is stored internally until verify_response() is called.
        """
        self._challenge = os.urandom(16)
        return self._challenge

    def verify_response(self, response: bytes, password: str) -> bool:
        """
        Verify the drone's HMAC-SHA256 response against the active challenge.

        Parameters
        ----------
        response : bytes received from the Drone
        password : the shared secret held by the GCS

        Returns
        -------
        True if the response is valid; False otherwise.

        Side-effect
        -----------
        Clears the active challenge regardless of outcome (single-use).
        """
        if self._challenge is None:
            raise RuntimeError(
                "No active challenge — call generate_challenge() first."
            )
        expected        = CHAPAuthenticator._compute_hmac(self._challenge, password)
        self._challenge = None      # invalidate immediately — prevents reuse
        return hmac.compare_digest(expected, response)

    # ------------------------------------------------------------------
    # Drone side (static — no state needed)
    # ------------------------------------------------------------------

    @staticmethod
    def compute_response(challenge: bytes, password: str) -> bytes:
        """
        Compute the CHAP response: HMAC-SHA256(key=password, msg=challenge).

        Called by the Drone upon receiving a challenge from the GCS.
        """
        return CHAPAuthenticator._compute_hmac(challenge, password)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_hmac(challenge: bytes, password: str) -> bytes:
        return hmac.new(
            password.encode("utf-8"),
            challenge,
            hashlib.sha256,
        ).digest()
