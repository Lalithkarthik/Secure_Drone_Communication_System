"""
tools/authentication.py

Authentication of the Drone happens in the Challenge-Response style. The following procedure takes place:
1. The Drone and Ground Station are assumed to be in possession of the registered password.
2. The Ground Station (authenticator) generates a unique, random challenge using the generate_challenge() function.
3. Drone receives this challenge, computes and returns the response it got after computation through compute_response() function.
4. Ground Station receives the response, computes the same computation by itself, and verifies through comparision.
Due to this style of implementation, the password is never shared directly over the communication media, and is thus more secure.
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
        (salt, sha256_digest)  - store both; salt is not secret
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
    CHAP styled Challenge–Response Authenticator class which lives on the Ground Station, while the Drone uses the components of this class
    independtly for responses alone. 
    """
    def __init__(self):
        self.challenge: bytes | None = None

    def generate_challenge(self) -> bytes:
        """
        Generate a unique, random challenge. The challenge is stored internally until verify_response() is called.
        """
        self.challenge = os.urandom(16)
        return self.challenge

    def verify_response(self, response: bytes, password: str) -> bool:
        """
        Verifies the Drone's challenge response against the active challenge by performing the computation by itself and comparing the
        results achieved. This is called by the authenticator, i.e. the Ground Station.
        """
        if self.challenge is None:
            raise RuntimeError("No active challenge - call generate_challenge() first.")
        expected = CHAPAuthenticator.compute_mac(self.challenge, password)
        self.challenge = None      # invalidate immediately - prevents reuse
        return hmac.compare_digest(expected, response)

    @staticmethod
    def compute_response(challenge: bytes, password: str) -> bytes:
        """
        Computes the CHAP response. Called upon by the Drone upon receiving a challenge from the Ground Station.
        """
        return CHAPAuthenticator.compute_mac(challenge, password)

    @staticmethod
    def compute_mac(challenge: bytes, password: str) -> bytes:
        return hmac.new(password.encode("utf-8"), challenge, hashlib.sha256).digest()
