"""
tools/digital_signature.py
==========================
RSA Digital Signatures — PSS padding + SHA-256

Purpose
-------
The Drone signs the plaintext telemetry JSON with its RSA private key
before encrypting.  The GCS verifies the signature against the Drone's
pre-enrolled RSA public key after decryption.

This provides:
  - Authenticity   : proves the message was sent by the specific Drone
  - Non-repudiation: the Drone cannot later deny sending the message
  - Integrity      : any tampering of the plaintext invalidates the signature

PSS vs PKCS#1 v1.5
-------------------
PSS (Probabilistic Signature Scheme) is the modern, provably-secure
padding for RSA signatures.  PKCS#1 v1.5 is legacy and has known
weaknesses.  PSS is the recommended choice per NIST SP 800-131A.

Classes
-------
RSASigner — stateless; all methods are static helpers.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


class RSA_Signer:
    """
    Stateless helper for RSA-PSS-SHA256 digital signatures.

    All methods are static — instantiation is not required.
    """

    # PSS padding configuration — used for both sign and verify
    _PSS = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    @staticmethod
    def generate_keypair(key_size: int = 2048) -> tuple[RSAPrivateKey, RSAPublicKey]:
        """
        Generate a fresh RSA keypair.

        Parameters
        ----------
        key_size : RSA modulus size in bits (default 2048)

        Returns
        -------
        (private_key, public_key)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        return private_key, private_key.public_key()

    # ------------------------------------------------------------------
    # Sign / Verify
    # ------------------------------------------------------------------

    @staticmethod
    def sign(message: bytes, private_key: RSAPrivateKey) -> bytes:
        """
        Sign arbitrary bytes with RSA-PSS-SHA256.

        Parameters
        ----------
        message     : bytes to sign (the plaintext telemetry JSON)
        private_key : signer's RSA private key

        Returns
        -------
        PSS signature bytes
        """
        return private_key.sign(message, RSA_Signer._PSS, hashes.SHA256())

    @staticmethod
    def verify(message: bytes,
               signature: bytes,
               public_key: RSAPublicKey) -> bool:
        """
        Verify an RSA-PSS-SHA256 signature.

        Parameters
        ----------
        message    : the original plaintext bytes
        signature  : PSS signature from sign()
        public_key : signer's RSA public key (pre-enrolled with the GCS)

        Returns
        -------
        True  — signature is valid; message is authentic
        False — signature is invalid; possible forgery or MITM
        """
        try:
            public_key.verify(signature, message, RSA_Signer._PSS, hashes.SHA256())
            return True
        except InvalidSignature:
            return False
