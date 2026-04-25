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
    # PSS padding configuration — used for both sign and verify, CHECK HERE
    PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)

    @staticmethod
    def generate_keypair(key_size: int = 2048) -> tuple[RSAPrivateKey, RSAPublicKey]:
        """
        Generats a fresh RSA keypair. Returns the public and private keys.
        """
        private_key = rsa.generate_private_key(public_exponent=65537,key_size=key_size)
        return private_key, private_key.public_key()

    @staticmethod
    def sign(message: bytes, private_key: RSAPrivateKey) -> bytes:
        """
        Signs a message with RSA private key. Returns signature bytes only.
        """
        return private_key.sign(message, RSA_Signer.PSS, hashes.SHA256())

    @staticmethod
    def verify(message: bytes, signature: bytes, public_key: RSAPublicKey) -> bool:
        """
        Takes a message and it's corresponding signature, along with the RSA public key. Using these, it verifies whether the signature
         matches the valid sender or not. Works towards checking the sender's identity. Prevents forgery and some variants of MITM attacks.
        """
        try:
            public_key.verify(signature, message, RSA_Signer.PSS, hashes.SHA256())
            return True
        except InvalidSignature:
            return False
