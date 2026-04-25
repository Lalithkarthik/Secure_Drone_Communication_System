"""
digital_signature.py

This file contains components used for digital signature, which ensures verification of sender and non-repudiation. The process followed
is: 
1. Drone signs the plaintext message with its RSA private key.
2. The message undergoes further processing as needed, and is transmitted over to the Ground station.
3. Upon receiving the packet, the Ground Station verifies the digital signature by trying to decrypt that aspect with the Drone's
public RSA key.
Successful signature ensures authenticity, integrity, non-repudiation, protection against some variants of MITM attacks, etc.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

class RSA_Signer:
    #PSS is a commonly used padding configuration for digital signatures.
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
