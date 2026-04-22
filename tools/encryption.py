"""
tools/encryption.py
===================
Hybrid Encryption: RSA-OAEP  +  AES-256-CTR

Why hybrid?
-----------
RSA is computationally expensive and can only encrypt small payloads.
AES-CTR is fast and handles arbitrary-length data.
The hybrid scheme combines the key-distribution strength of RSA with
the throughput of AES:
    1. Drone generates a fresh random AES-256 session key.
    2. Drone encrypts the session key with the GCS's RSA public key.
    3. Drone encrypts the actual telemetry data with AES-256-CTR.
    4. GCS decrypts the session key with its RSA private key.
    5. GCS decrypts the telemetry data with the recovered session key.

AES-CTR mode
------------
CTR (Counter) mode turns AES into a stream cipher — no padding required,
and every 16-byte block is encrypted independently.  A fresh 16-byte
nonce is generated per message and transmitted alongside the ciphertext.

Classes
-------
HybridEncryptor — stateless; all methods are static helpers.
"""

import os
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes


class HybridEncryptor:
    """
    Stateless helper that provides RSA-OAEP key wrapping
    and AES-256-CTR data encryption/decryption.
    """

    # OAEP padding used for RSA encryption/decryption of the AES key
    _OAEP = asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

    # ------------------------------------------------------------------
    # RSA layer — session key wrapping
    # ------------------------------------------------------------------

    @staticmethod
    def rsa_encrypt_key(aes_key: bytes, rsa_public_key: RSAPublicKey) -> bytes:
        """
        Wrap an AES key using RSA-OAEP-SHA256.

        Parameters
        ----------
        aes_key        : 32-byte AES-256 key to protect
        rsa_public_key : recipient's RSA public key

        Returns
        -------
        RSA ciphertext (same length as the RSA key modulus)
        """
        return rsa_public_key.encrypt(aes_key, HybridEncryptor._OAEP)

    @staticmethod
    def rsa_decrypt_key(encrypted_key: bytes,
                        rsa_private_key: RSAPrivateKey) -> bytes:
        """
        Unwrap an RSA-OAEP-encrypted AES key.

        Parameters
        ----------
        encrypted_key   : ciphertext produced by rsa_encrypt_key
        rsa_private_key : recipient's RSA private key

        Returns
        -------
        The original 32-byte AES key
        """
        return rsa_private_key.decrypt(encrypted_key, HybridEncryptor._OAEP)

    # ------------------------------------------------------------------
    # AES layer — data encryption / decryption
    # ------------------------------------------------------------------

    @staticmethod
    def aes_encrypt(plaintext: bytes, aes_key: bytes) -> tuple[bytes, bytes]:
        """
        Encrypt arbitrary bytes with AES-256-CTR.

        A fresh 16-byte nonce is generated per call — NEVER reuse a nonce
        with the same key.

        Parameters
        ----------
        plaintext : data to encrypt
        aes_key   : 32-byte AES-256 key

        Returns
        -------
        (ciphertext, ctr_nonce) — both must be kept; nonce is not secret
        but must be transmitted to enable decryption.
        """
        ctr_nonce = os.urandom(16)
        cipher    = Cipher(algorithms.AES(aes_key), modes.CTR(ctr_nonce))
        enc       = cipher.encryptor()
        ciphertext = enc.update(plaintext) + enc.finalize()
        return ciphertext, ctr_nonce

    @staticmethod
    def aes_decrypt(ciphertext: bytes,
                    aes_key:    bytes,
                    ctr_nonce:  bytes) -> bytes:
        """
        Decrypt AES-256-CTR ciphertext.

        Parameters
        ----------
        ciphertext : data produced by aes_encrypt
        aes_key    : same 32-byte key used for encryption
        ctr_nonce  : same 16-byte nonce used for encryption

        Returns
        -------
        Original plaintext bytes
        """
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(ctr_nonce))
        dec    = cipher.decryptor()
        return dec.update(ciphertext) + dec.finalize()
