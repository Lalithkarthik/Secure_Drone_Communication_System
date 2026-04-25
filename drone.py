"""
drone.py
========
Drone — the client side of the secure drone communication system.

Responsibilities
----------------
Phase 1 — Authentication
    Receive the GCS's CHAP challenge and return an HMAC response.

Phase 2 — DH Key Exchange
    Generate an ephemeral DH keypair; exchange public values with the GCS
    to establish a shared MAC key (first 16 bytes of the DH-derived key).

Phase 3 — Session Key Distribution
    Generate a fresh AES-256 session key; wrap it with the GCS's RSA
    public key so only the GCS can unwrap it.

Phase 4 — Telemetry Transmission
    For each DroneMessage:
        1. Serialise to JSON bytes
        2. Sign with the Drone's RSA private key  (authenticity + non-repudiation)
        3. Encrypt with AES-256-CTR session key   (confidentiality)
        4. MAC over ciphertext + nonce            (integrity, Encrypt-then-MAC)
        5. Return the packet dict (binary fields base64-encoded for transmission)
"""

import base64
import os
from time import sleep

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from tools import (
    CHAPAuthenticator,
    DHParty,
    DroneMessage,
    HybridEncryptor,
    MACHandler,
    RSA_Signer,
)


class Drone:
    """
    Represents a drone in the secure communication system.

    Parameters
    ----------
    drone_id : unique identifier string for this drone (e.g. "DR001")
    password : pre-shared secret used for CHAP authentication with the GCS
    """

    def __init__(self, drone_id: str, password: str):
        self.drone_id = drone_id
        self.password = password
        print(f"Starting up the Drone {drone_id}...")
        sleep(1)

        print("Generating Drone's RSA public and private keys...")
        sleep(1) 
        self.rsa_private_key, self.rsa_public_key = RSA_Signer.generate_keypair() #Generates its own RSA public and private keys
        print(f"Generated Drone {drone_id}'s RSA keys successfully.")

        #The following variables are populated during the system simulation
        self.gcs_public: RSAPublicKey | None = None
        self.dh: DHParty | None = None
        self.aes_session_key: bytes | None = None
        self.mac_key: bytes | None = None

        print(f"[Drone {self.drone_id} reporting] En route the Mission.")

    def get_public_rsa_key(self) -> RSAPublicKey:
        """Returns Drone's RSA public key for the Ground Station to use."""
        return self.rsa_public_key

    def set_gcs_public_key(self, gcs_public_key: RSAPublicKey) -> None:
        """
        Obtains the Ground Station's RSA public key and stores it.
        """
        self.gcs_public = gcs_public_key
        print(f"[Drone {self.drone_id}] GCS RSA public key stored.")

    # ------------------------------------------------------------------
    # Phase 1 — CHAP Response
    # ------------------------------------------------------------------

    def respond_to_challenge(self, challenge: bytes) -> bytes:
        """
        Compute the CHAP response for the given challenge.

        Response = HMAC-SHA256(key=password, msg=challenge)
        The password is never transmitted.
        """
        response = CHAPAuthenticator.compute_response(challenge, self.password)
        print(f"[Drone {self.drone_id}] CHAP response computed.")
        return response

    # ------------------------------------------------------------------
    # Phase 2 — DH Key Exchange
    # ------------------------------------------------------------------

    def init_dh(self) -> int:
        """
        Generate an ephemeral DH keypair and return the public value.

        Must be called before complete_dh().
        """
        self.dh = DHParty()
        pub = self.dh.get_public_int()
        print(f"[Drone {self.drone_id}] DH keypair generated.")
        return pub

    def complete_dh(self, gcs_dh_public: int) -> None:
        """
        Finalise the DH exchange using the GCS's public value.

        Derives a 32-byte shared key; uses the first 16 bytes as the MAC key.
        The remaining bytes are available if needed for additional key material.
        """
        if self.dh is None:
            raise RuntimeError("Call init_dh() before complete_dh().")
        derived       = self.dh.derive_shared_key(gcs_dh_public)
        self.mac_key = derived[:16]
        print(f"[Drone {self.drone_id}] DH exchange complete — MAC key derived.")

    # ------------------------------------------------------------------
    # Phase 3 — Session Key Generation and Distribution
    # ------------------------------------------------------------------

    def generate_and_send_session_key(self) -> bytes:
        """
        Generate a fresh 32-byte AES-256 session key and return it
        wrapped (encrypted) with the GCS's RSA public key.

        Only the GCS, with its RSA private key, can recover the session key.
        """
        if self.gcs_public is None:
            raise RuntimeError("GCS RSA public key not set.")

        self.aes_session_key  = os.urandom(32)
        encrypted_key      = HybridEncryptor.rsa_encrypt_key(
            self.aes_session_key, self.gcs_public
        )
        print(f"[Drone {self.drone_id}] AES-256 session key generated and RSA-wrapped.")
        return encrypted_key

    # ------------------------------------------------------------------
    # Phase 4 — Secure Telemetry Transmission
    # ------------------------------------------------------------------

    def send_message(self, message: DroneMessage) -> dict:
        """
        Package a DroneMessage into a secure, authenticated packet.

        Processing order (Sign-then-Encrypt-then-MAC)
        -----------------------------------------------
        1. Serialise  → JSON bytes (plaintext)
        2. Sign       → RSA-PSS signature over plaintext
        3. Encrypt    → AES-256-CTR  → (ciphertext, aes_nonce)
        4. MAC        → HMAC-SHA256 over (ciphertext || aes_nonce)

        All binary fields are base64-encoded for safe transmission.

        Parameters
        ----------
        message : DroneMessage to transmit

        Returns
        -------
        dict with keys: ciphertext, aes_nonce, mac, signature, msg_nonce
        """
        if self.aes_session_key is None:
            raise RuntimeError("Session key not set — complete key exchange first.")
        if self.mac_key is None:
            raise RuntimeError("MAC key not set — complete DH exchange first.")

        # Step 1: Serialise
        plaintext = message.to_json().encode("utf-8")

        # Step 2: Sign plaintext (RSA-PSS-SHA256)
        signature = RSA_Signer.sign(plaintext, self.rsa_private_key)

        # Step 3: Encrypt with AES-256-CTR
        ciphertext, aes_nonce = HybridEncryptor.aes_encrypt(plaintext, self.aes_session_key)

        # Step 4: MAC over ciphertext || aes_nonce  (Encrypt-then-MAC)
        mac_tag = MACHandler.generate(ciphertext + aes_nonce, self.mac_key)

        packet = {
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "aes_nonce":  base64.b64encode(aes_nonce).decode("ascii"),
            "mac":        base64.b64encode(mac_tag).decode("ascii"),
            "signature":  base64.b64encode(signature).decode("ascii"),
            "msg_nonce":  message.nonce,    # plaintext nonce for replay check
        }

        print(f"[Drone {self.drone_id}] Secure packet assembled and ready to transmit.")
        return packet
