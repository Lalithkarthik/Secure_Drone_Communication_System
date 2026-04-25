"""
drone.py
========
Drone - the client side of the secure drone communication system.

Responsibilities
----------------
Phase 1 - Authentication
    Receive the GCS's CHAP challenge and return an HMAC response.

Phase 2 - DH Key Exchange
    Generate an ephemeral DH keypair; exchange public values with the GCS
    to establish a shared MAC key (first 16 bytes of the DH-derived key).

Phase 3 - Session Key Distribution
    Generate a fresh AES-256 session key; wrap it with the GCS's RSA
    public key so only the GCS can unwrap it.

Phase 4 - Telemetry Transmission
    For each DroneMessage:
        1. Serialise to JSON bytes
        2. Sign with the Drone's RSA private key  (authenticity + non-repudiation)
        3. Encrypt with AES-256-CTR session key   (confidentiality)
        4. MAC over ciphertext + nonce            (integrity, Encrypt-then-MAC)
        5. Return the packet dict (binary fields base64-encoded for transmission)
"""

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
        """
        Returns Drone's RSA public key for the Ground Station to use.
        """
        return self.rsa_public_key

    def set_gcs_public_key(self, gcs_public_key: RSAPublicKey) -> None:
        """
        Obtains the Ground Station's RSA public key and stores it.
        """
        self.gcs_public = gcs_public_key
        print(f"[Drone {self.drone_id}] GCS RSA public key stored.")

    def respond_to_challenge(self, challenge: bytes) -> bytes:
        """
        Compute the CHAP response for the given challenge and passes it back to the Ground Station for authentication, without the password
        ever being transmitted directly.
        """
        response = CHAPAuthenticator.compute_response(challenge, self.password)
        sleep(1)
        print(f"[Drone {self.drone_id}] CHAP response computed.")
        return response

    def init_dh(self) -> int:
        """
        Generates a DH keypair. Exchange occurs with the next function.
        """
        self.dh = DHParty()
        public_key = self.dh.get_public_int()
        print(f"[Drone {self.drone_id}] DH keypair generated.")
        return public_key

    def complete_dh(self, gcs_dh_public: int) -> None:
        """
        Exchange is performed with the Ground Station's key, to finally obtain the key for generating the MAC.
        """
        if self.dh is None:
            raise RuntimeError("Call init_dh() before complete_dh().")
        derived = self.dh.derive_shared_key(gcs_dh_public)
        self.mac_key = derived[:16] #The first 16 characters of the exchanged key are used for MAC in our implementation. Rest can be considered to be additional, potentially used later for future applications.
        sleep(1)
        print(f"[Drone {self.drone_id}] DH exchange complete - MAC key derived.")

    def generate_and_send_session_key(self) -> bytes:
        """
        Generation of AES-256 session key is done by the Drone, and is securely transmitted to the Ground Station using RSA.
        """
        if self.gcs_public is None:
            raise RuntimeError("GCS RSA public key not set.")

        self.aes_session_key  = os.urandom(32)
        encrypted_key = HybridEncryptor.rsa_encrypt_key(self.aes_session_key, self.gcs_public)
        sleep(1)
        print(f"[Drone {self.drone_id}] AES-256 session key generated and RSA-wrapped. Sending securely to the Ground Station...")
        return encrypted_key
    
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
            raise RuntimeError("Session key not set - complete key exchange first.")
        if self.mac_key is None:
            raise RuntimeError("MAC key not set - complete DH exchange first.")

        plaintext = message.to_json().encode("utf-8") #Encoded into the prescribed format (from message.py)
        signature = RSA_Signer.sign(plaintext, self.rsa_private_key) #Digital signature using RSA
        ciphertext, aes_nonce = HybridEncryptor.aes_encrypt(plaintext, self.aes_session_key) #Encrypted with AES and it's nonce generated
        mac = MACHandler.generate(ciphertext + aes_nonce, self.mac_key) #MAC generated
        packet = {
            "ciphertext" : ciphertext,
            "aes_nonce"  : aes_nonce,
            "mac"        : mac,
            "signature"  : signature,
            "msg_nonce"  : message.nonce  #plaintext nonce for replay check
        } 
        sleep(1)
        print(f"[Drone {self.drone_id}] Secure packet assembled. Transmitting...")
        return packet
