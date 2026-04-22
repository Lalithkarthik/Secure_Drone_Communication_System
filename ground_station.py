"""
ground_station.py
=================
Ground Control Station (GCS) — the server side of the secure
drone communication system.

Responsibilities
----------------
Phase 1 — Authentication
    Issue a CHAP challenge; verify the drone's HMAC response.

Phase 2 — DH Key Exchange
    Generate an ephemeral DH keypair; exchange public values with the
    Drone to establish a shared MAC key.

Phase 3 — Session Key Receipt
    Receive the RSA-wrapped AES session key and decrypt it with the
    GCS's RSA private key.

Phase 4 — Receive and Validate Telemetry
    For each incoming packet:
        1. Verify HMAC  (integrity — Encrypt-then-MAC)
        2. Check nonce  (replay protection)
        3. Decrypt AES  (recover plaintext)
        4. Verify RSA signature  (authenticity + non-repudiation)
        5. Deserialise DroneMessage
"""

import base64

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from tools import (
    CHAPAuthenticator,
    DHParty,
    DroneMessage,
    HybridEncryptor,
    MACHandler,
    NonceManager,
    PasswordStore,
    RSASigner,
)


class SecurityException(Exception):
    """
    Raised whenever a security check fails during packet processing.
    The message describes which check failed.
    """
    pass


class GroundStation:
    """
    Ground Control Station — authenticates drones and receives telemetry.

    Parameters
    ----------
    password : pre-shared secret used for CHAP authentication.
               Note: CHAP requires the authenticator to hold this value
               so it can recompute the expected HMAC for verification.
               In a production system it would be stored in an HSM.
    """

    def __init__(self, password: str):
        # CHAP requires the raw password on the authenticator side
        self._password = password

        # Salted hash stored for auditing / display (never used for CHAP logic)
        self._pw_store = PasswordStore()
        self._pw_salt, self._pw_hash = self._pw_store.hash_password(password)

        # Long-term RSA identity keypair
        self._rsa_private, self._rsa_public = RSASigner.generate_keypair()

        # CHAP authenticator
        self._chap = CHAPAuthenticator()

        # Session state (populated during handshake)
        self._drone_rsa_public: RSAPublicKey | None = None
        self._dh_party:    DHParty | None = None
        self._mac_key:     bytes   | None = None
        self._session_key: bytes   | None = None

        # Nonce registry — persists across all packets in the session
        self._nonce_manager = NonceManager()

        self._authenticated = False
        print("[GCS] Ground Control Station initialised — RSA-2048 keypair generated.")

    # ------------------------------------------------------------------
    # Key provisioning (pre-mission)
    # ------------------------------------------------------------------

    def get_public_rsa_key(self) -> RSAPublicKey:
        """Return the GCS's RSA public key for sharing with the Drone."""
        return self._rsa_public

    def enroll_drone_public_key(self, drone_public_key: RSAPublicKey) -> None:
        """
        Register a drone's RSA public key before a mission.

        In a real system this would be part of a PKI certificate
        provisioned by a Certificate Authority at manufacture time.
        """
        self._drone_rsa_public = drone_public_key
        print("[GCS] Drone RSA public key enrolled.")

    # ------------------------------------------------------------------
    # Phase 1 — CHAP Authentication
    # ------------------------------------------------------------------

    def issue_challenge(self) -> bytes:
        """
        Generate and return a fresh 16-byte CHAP challenge.

        The challenge is stored internally until verify_challenge_response()
        is called.  Each challenge is single-use.
        """
        challenge = self._chap.generate_challenge()
        print(f"[GCS] CHAP challenge issued: {challenge.hex()}")
        return challenge

    def verify_challenge_response(self, response: bytes) -> bool:
        """
        Verify the Drone's CHAP response.

        Internally recomputes HMAC-SHA256(key=password, msg=challenge)
        and compares in constant time.  The challenge is cleared
        regardless of outcome.

        Returns
        -------
        True on success (sets authenticated flag); False on failure.
        """
        result = self._chap.verify_response(response, self._password)
        if result:
            self._authenticated = True
            print("[GCS] CHAP authentication: PASSED ✓")
        else:
            print("[GCS] CHAP authentication: FAILED ✗")
        return result

    # ------------------------------------------------------------------
    # Phase 2 — DH Key Exchange
    # ------------------------------------------------------------------

    def init_dh(self) -> int:
        """
        Generate an ephemeral DH keypair and return the public value.
        """
        self._dh_party = DHParty()
        pub = self._dh_party.get_public_int()
        print("[GCS] DH keypair generated.")
        return pub

    def complete_dh(self, drone_dh_public: int) -> None:
        """
        Finalise the DH exchange using the Drone's public value.

        Derives a 32-byte shared key; uses the first 16 bytes as the MAC key.
        """
        if self._dh_party is None:
            raise RuntimeError("Call init_dh() before complete_dh().")
        derived       = self._dh_party.derive_shared_key(drone_dh_public)
        self._mac_key = derived[:16]
        print("[GCS] DH exchange complete — MAC key derived.")

    # ------------------------------------------------------------------
    # Phase 3 — Session Key Receipt
    # ------------------------------------------------------------------

    def receive_session_key(self, encrypted_session_key: bytes) -> None:
        """
        Decrypt the RSA-wrapped AES session key sent by the Drone.

        Uses the GCS's RSA private key — the only key that can unwrap it.
        """
        self._session_key = HybridEncryptor.rsa_decrypt_key(
            encrypted_session_key, self._rsa_private
        )
        print("[GCS] AES-256 session key unwrapped successfully.")

    # ------------------------------------------------------------------
    # Phase 4 — Receive and Validate Telemetry
    # ------------------------------------------------------------------

    def receive_telemetry(self, packet: dict) -> DroneMessage:
        """
        Validate and decrypt an incoming telemetry packet.

        Security checks in order
        -------------------------
        1. Authentication gate  — drone must have completed CHAP
        2. HMAC verification    — detect any in-transit tampering
        3. Nonce check          — detect replayed packets
        4. AES decryption       — recover plaintext
        5. RSA signature check  — confirm message came from enrolled drone

        Parameters
        ----------
        packet : dict with keys ciphertext, aes_nonce, mac, signature, msg_nonce
                 (all binary fields are base64-encoded strings)

        Returns
        -------
        DroneMessage on success

        Raises
        ------
        SecurityException if any check fails — caller should discard the packet
        """
        # -- Gate: must be authenticated first --
        if not self._authenticated:
            raise SecurityException("Drone is not authenticated.")

        # Decode base64 fields
        ciphertext = base64.b64decode(packet["ciphertext"])
        aes_nonce  = base64.b64decode(packet["aes_nonce"])
        mac_tag    = base64.b64decode(packet["mac"])
        signature  = base64.b64decode(packet["signature"])
        msg_nonce: str = packet["msg_nonce"]

        # -- Check 1: HMAC integrity over ciphertext || aes_nonce --
        if not MACHandler.verify(ciphertext + aes_nonce, self._mac_key, mac_tag):
            raise SecurityException(
                "HMAC verification FAILED — message was tampered with in transit."
            )
        print("[GCS] ✓ HMAC integrity check passed.")

        # -- Check 2: Nonce uniqueness (replay protection) --
        if not self._nonce_manager.register_nonce(msg_nonce):
            raise SecurityException(
                f"REPLAY ATTACK detected — nonce '{msg_nonce}' has already been processed."
            )
        print("[GCS] ✓ Nonce is fresh — not a replay.")

        # -- Check 3: AES-256-CTR decryption --
        plaintext = HybridEncryptor.aes_decrypt(ciphertext, self._session_key, aes_nonce)
        print("[GCS] ✓ AES-256-CTR decryption successful.")

        # -- Check 4: RSA-PSS digital signature --
        if self._drone_rsa_public is None:
            raise SecurityException("No drone RSA public key enrolled.")
        if not RSASigner.verify(plaintext, signature, self._drone_rsa_public):
            raise SecurityException(
                "RSA signature verification FAILED — possible forgery or MITM attack."
            )
        print("[GCS] ✓ RSA digital signature verified.")

        # All checks passed — deserialise and return
        message = DroneMessage.from_json(plaintext.decode("utf-8"))
        print(f"[GCS] Telemetry accepted: {message.pretty()}")
        return message
