"""
attacks/mitm_attack.py
======================
Man-in-the-Middle (MITM) Attack Simulation

What is a MITM attack?
-----------------------
An attacker ("Eve") inserts herself between the Drone and the GCS.
She intercepts both sides of the DH key exchange and substitutes her
own DH public values.  This gives her separate shared secrets with
both the Drone and the GCS — she can potentially read and re-encrypt
traffic in both directions.

Why our system defeats it
--------------------------
The critical protection is the RSA digital signature:

    1. The GCS pre-enrolls the REAL Drone's RSA public key before the mission.
    2. Every telemetry message is signed by the Drone's RSA PRIVATE key.
    3. Even if Eve controls the DH channel, she does NOT have the Drone's
       RSA private key and cannot forge a valid signature.
    4. When Eve submits her forged packet to the GCS, signature verification
       fails because her signature was made with her OWN RSA key,
       not the enrolled Drone key.

Simulation setup
----------------
A fresh GCS is created with the REAL Drone's RSA public key enrolled.
Eve:
  1. Successfully completes CHAP (she knows the shared password —
     CHAP proves knowledge of the password but not RSA identity).
  2. Completes a DH exchange with the GCS using her OWN DH keys.
  3. Generates and sends her own session key to the GCS.
  4. Constructs a forged telemetry packet, signed with her OWN RSA key.
  5. Submits the forged packet.

Result: GCS rejects the packet — Eve's RSA public key ≠ enrolled Drone key.

Classes
-------
MITMAttacker
"""

import base64
import os

from ground_station import GroundStation, SecurityException
from tools import (
    CHAPAuthenticator,
    DHParty,
    DroneMessage,
    DroneStatus,
    HybridEncryptor,
    MACHandler,
    RSA_Signer,
)


class MITMAttacker:
    """
    Simulates an active Man-in-the-Middle attacker (Eve).

    Eve knows the shared CHAP password (she may have sniffed it from
    another source), owns her own DH and RSA keypairs, but crucially
    does NOT have the legitimate Drone's RSA private key.
    """

    def __init__(self, password: str):
        """
        Parameters
        ----------
        password : the pre-shared CHAP password (attacker has obtained this)
        """
        self._password = password

        # Eve's own RSA keypair — NOT the same as the real Drone's
        self._rsa_private, self._rsa_public = RSA_Signer.generate_keypair()
        self._session_key: bytes | None  = None
        self._mac_key:     bytes | None  = None

        print("[MITM Attacker] Initialised with own RSA keypair.")

    def attack(self,
               gcs: GroundStation,
               real_drone_mission_id: str = "MISSION_ALPHA_001") -> None:
        """
        Attempt a full MITM impersonation of the Drone.

        Steps
        -----
        1. Authenticate with CHAP (succeeds — Eve knows the password).
        2. Perform DH key exchange with GCS using Eve's DH keys.
        3. Generate own session key; wrap with GCS's RSA public key.
        4. Construct a forged DroneMessage.
        5. Sign with Eve's RSA private key (NOT the real Drone's).
        6. Encrypt, MAC, and send to GCS.

        Expected result: GCS rejects at signature verification step
        because Eve's public key ≠ the enrolled Drone public key.

        Parameters
        ----------
        gcs                   : the target GroundStation
        real_drone_mission_id : mission ID to embed in the forged message
        """
        print("[MITM Attacker] Starting impersonation of Drone...")

        # -- Step 1: CHAP Authentication --
        # Eve knows the password and can respond correctly.
        # CHAP only proves "I know the password" — it does NOT prove RSA identity.
        challenge = gcs.issue_challenge()
        response  = CHAPAuthenticator.compute_response(challenge, self._password)
        auth_ok   = gcs.verify_challenge_response(response)
        if not auth_ok:
            print("[MITM Attacker] CHAP failed — cannot proceed.")
            return
        print("[MITM Attacker] CHAP passed (password known). Proceeding...")

        # -- Step 2: DH Key Exchange (using Eve's own DH keys) --
        eve_dh      = DHParty()
        eve_dh_pub  = eve_dh.get_public_int()
        gcs_dh_pub  = gcs.init_dh()

        # GCS derives shared secret with Eve (thinking it is the real Drone)
        gcs.complete_dh(eve_dh_pub)

        # Eve derives her shared secret with the GCS
        eve_derived   = eve_dh.derive_shared_key(gcs_dh_pub)
        self._mac_key = eve_derived[:16]
        print("[MITM Attacker] DH exchange complete (GCS shares key with Eve, not real Drone).")

        # -- Step 3: Session Key (Eve generates her own) --
        self._session_key = os.urandom(32)
        enc_key = HybridEncryptor.rsa_encrypt_key(
            self._session_key, gcs.get_public_rsa_key()
        )
        gcs.receive_session_key(enc_key)
        print("[MITM Attacker] Forged session key sent to GCS.")

        # -- Step 4: Forge a DroneMessage --
        forged_msg = DroneMessage(
            drone_id=   "DR001",                        # pretend to be real drone
            position=   (50.0, 50.0, 10.0),
            velocity=   (0.0, 0.0, -5.0),               # forged "landing" command
            battery_pct=99.0,
            status=     DroneStatus.LANDING,            # malicious status injection
            mission_id= real_drone_mission_id,
        )
        plaintext = forged_msg.to_json().encode("utf-8")
        print(f"[MITM Attacker] Forged message: {forged_msg.printer()}")

        # -- Step 5: Sign with Eve's own RSA key (NOT the Drone's) --
        forged_signature = RSA_Signer.sign(plaintext, self._rsa_private)
        print("[MITM Attacker] Signed with Eve's RSA key (≠ enrolled Drone key).")

        # -- Step 6: Encrypt and MAC --
        ciphertext, aes_nonce = HybridEncryptor.aes_encrypt(plaintext, self._session_key)
        mac_tag = MACHandler.generate(ciphertext + aes_nonce, self._mac_key)

        forged_packet = {
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "aes_nonce":  base64.b64encode(aes_nonce).decode("ascii"),
            "mac":        base64.b64encode(mac_tag).decode("ascii"),
            "signature":  base64.b64encode(forged_signature).decode("ascii"),
            "msg_nonce":  forged_msg.nonce,
        }

        # -- Submit to GCS --
        print("[MITM Attacker] Submitting forged packet to GCS...")
        try:
            gcs.receive_message(forged_packet)
            print("[MITM Attacker] !! MITM SUCCEEDED — SYSTEM IS VULNERABLE !!")
        except SecurityException as exc:
            print(f"[GCS] ✗ MITM attack BLOCKED: {exc}")
