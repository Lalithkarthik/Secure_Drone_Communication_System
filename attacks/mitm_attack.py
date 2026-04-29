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

import os
from time import sleep

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
        self.password = password #Same as the password shared between Drone and Ground Station, which the cryptanalyst has figured out.

        #Cryptanalyst creates and uses her own RSA keys
        self.rsa_private_key, self.rsa_public_key = RSA_Signer.generate_keypair()

        #Cryptanalyst does not have access to the AES session key, or the key to generate the MAC+
        self.session_key: bytes | None  = None
        self.mac_key: bytes | None  = None
        sleep(1)
        print("[MITM Attacker] Initialised with own RSA keypair.")

    def attack(self, gcs: GroundStation, mission: str) -> None:
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
        mission : mission ID to embed in the forged message
        """
        print("[MITM Attacker] Starting impersonation of Drone...")
        #Cryptanalyst knows the password, so can successfully authenticate with the ground station, posing as the drone
        challenge = gcs.issue_challenge()
        response = CHAPAuthenticator.compute_response(challenge, self.password)
        auth_ok = gcs.verify_challenge_response(response)
        if not auth_ok:
            print("[MITM Attacker] CHAP failed — cannot proceed.")
            return
        sleep(1)
        print("[MITM Attacker] CHAP passed (password known). Proceeding...")

        #Cryptanalyst proceeds to exchange her own keys with the Ground Station
        cryptanalyst_dh = DHParty()
        cryptanalyst_dh_public  = cryptanalyst_dh.get_public_int()
        gcs_dh_public = gcs.init_dh()
        gcs.complete_dh(cryptanalyst_dh_public) #GCS unknowingly exchanges keys with the cryptanalyst, assuming the identity to be the drone.
        mac_key_derived = cryptanalyst_dh.derive_shared_key(gcs_dh_public)
        self.mac_key = mac_key_derived[:16] #Using this, the cryptanalyst successfully derives the key for MAC
        sleep(1)
        print("[MITM Attacker] DH exchange complete. Now has the key for the MAC.")

        #Cryptanalyst proceeds to create a fake AES session key and share it with the GCS
        self.session_key = os.urandom(32)
        enc_key = HybridEncryptor.rsa_encrypt_key(self.session_key, gcs.get_public_rsa_key())
        gcs.receive_session_key(enc_key)
        sleep(1)
        print("[MITM Attacker] Fake AES session key sent to GCS.")

        #Now, cryptanalyst forges messages to seem they are from the drone. The message gives the information of forged "landing" command, and maliciously gives 
        #incorrect information of the sensitive "Drone Status" to the Ground Station.
        forged_msg = DroneMessage(
            drone_id = "DR001",                 
            position = (50.0, 50.0, 10.0),
            velocity = (0.0, 0.0, -5.0),             
            battery_pct = 99.0,
            status = DroneStatus.LANDING,  
            mission_id = mission,
        )
        plaintext = forged_msg.to_json().encode("utf-8")
        sleep(1)
        print(f"[MITM Attacker] Forged message ready: {forged_msg.printer()}")

        #Cryptanalyst continues the normal communication flow of signing with it's own RSA key, encrypting and applying MAC correctly and submit to the GCS
        forged_signature = RSA_Signer.sign(plaintext, self.rsa_private_key)
        sleep(1)
        print("[MITM Attacker] Digital signature with own RSA key (not the same as enrolled Drone key).") #This is the reason due to which the GCS is able to identify the attack
        ciphertext, aes_nonce = HybridEncryptor.aes_encrypt(plaintext, self.session_key)
        mac = MACHandler.generate(ciphertext + aes_nonce, self.mac_key)
        forged_packet = {
            "ciphertext": ciphertext,
            "aes_nonce": aes_nonce,
            "mac": mac,
            "signature": forged_signature,
            "msg_nonce": forged_msg.nonce,
        }
        print("[MITM Attacker] Submitting forged packet to Ground Station...")
        sleep(1)
        try:
            gcs.receive_message(forged_packet)
            print("[MITM Attacker] MITM SUCCEEDED - WE BROKE THE SYSTEM !!")
        except SecurityException as exc:
            sleep(1)
            print(f"\n[Ground Station] MITM attack BLOCKED: {exc}")
            print("SYSTEM SECURE.")
